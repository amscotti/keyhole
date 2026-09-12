package egress_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/amscotti/keyhole/internal/egress"
)

// mapResolver is a deterministic Resolver for tests.
type mapResolver map[string][]net.IP

func (m mapResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	return m[host], nil
}

func TestIsBlocked(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"127.0.0.1":       true,  // loopback
		"10.2.3.4":        true,  // RFC1918
		"192.168.1.1":     true,  // RFC1918
		"172.16.0.1":      true,  // RFC1918
		"169.254.169.254": true,  // cloud metadata (link-local)
		"::1":             true,  // IPv6 loopback
		"fc00::1":         true,  // ULA
		"224.0.0.1":       true,  // multicast
		"0.0.0.0":         true,  // unspecified
		"8.8.8.8":         false, // public
		"1.1.1.1":         false, // public
		// Ranges net.IP's helpers miss but that reach internal services.
		"100.64.0.1":       true, // carrier-grade NAT
		"100.100.100.200":  true, // Alibaba cloud metadata (inside 100.64/10)
		"0.0.0.1":          true, // "this network" beyond unspecified
		"192.0.0.1":        true, // IETF protocol assignments
		"198.18.0.1":       true, // benchmarking
		"240.0.0.1":        true, // reserved
		"192.88.99.1":      true, // 6to4 relay anycast
		"::127.0.0.1":      true, // IPv4-compatible loopback
		"::ffff:127.0.0.1": true, // v4-mapped loopback
		"64:ff9b::7f00:1":  true, // NAT64-embedded loopback
		"2002:7f00:1::":    true, // 6to4-embedded loopback
		"2001:db8::1":      true, // documentation range
		"fe80::1":          true, // IPv6 link-local
		"ff02::1":          true, // IPv6 multicast
		// Public IPv6 stays dialable.
		"2606:4700:4700::1111": false,
		"2001:4860:4860::8888": false,
	}
	for ip, want := range cases {
		if got := egress.IsBlocked(net.ParseIP(ip)); got != want {
			t.Errorf("IsBlocked(%s) = %v, want %v", ip, got, want)
		}
	}
	if !egress.IsBlocked(nil) {
		t.Error("IsBlocked(nil) must fail closed")
	}
}

// TestDialEmptyResolverFailsClosed pins that a resolver returning "no
// addresses, no error" cannot fall through to an unchecked dial of the raw
// hostname (a second DNS resolution that bypasses the blocklist).
func TestDialEmptyResolverFailsClosed(t *testing.T) {
	t.Parallel()
	_, err := egress.Dial(context.Background(), egress.Policy{}, mapResolver{}, nil, "tcp", "empty.test:80")
	if err == nil {
		t.Fatal("expected an error when the resolver returns no addresses")
	}
	var blocked *egress.BlockedError
	if asBlocked(err, &blocked) {
		t.Fatalf("empty resolution is a resolution failure, not an SSRF denial: %v", err)
	}
}

func TestDialBlocksPrivateHostname(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, err := egress.Dial(ctx, egress.Policy{}, mapResolver{
		"evil.test": {net.ParseIP("10.2.3.4")},
	}, nil, "tcp", "evil.test:80")
	if err == nil {
		t.Fatal("expected denial for hostname resolving to private IP")
	}
	var blocked *egress.BlockedError
	if !asBlocked(err, &blocked) {
		t.Fatalf("expected *BlockedError, got %T (%v)", err, err)
	}
}

func TestDialAllowPrivatePermitsHostname(t *testing.T) {
	t.Parallel()
	// With AllowPrivate the dial proceeds to the (unreachable) address rather
	// than being refused at the guard: any error must NOT be a BlockedError.
	_, err := egress.Dial(context.Background(), egress.Policy{AllowPrivate: true}, mapResolver{
		"internal.test": {net.ParseIP("10.9.9.9")},
	}, &net.Dialer{Timeout: 50 * time.Millisecond}, "tcp", "internal.test:81")
	var blocked *egress.BlockedError
	if asBlocked(err, &blocked) {
		t.Fatalf("allow_private must not block, got %v", err)
	}
}

func TestDialPinDNSReblocksHostnameDespiteAllowPrivate(t *testing.T) {
	t.Parallel()
	_, err := egress.Dial(context.Background(),
		egress.Policy{AllowPrivate: true, PinDNS: true}, mapResolver{
			"rebind.test": {net.ParseIP("10.5.5.5")},
		}, nil, "tcp", "rebind.test:80")
	var blocked *egress.BlockedError
	if !asBlocked(err, &blocked) {
		t.Fatalf("pin_dns must re-block hostname→private, got %v", err)
	}
}

func TestDialLiteralIPIgnoresPinDNS(t *testing.T) {
	t.Parallel()
	// No DNS lookup happens for a literal IP, so there is no rebinding
	// vector: with AllowPrivate the dial proceeds past the guard.
	_, err := egress.Dial(context.Background(),
		egress.Policy{AllowPrivate: true, PinDNS: true}, mapResolver{},
		&net.Dialer{Timeout: 50 * time.Millisecond}, "tcp", "127.0.0.1:81")
	var blocked *egress.BlockedError
	if asBlocked(err, &blocked) {
		t.Fatalf("literal IP with allow_private must pass the guard, got %v", err)
	}
}

func TestDialLiteralPrivateBlockedByDefault(t *testing.T) {
	t.Parallel()
	_, err := egress.Dial(context.Background(), egress.Policy{}, mapResolver{}, nil, "tcp", "10.1.2.3:80")
	var blocked *egress.BlockedError
	if !asBlocked(err, &blocked) {
		t.Fatalf("expected *BlockedError for literal private IP, got %v", err)
	}
}

// TestDefaultResolverLiteralIP pins the no-DNS fast path: a literal IP is
// returned verbatim (never sent to the system resolver), so Dial can check it
// directly and there is no lookup a rebinding attacker could race.
func TestDefaultResolverLiteralIP(t *testing.T) {
	t.Parallel()
	ips, err := egress.DefaultResolver().LookupIP(context.Background(), "203.0.113.9")
	if err != nil {
		t.Fatalf("LookupIP(literal) error = %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("203.0.113.9")) {
		t.Fatalf("LookupIP(literal) = %v, want [203.0.113.9]", ips)
	}
}

// TestDefaultResolverInvalidHostErrors pins that a non-resolving hostname
// returns an error rather than hanging: the lookup runs under a short context
// deadline so a resolver that stalls cannot wedge the caller (or this test).
func TestDefaultResolverInvalidHostErrors(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := egress.DefaultResolver().LookupIP(ctx, "does-not-exist.invalid"); err == nil {
		t.Fatal("expected an error for a hostname that cannot resolve")
	}
}

func TestNewHTTPClientDefaults(t *testing.T) {
	t.Parallel()
	c := egress.NewHTTPClient(egress.Policy{}, 0, 0)
	if c.Timeout != egress.DefaultTimeout {
		t.Errorf("Timeout = %v, want default %v", c.Timeout, egress.DefaultTimeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", c.Transport)
	}
	if tr.DialContext == nil {
		t.Error("Transport.DialContext must be the guarded dial")
	}
	if tr.IdleConnTimeout <= 0 || tr.MaxIdleConns <= 0 || tr.MaxIdleConnsPerHost <= 0 {
		t.Errorf("idle-connection bounds must be set, got IdleConnTimeout=%v MaxIdleConns=%d MaxIdleConnsPerHost=%d",
			tr.IdleConnTimeout, tr.MaxIdleConns, tr.MaxIdleConnsPerHost)
	}
}

func TestNewHTTPClientEnforcesRedirectLimit(t *testing.T) {
	t.Parallel()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, srv.URL+"/loop", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	// Loopback needs an explicit private-targets policy even in tests.
	c := egress.NewHTTPClient(egress.Policy{AllowPrivate: true}, 5*time.Second, 3)
	_, err := c.Get(srv.URL)
	if err == nil {
		t.Fatal("expected redirect-limit error on infinite redirect loop")
	}
}

// staticTransport is a RoundTripper serving a fixed body without touching the
// network, for the size-cap tests.
type staticTransport struct{ body string }

func (s staticTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(s.body)),
	}, nil
}

// TestSizeCappedTransportBodyAtCap pins the inclusive bound: a body exactly at
// max_size must read to a clean EOF, not a spurious too-large error. An
// off-by-one here would reject legitimate responses the generic fetcher
// accepts at the same size.
func TestSizeCappedTransportBodyAtCap(t *testing.T) {
	t.Parallel()
	const capBytes = 8
	body := strings.Repeat("a", capBytes)
	client := &http.Client{
		Transport: egress.NewSizeCappedTransport(staticTransport{body: body}, capBytes),
	}
	resp, err := client.Get("http://capped.test/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("at-cap body must read to a clean EOF, got %v", err)
	}
	if string(data) != body {
		t.Fatalf("body = %q, want %q", data, body)
	}
}

// TestSizeCappedTransportBodyOverCap pins enforcement: the read that crosses
// the cap returns an error instead of silently truncating, so a client that
// reads with io.ReadAll (e.g. the YouTube library) cannot mistake a clipped
// body for a complete response.
func TestSizeCappedTransportBodyOverCap(t *testing.T) {
	t.Parallel()
	const capBytes = 8
	body := strings.Repeat("a", capBytes+1)
	client := &http.Client{
		Transport: egress.NewSizeCappedTransport(staticTransport{body: body}, capBytes),
	}
	resp, err := client.Get("http://capped.test/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	buf := make([]byte, capBytes)
	if n, rerr := resp.Body.Read(buf); n != capBytes || rerr != nil {
		t.Fatalf("first read = (%d, %v), want (%d, nil)", n, rerr, capBytes)
	}
	if _, rerr := resp.Body.Read(buf); rerr == nil {
		t.Fatal("second read must surface the size-cap error")
	} else if !strings.Contains(rerr.Error(), "size cap") {
		t.Errorf("error = %v, want it to mention the size cap", rerr)
	}
}

func asBlocked(err error, target **egress.BlockedError) bool {
	return errors.As(err, target)
}
