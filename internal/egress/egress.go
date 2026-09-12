// Package egress is the single choke point for outbound network dials.
//
// Every egress path in keyhole — the generic fetcher and the YouTube
// DirectTransform's innertube/caption clients — must dial through here so the
// SSRF guard cannot be bypassed by adding a new client elsewhere. The guard
// has two layers:
//
//  1. Blocklist: the target IP (resolved via the injectable Resolver, then
//     dialed directly with no second lookup that could disagree) is refused
//     when it is loopback, private, link-local, multicast, or unspecified,
//     unless the policy allows private targets.
//  2. DNS-rebinding pin: when Policy.PinDNS is set, the blocklist is enforced
//     on hostname-resolved IPs even when private targets are allowed, so a
//     public hostname resolving to an internal address is refused. Literal-IP
//     URLs are unaffected: no DNS lookup means no rebinding vector.
//
// The package depends only on the standard library so both net-facing
// packages (fetch, transform) can import it without creating cycles.
package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// DefaultTimeout bounds clients built without an explicit timeout so a
// stalled upstream can never pin a handler goroutine indefinitely.
const DefaultTimeout = 30 * time.Second

// DefaultMaxRedirects caps redirect hops for clients built without an
// explicit limit.
const DefaultMaxRedirects = 10

// Policy selects which dial targets are permitted. It mirrors the
// [network] allow_private / pin_dns settings without importing the config
// package, keeping this choke point dependency-free.
type Policy struct {
	// AllowPrivate permits private/link-local/metadata IPs (internal-site
	// deployments). Default false: safe to expose without review.
	AllowPrivate bool
	// PinDNS enforces the blocklist on hostname-resolved IPs even when
	// AllowPrivate is set — the DNS-rebinding mitigation. Literal-IP URLs
	// are unaffected.
	PinDNS bool
}

// Resolver abstracts DNS resolution so tests can inject deterministic
// results (e.g. a hostname that "resolves" to a private IP).
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

// BlockedError is returned by Dial when the target IP is in a blocked range.
// Callers map it to a policy denial.
type BlockedError struct {
	Host string
	IP   net.IP
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("ssrf: %s resolves to blocked address %s", e.Host, e.IP)
}

// blockedPrefixes is the explicit special-use destination table. It is a
// superset of net.IP's IsPrivate/IsLoopback/etc. helpers so ranges those
// helpers omit — carrier-grade NAT (100.64/10, which includes Alibaba's
// metadata endpoint 100.100.100.200), 0.0.0.0/8, 192.0.0.0/24, benchmarking
// 198.18/15, 240/4, NAT64, 6to4 and Teredo (both of which embed an IPv4
// address that can be private) — are refused too.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network"
	netip.MustParsePrefix("10.0.0.0/8"),     // RFC1918
	netip.MustParsePrefix("100.64.0.0/10"),  // carrier-grade NAT (incl. cloud metadata)
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("169.254.0.0/16"), // link-local (incl. 169.254.169.254)
	netip.MustParsePrefix("172.16.0.0/12"),  // RFC1918
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("192.88.99.0/24"), // 6to4 relay anycast (deprecated)
	netip.MustParsePrefix("192.168.0.0/16"), // RFC1918
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking
	netip.MustParsePrefix("224.0.0.0/4"),    // multicast
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved (incl. broadcast)
	netip.MustParsePrefix("::/96"),          // IPv4-compatible incl. :: and ::1
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64 well-known prefix
	netip.MustParsePrefix("64:ff9b:1::/48"), // NAT64 local-use prefix
	netip.MustParsePrefix("100::/64"),       // discard-only
	netip.MustParsePrefix("2001::/32"),      // Teredo
	netip.MustParsePrefix("2001:2::/48"),    // benchmarking
	netip.MustParsePrefix("2001:10::/28"),   // ORCHID (deprecated)
	netip.MustParsePrefix("2001:db8::/32"),  // documentation
	netip.MustParsePrefix("2002::/16"),      // 6to4 (embeds an IPv4 address)
	netip.MustParsePrefix("fc00::/7"),       // unique local
	netip.MustParsePrefix("fe80::/10"),      // link-local
	netip.MustParsePrefix("ff00::/8"),       // multicast
}

// IsBlocked reports whether ip must not be dialed without an explicit
// private-targets policy. IPv4-mapped IPv6 addresses are unmapped first, so
// ::ffff:169.254.169.254 is refused exactly like 169.254.169.254. An address
// that cannot be parsed is blocked (fail closed).
func IsBlocked(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Dial resolves host through resolver, checks every resolved IP against the
// blocklist per policy, and dials the first resolved IP directly — avoiding
// a second DNS lookup that could disagree with the check (a partial
// DNS-rebinding mitigation). A nil resolver uses the system resolver; a nil
// base dialer uses a default one.
func Dial(ctx context.Context, policy Policy, resolver Resolver, base *net.Dialer, network, addr string) (net.Conn, error) {
	if resolver == nil {
		resolver = DefaultResolver()
	}
	if base == nil {
		base = &net.Dialer{}
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("ssrf: bad address %q: %w", addr, err)
	}

	// Literal IP: check directly without a DNS round-trip.
	if ip := net.ParseIP(host); ip != nil {
		if !policy.AllowPrivate && IsBlocked(ip) {
			return nil, &BlockedError{Host: host, IP: ip}
		}
		return base.DialContext(ctx, network, addr)
	}

	// Hostname: resolve, check, and dial the first resolved IP.
	ips, err := resolver.LookupIP(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("ssrf: resolve %s: %w", host, err)
	}
	for _, ip := range ips {
		// pin_dns enforces the blocklist on resolved IPs even when
		// allow_private is set — a public hostname mapping to a
		// private/link-local/metadata address is the classic
		// DNS-rebinding signal. Literal-IP URLs (above) are unaffected:
		// no DNS lookup means no rebinding vector.
		if IsBlocked(ip) && (policy.PinDNS || !policy.AllowPrivate) {
			return nil, &BlockedError{Host: host, IP: ip}
		}
	}
	if len(ips) == 0 {
		// A resolver that reports "no addresses, no error" must not fall
		// through to an unchecked dial of the raw hostname: that would let a
		// faulty/custom resolver skip the blocklist and perform a second DNS
		// resolution. Fail closed.
		return nil, fmt.Errorf("ssrf: resolver returned no addresses for %s", host)
	}
	dialAddr := net.JoinHostPort(ips[0].String(), port)
	return base.DialContext(ctx, network, dialAddr)
}

// DialFunc adapts Dial with fixed policy/resolver/dialer into the
// http.Transport.DialContext shape.
func DialFunc(policy Policy, resolver Resolver, base *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return Dial(ctx, policy, resolver, base, network, addr)
	}
}

// NewTransport builds the guarded transport. All *http.Transport literals
// in keyhole live here or are built by this function — the arch test
// (internal/arch) rejects Transport/Client literals anywhere else outside
// _test.go files.
func NewTransport(dialContext func(ctx context.Context, network, addr string) (net.Conn, error), tlsHandshakeTimeout time.Duration) *http.Transport {
	// Idle-connection bounds matter for a service whose target host set is
	// client-controlled: with the zero value, net/http keeps idle connections
	// effectively forever and the pool has no global limit, so fetching many
	// distinct hosts would accumulate sockets until GC/FD exhaustion.
	return &http.Transport{
		DialContext:         dialContext,
		TLSHandshakeTimeout: tlsHandshakeTimeout,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
}

// NewClient assembles an *http.Client from its parts. All *http.Client
// literals in keyhole live here — see NewTransport.
func NewClient(transport http.RoundTripper, timeout time.Duration, checkRedirect func(req *http.Request, via []*http.Request) error) *http.Client {
	return &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: checkRedirect,
	}
}

// NewHTTPClient builds a self-contained guarded client: system (or default)
// resolution, the SSRF-guarded dial, a redirect-hop limit, and a timeout
// that defaults to DefaultTimeout when timeout <= 0. maxRedirects <= 0
// defaults to DefaultMaxRedirects. This is the constructor DirectTransform
// clients and other non-fetcher egress must use.
func NewHTTPClient(policy Policy, timeout time.Duration, maxRedirects int) *http.Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if maxRedirects <= 0 {
		maxRedirects = DefaultMaxRedirects
	}
	base := &net.Dialer{Timeout: timeout}
	transport := NewTransport(DialFunc(policy, DefaultResolver(), base), timeout)
	return NewClient(transport, timeout, func(_ *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return fmt.Errorf("max_redirects (%d) exceeded", maxRedirects)
		}
		return nil
	})
}

// errBodyTooLarge is returned by a size-capped response body once it exceeds
// its cap.
var errBodyTooLarge = errors.New("egress: response body exceeds size cap")

// NewSizeCappedTransport wraps a RoundTripper so every response body is capped
// at maxBytes. Third-party API clients (e.g. the YouTube library) read bodies
// with io.ReadAll and no bound; wrapping their transport applies the same
// [network].max_size discipline the generic fetcher has. maxBytes <= 0 returns
// base unchanged; a nil base uses http.DefaultTransport.
func NewSizeCappedTransport(base http.RoundTripper, maxBytes int64) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if maxBytes <= 0 {
		return base
	}
	return &sizeCappedTransport{base: base, max: maxBytes}
}

type sizeCappedTransport struct {
	base http.RoundTripper
	max  int64
}

func (t *sizeCappedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil || resp.Body == nil {
		return resp, err
	}
	resp.Body = &sizeCappedBody{rc: resp.Body, remaining: t.max}
	return resp, nil
}

// Unwrap exposes the wrapped RoundTripper so callers (and tests locking the
// egress invariant) can inspect the transport underneath the cap.
func (t *sizeCappedTransport) Unwrap() http.RoundTripper { return t.base }

// sizeCappedBody returns errBodyTooLarge as soon as a read would cross the cap,
// while still reporting a clean EOF for a body that is exactly at the cap.
type sizeCappedBody struct {
	rc        io.ReadCloser
	remaining int64
}

func (b *sizeCappedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		// The cap is exhausted: one more byte distinguishes "exactly at the
		// cap" (EOF) from "over the cap" (error).
		var one [1]byte
		n, err := b.rc.Read(one[:])
		if n > 0 {
			return 0, errBodyTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.rc.Read(p)
	b.remaining -= int64(n)
	return n, err
}

func (b *sizeCappedBody) Close() error { return b.rc.Close() }

// --- default resolver -----------------------------------------------------

type defaultResolver struct{}

func (defaultResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, len(addrs))
	for i, a := range addrs {
		ips[i] = a.IP
	}
	return ips, nil
}

// DefaultResolver returns the system DNS resolver as a Resolver.
func DefaultResolver() Resolver { return defaultResolver{} }
