package fetch_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/amscotti/keyhole/internal/authprofile"
	"github.com/amscotti/keyhole/internal/config"
	"github.com/amscotti/keyhole/internal/fetch"
	"github.com/amscotti/keyhole/internal/rules"
)

// --- helpers --------------------------------------------------------------

func newCaptureLogger() (*zap.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(&buf),
		zapcore.DebugLevel,
	))
	return logger, &buf
}

func allowAllEngine(t *testing.T) *rules.Engine {
	t.Helper()
	e, err := rules.NewEngine(nil, "allow")
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	return e
}

// writeBody writes s to the ResponseWriter and fails the test on error. Used by
// httptest handlers so errcheck is satisfied.
func writeBody(t *testing.T, w http.ResponseWriter, s string) {
	t.Helper()
	if _, err := io.WriteString(w, s); err != nil {
		t.Errorf("write body: %v", err)
	}
}

// netConfig returns a NetworkConfig for tests. allowPrivate controls SSRF.
func netConfig(allowPrivate bool) config.NetworkConfig {
	return config.NetworkConfig{
		Timeout:       "5s",
		MaxSize:       1024 * 1024,
		MaxRedirects:  10,
		UserAgent:     "keyhole-test",
		AllowPrivate:  allowPrivate,
		RespectRobots: false,
	}
}

// --- SSRF guard tests -----------------------------------------------------

func TestSSRFBlocksLoopbackLiteralIP(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, "ok")
	}))
	defer srv.Close()

	f := fetch.New(netConfig(false), allowAllEngine(t), nil, zap.NewNop())
	_, err := f.Fetch(context.Background(), srv.URL, "")
	if err == nil {
		t.Fatal("expected denial for loopback address")
	}
	if !isFetchCode(err, "denied") {
		t.Fatalf("expected code 'denied', got: %v", err)
	}
}

func TestSSRFAllowsLoopbackWithAllowPrivate(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, "ok")
	}))
	defer srv.Close()

	f := fetch.New(netConfig(true), allowAllEngine(t), nil, zap.NewNop())
	res, err := f.Fetch(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("unexpected error with allow_private: %v", err)
	}
	if string(res.Body) != "ok" {
		t.Fatalf("body = %q, want %q", res.Body, "ok")
	}
}

func TestSSRFMatrix(t *testing.T) {
	t.Parallel()

	// These are literal-IP targets that must be blocked regardless of port
	// or path. Each is tested without allow_private and must be denied.
	cases := []struct {
		name string
		ip   string
	}{
		{"loopback", "127.0.0.1"},
		{"loopback_alt", "127.1.2.3"},
		{"rfc1918_10", "10.0.0.1"},
		{"rfc1918_172", "172.16.0.1"},
		{"rfc1918_192", "192.168.1.1"},
		{"link_local", "169.254.1.1"},
		{"metadata", "169.254.169.254"},
		{"unspecified", "0.0.0.0"},
		{"ipv6_loopback", "::1"},
		{"ipv6_ula", "fc00::1"},
		{"ipv6_link_local", "fe80::1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := fetch.New(netConfig(false), allowAllEngine(t), nil, zap.NewNop())
			target := "http://" + tc.ip + ":9999/test"
			_, err := f.Fetch(context.Background(), target, "")
			if err == nil {
				t.Fatalf("expected denial for %s", tc.ip)
			}
			if !isFetchCode(err, "denied") {
				t.Fatalf("expected code 'denied' for %s, got: %v", tc.ip, err)
			}
		})
	}
}

func TestSSRFBlocksHostnameResolvingToPrivate(t *testing.T) {
	t.Parallel()
	f := fetch.New(netConfig(false), allowAllEngine(t), nil, zap.NewNop())
	// evil.test resolves to a private IP via the fake resolver; the fetcher
	// blocks it before connecting.
	f.SetResolver(stubResolver{"evil.test": {net.ParseIP("10.2.3.4")}})

	_, err := f.Fetch(context.Background(), "http://evil.test:8080/path", "")
	if err == nil {
		t.Fatal("expected denial for hostname resolving to private IP")
	}
	if !isFetchCode(err, "denied") {
		t.Fatalf("expected code 'denied', got: %v", err)
	}
}

// --- DNS-rebinding pin (Phase 8) -------------------------------------------
//
// pin_dns is the DNS-rebinding mitigation: when on, a hostname resolving to a
// private/link-local/metadata IP is refused even with allow_private = true,
// because a public hostname mapping to an internal address is the classic
// rebinding signal.

func TestPinDNSBlocksPrivateHostnameEvenWithAllowPrivate(t *testing.T) {
	t.Parallel()
	cfg := netConfig(true) // allow_private = true
	cfg.PinDNS = true
	f := fetch.New(cfg, allowAllEngine(t), nil, zap.NewNop())
	f.SetResolver(stubResolver{"rebind.test": {net.ParseIP("10.5.5.5")}})

	_, err := f.Fetch(context.Background(), "http://rebind.test/path", "")
	if err == nil {
		t.Fatal("expected denial: pin_dns must block hostname→private even with allow_private")
	}
	if !isFetchCode(err, "denied") {
		t.Fatalf("expected code 'denied', got: %v", err)
	}
}

func TestPinDNSBlocksMetadataHostnameEvenWithAllowPrivate(t *testing.T) {
	t.Parallel()
	cfg := netConfig(true)
	cfg.PinDNS = true
	f := fetch.New(cfg, allowAllEngine(t), nil, zap.NewNop())
	f.SetResolver(stubResolver{"meta.test": {net.ParseIP("169.254.169.254")}})

	_, err := f.Fetch(context.Background(), "http://meta.test/latest/meta-data/", "")
	if err == nil {
		t.Fatal("expected denial: pin_dns must block hostname→metadata IP")
	}
	if !isFetchCode(err, "denied") {
		t.Fatalf("expected code 'denied', got: %v", err)
	}
}

// Literal IPs are unaffected by pin_dns: there is no DNS lookup, so there is no
// rebinding vector. allow_private still governs literal-IP access.
func TestPinDNSAllowsLiteralLoopbackWithAllowPrivate(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, "ok")
	}))
	defer srv.Close()

	cfg := netConfig(true)
	cfg.PinDNS = true
	f := fetch.New(cfg, allowAllEngine(t), nil, zap.NewNop())
	res, err := f.Fetch(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: pin_dns must not block literal IPs with allow_private: %v", err)
	}
	if string(res.Body) != "ok" {
		t.Fatalf("body = %q, want %q", res.Body, "ok")
	}
}

// pin_dns off + allow_private on: hostname resolving to a private IP is allowed
// (the internal-site use case). This proves pin_dns is the toggle, not
// allow_private.
func TestPinDNSOffAllowsPrivateHostnameWithAllowPrivate(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, "ok")
	}))
	defer srv.Close()

	srvURL, _ := url.Parse(srv.URL)
	_, port, _ := net.SplitHostPort(srvURL.Host)
	srvIP := net.ParseIP("127.0.0.1")

	cfg := netConfig(true) // allow_private=true, pin_dns=false (default)
	f := fetch.New(cfg, allowAllEngine(t), nil, zap.NewNop())
	f.SetResolver(stubResolver{"internal.test": {srvIP}})

	res, err := f.Fetch(context.Background(),
		fmt.Sprintf("http://internal.test:%s/x", port), "")
	if err != nil {
		t.Fatalf("unexpected error with allow_private and pin_dns off: %v", err)
	}
	if string(res.Body) != "ok" {
		t.Fatalf("body = %q", res.Body)
	}
}

func TestSSRFAllowsPublicHostnameResolvingToPublicIP(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, "pub")
	}))
	defer srv.Close()

	// Parse the httptest server's address so the fake resolver returns it.
	srvURL, _ := url.Parse(srv.URL)
	host, port, _ := net.SplitHostPort(srvURL.Host)
	srvIP := net.ParseIP(host)

	f := fetch.New(netConfig(true), allowAllEngine(t), nil, zap.NewNop())
	f.SetResolver(stubResolver{"myhost.test": {srvIP}})

	res, err := f.Fetch(context.Background(),
		fmt.Sprintf("http://myhost.test:%s/x", port), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(res.Body) != "pub" {
		t.Fatalf("body = %q, want %q", res.Body, "pub")
	}
}

// --- redirect tests -------------------------------------------------------

func TestRedirectChainSucceeds(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/mid", http.StatusFound)
		case "/mid":
			http.Redirect(w, r, "/end", http.StatusFound)
		case "/end":
			writeBody(t, w, "arrived")
		}
	}))
	defer srv.Close()

	f := fetch.New(netConfig(true), allowAllEngine(t), nil, zap.NewNop())
	res, err := f.Fetch(context.Background(), srv.URL+"/start", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(res.Body) != "arrived" {
		t.Fatalf("body = %q", res.Body)
	}
	if !strings.HasSuffix(res.FinalURL, "/end") {
		t.Fatalf("final_url = %q, want suffix /end", res.FinalURL)
	}
}

func TestRedirectExceedsMaxRedirects(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer srv.Close()

	cfg := netConfig(true)
	cfg.MaxRedirects = 2
	f := fetch.New(cfg, allowAllEngine(t), nil, zap.NewNop())
	_, err := f.Fetch(context.Background(), srv.URL+"/loop", "")
	if err == nil {
		t.Fatal("expected error for too many redirects")
	}
}

func TestRedirectIntoDeniedURLIsBlocked(t *testing.T) {
	t.Parallel()
	var secretHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/allowed":
			// Redirect to a denied path.
			http.Redirect(w, r, "/secret", http.StatusFound)
		case "/secret":
			secretHits.Add(1)
			writeBody(t, w, "should-not-reach")
		}
	}))
	defer srv.Close()

	// Build an engine that allows /allowed but denies /secret.
	base := strings.TrimPrefix(srv.URL, "http://")
	denyRule := config.Rule{Match: "http://" + base + "/secret", Allow: boolPtr(false)}
	allowRule := config.Rule{Match: "http://" + base + "/allowed", Allow: boolPtr(true)}
	engine, err := rules.NewEngine([]config.Rule{denyRule, allowRule}, "deny")
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}

	f := fetch.New(netConfig(true), engine, nil, zap.NewNop())
	_, err = f.Fetch(context.Background(), srv.URL+"/allowed", "")
	if err == nil {
		t.Fatal("expected denial for redirect into denied URL")
	}
	if !isFetchCode(err, "denied") {
		t.Fatalf("expected code 'denied', got: %v", err)
	}
	// Policy must refuse the hop in CheckRedirect — the denied URL must never
	// be contacted (credential exposure + side-effect surface).
	if secretHits.Load() != 0 {
		t.Fatalf("denied hop was contacted %d times; CheckRedirect must block before dial", secretHits.Load())
	}
}

func TestRedirectIntermediateDeniedHopNotContacted(t *testing.T) {
	t.Parallel()
	// allow → deny → allow: the intermediate denied hop must never be hit,
	// even if the final URL would be allowed.
	var midHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/mid", http.StatusFound)
		case "/mid":
			midHits.Add(1)
			http.Redirect(w, r, "/end", http.StatusFound)
		case "/end":
			writeBody(t, w, "should-not-reach")
		}
	}))
	defer srv.Close()

	base := strings.TrimPrefix(srv.URL, "http://")
	engine, err := rules.NewEngine([]config.Rule{
		{Match: "http://" + base + "/start", Allow: boolPtr(true)},
		{Match: "http://" + base + "/mid", Allow: boolPtr(false)},
		{Match: "http://" + base + "/end", Allow: boolPtr(true)},
	}, "deny")
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}

	f := fetch.New(netConfig(true), engine, nil, zap.NewNop())
	_, err = f.Fetch(context.Background(), srv.URL+"/start", "")
	if err == nil {
		t.Fatal("expected denial for intermediate redirect hop")
	}
	if !isFetchCode(err, "denied") {
		t.Fatalf("expected code 'denied', got: %v", err)
	}
	if midHits.Load() != 0 {
		t.Fatalf("intermediate denied hop contacted %d times", midHits.Load())
	}
}

// --- redirect credential tests --------------------------------------------

// TestRedirectSameOriginKeepsProfileHeaders pins the authorized case: a
// same-origin redirect is a normal API pattern (e.g. /v1 -> /v1/) and the
// profile's credentials must continue to be sent.
func TestRedirectSameOriginKeepsProfileHeaders(t *testing.T) {
	t.Parallel()
	var endAuth, endKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/end", http.StatusFound)
		case "/end":
			endAuth = r.Header.Get("Authorization")
			endKey = r.Header.Get("X-Api-Key")
			writeBody(t, w, "arrived")
		}
	}))
	defer srv.Close()

	profiles := authprofile.New([]config.AuthProfile{
		{Name: "api", Headers: map[string]string{
			"Authorization": "Bearer secret",
			"X-Api-Key":     "key-123",
		}},
	})
	f := fetch.New(netConfig(true), allowAllEngine(t), profiles, zap.NewNop())
	if _, err := f.Fetch(context.Background(), srv.URL+"/start", "api"); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if endAuth != "Bearer secret" || endKey != "key-123" {
		t.Fatalf("same-origin redirect lost profile headers: auth=%q key=%q", endAuth, endKey)
	}
}

// TestRedirectCrossHostStripsProfileHeaders is the security half: a redirect to
// a different origin must not receive the profile's credential headers, even
// when policy allows the destination (default-allow deployments included).
// Go's redirect header copier only strips a fixed sensitive-header list at a
// different registrable domain, which misses custom credential headers.
func TestRedirectCrossHostStripsProfileHeaders(t *testing.T) {
	t.Parallel()
	var endAuth, endKey atomic.Value
	endAuth.Store("unset")
	endKey.Store("unset")
	end := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endAuth.Store(r.Header.Get("Authorization"))
		endKey.Store(r.Header.Get("X-Api-Key"))
		writeBody(t, w, "arrived")
	}))
	defer end.Close()

	start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, end.URL+"/end", http.StatusFound)
	}))
	defer start.Close()

	profiles := authprofile.New([]config.AuthProfile{
		{Name: "api", Headers: map[string]string{
			"Authorization": "Bearer secret",
			"X-Api-Key":     "key-123",
		}},
	})
	f := fetch.New(netConfig(true), allowAllEngine(t), profiles, zap.NewNop())
	if _, err := f.Fetch(context.Background(), start.URL+"/start", "api"); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got := endAuth.Load().(string); got != "" {
		t.Fatalf("Authorization leaked to redirect target: %q", got)
	}
	if got := endKey.Load().(string); got != "" {
		t.Fatalf("X-Api-Key leaked to redirect target: %q", got)
	}
}

// TestRedirectCrossHostAppliesDestinationRuleProfile covers the intended
// workflow the strip must not break: the destination host has its own rule
// with an auth_profile, so the redirect arrives authenticated — with the
// destination's credentials, not the origin's.
func TestRedirectCrossHostAppliesDestinationRuleProfile(t *testing.T) {
	t.Parallel()
	var gotA, gotB atomic.Value
	gotA.Store("unset")
	gotB.Store("unset")
	end := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotA.Store(r.Header.Get("X-From-A"))
		gotB.Store(r.Header.Get("X-From-B"))
		writeBody(t, w, "arrived")
	}))
	defer end.Close()

	start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, end.URL+"/end", http.StatusFound)
	}))
	defer start.Close()

	destHost := strings.TrimPrefix(end.URL, "http://")
	allow := true
	engine, err := rules.NewEngine([]config.Rule{
		{Match: "http://" + destHost + "/end", Allow: &allow, AuthProfile: "b"},
	}, "allow")
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	profiles := authprofile.New([]config.AuthProfile{
		{Name: "a", Headers: map[string]string{"X-From-A": "cred-a"}},
		{Name: "b", Headers: map[string]string{"X-From-B": "cred-b"}},
	})

	f := fetch.New(netConfig(true), engine, profiles, zap.NewNop())
	if _, err := f.Fetch(context.Background(), start.URL+"/start", "a"); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got := gotA.Load().(string); got != "" {
		t.Fatalf("origin profile header leaked cross-host: %q", got)
	}
	if got := gotB.Load().(string); got != "cred-b" {
		t.Fatalf("destination rule profile not applied: X-From-B = %q, want cred-b", got)
	}
}

// TestMaxRedirectsCountsRedirects pins the documented meaning: max_redirects is
// the number of redirects followed, not the number of requests made.
func TestMaxRedirectsCountsRedirects(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			http.Redirect(w, r, "/b", http.StatusFound)
		case "/b":
			http.Redirect(w, r, "/c", http.StatusFound)
		case "/c":
			writeBody(t, w, "arrived")
		}
	}))
	defer srv.Close()

	cfg := netConfig(true)
	cfg.MaxRedirects = 2
	f := fetch.New(cfg, allowAllEngine(t), nil, zap.NewNop())
	if _, err := f.Fetch(context.Background(), srv.URL+"/a", ""); err != nil {
		t.Fatalf("two redirects must be allowed with max_redirects=2: %v", err)
	}

	cfg.MaxRedirects = 1
	f = fetch.New(cfg, allowAllEngine(t), nil, zap.NewNop())
	if _, err := f.Fetch(context.Background(), srv.URL+"/a", ""); err == nil {
		t.Fatal("expected error for a second redirect with max_redirects=1")
	}
}

// --- size cap tests -------------------------------------------------------

func TestBodyWithinMaxSizeSucceeds(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, strings.Repeat("x", 100))
	}))
	defer srv.Close()

	cfg := netConfig(true)
	cfg.MaxSize = 200
	f := fetch.New(cfg, allowAllEngine(t), nil, zap.NewNop())
	res, err := f.Fetch(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Body) != 100 {
		t.Fatalf("body len = %d, want 100", len(res.Body))
	}
	if res.Truncated {
		t.Error("expected Truncated=false for body within cap")
	}
}

func TestBodyOverMaxSizeReturnsTooLarge(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, strings.Repeat("x", 500))
	}))
	defer srv.Close()

	cfg := netConfig(true)
	cfg.MaxSize = 100
	f := fetch.New(cfg, allowAllEngine(t), nil, zap.NewNop())
	_, err := f.Fetch(context.Background(), srv.URL, "")
	if err == nil {
		t.Fatal("expected too_large error")
	}
	if !isFetchCode(err, "too_large") {
		t.Fatalf("expected code 'too_large', got: %v", err)
	}
}

// --- auth profile tests ---------------------------------------------------

func TestAuthProfileHeadersApplied(t *testing.T) {
	t.Parallel()
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		writeBody(t, w, "ok")
	}))
	defer srv.Close()

	reg := authprofile.New([]config.AuthProfile{
		{Name: "github", Headers: map[string]string{"Authorization": "token secret-value-123"}},
	})
	f := fetch.New(netConfig(true), allowAllEngine(t), reg, zap.NewNop())
	_, err := f.Fetch(context.Background(), srv.URL, "github")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seenAuth != "token secret-value-123" {
		t.Fatalf("server saw Authorization = %q, want %q", seenAuth, "token secret-value-123")
	}
}

// TestAuthHeaderValueNeverLogged is the Phase 3 crown-jewel redaction test:
// the auth profile header value is sent to the server but must not appear
// anywhere in captured log output.
func TestAuthHeaderValueNeverLogged(t *testing.T) {
	t.Parallel()
	logger, buf := newCaptureLogger()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, "ok")
	}))
	defer srv.Close()

	const secret = "super-secret-token-zzz"
	reg := authprofile.New([]config.AuthProfile{
		{Name: "github", Headers: map[string]string{"Authorization": "Bearer " + secret}},
	})
	f := fetch.New(netConfig(true), allowAllEngine(t), reg, logger)
	_, err := f.Fetch(context.Background(), srv.URL, "github")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, secret) {
		t.Errorf("secret value leaked into log output:\n%s", out)
	}
	if !strings.Contains(out, "github") {
		t.Errorf("expected profile name 'github' in log:\n%s", out)
	}
}

func TestUserAgentHeaderSet(t *testing.T) {
	t.Parallel()
	var seenUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUA = r.Header.Get("User-Agent")
		writeBody(t, w, "ok")
	}))
	defer srv.Close()

	cfg := netConfig(true)
	cfg.UserAgent = "keyhole-test-ua"
	f := fetch.New(cfg, allowAllEngine(t), nil, zap.NewNop())
	_, err := f.Fetch(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seenUA != "keyhole-test-ua" {
		t.Fatalf("User-Agent = %q, want %q", seenUA, "keyhole-test-ua")
	}
}

func TestTimeoutReturnsTimeoutCode(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		writeBody(t, w, "slow")
	}))
	defer srv.Close()

	cfg := netConfig(true)
	cfg.Timeout = "100ms"
	f := fetch.New(cfg, allowAllEngine(t), nil, zap.NewNop())
	_, err := f.Fetch(context.Background(), srv.URL, "")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !isFetchCode(err, "timeout") {
		t.Fatalf("expected code 'timeout', got: %v", err)
	}
}

func TestConnectionRefusedReturnsUnreachable(t *testing.T) {
	t.Parallel()
	// A port that's almost certainly closed.
	f := fetch.New(netConfig(true), allowAllEngine(t), nil, zap.NewNop())
	_, err := f.Fetch(context.Background(), "http://127.0.0.1:1/", "")
	if err == nil {
		t.Fatal("expected unreachable error")
	}
	if !isFetchCode(err, "unreachable") {
		t.Fatalf("expected code 'unreachable', got: %v", err)
	}
}

func TestResultHasStatusCodeAndContentType(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusTeapot)
		writeBody(t, w, "tea")
	}))
	defer srv.Close()

	f := fetch.New(netConfig(true), allowAllEngine(t), nil, zap.NewNop())
	res, err := f.Fetch(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.StatusCode != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusTeapot)
	}
	if !strings.HasPrefix(res.ContentType, "text/html") {
		t.Fatalf("content_type = %q", res.ContentType)
	}
}

func TestContextCanceledReturnsUnreachable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(time.Second)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	f := fetch.New(netConfig(true), allowAllEngine(t), nil, zap.NewNop())
	_, err := f.Fetch(ctx, srv.URL, "")
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- robots.txt tests -----------------------------------------------------

func TestRobotsTxtBlocksDisallowedPath(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			writeBody(t, w, "User-agent: *\nDisallow: /secret\n")
		case "/secret":
			writeBody(t, w, "should-be-blocked")
		default:
			writeBody(t, w, "ok")
		}
	}))
	defer srv.Close()

	cfg := netConfig(true)
	cfg.RespectRobots = true
	f := fetch.New(cfg, allowAllEngine(t), nil, zap.NewNop())
	_, err := f.Fetch(context.Background(), srv.URL+"/secret", "")
	if err == nil {
		t.Fatal("expected denial by robots.txt")
	}
	if !isFetchCode(err, "denied") {
		t.Fatalf("expected code 'denied', got: %v", err)
	}
}

func TestRobotsTxtAllowsPermittedPath(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			writeBody(t, w, "User-agent: *\nDisallow: /secret\n")
		case "/public":
			writeBody(t, w, "public-content")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := netConfig(true)
	cfg.RespectRobots = true
	f := fetch.New(cfg, allowAllEngine(t), nil, zap.NewNop())
	res, err := f.Fetch(context.Background(), srv.URL+"/public", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(res.Body) != "public-content" {
		t.Fatalf("body = %q", res.Body)
	}
}

func TestRobotsTxtMissingFailsOpen(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeBody(t, w, "content")
	}))
	defer srv.Close()

	cfg := netConfig(true)
	cfg.RespectRobots = true
	f := fetch.New(cfg, allowAllEngine(t), nil, zap.NewNop())
	res, err := f.Fetch(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("expected fail-open when robots.txt is absent: %v", err)
	}
	if string(res.Body) != "content" {
		t.Fatalf("body = %q", res.Body)
	}
}

// TestRobotsTxtCrossHostRedirectIsChecked pins that a redirect to another host
// still honors that host's robots.txt (previously only the original URL was
// checked, so a 302 bypassed politeness).
func TestRobotsTxtCrossHostRedirectIsChecked(t *testing.T) {
	t.Parallel()
	var blockedHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			writeBody(t, w, "User-agent: *\nDisallow: /blocked\n")
		case "/blocked":
			blockedHits.Add(1)
			writeBody(t, w, "should-not-reach")
		}
	}))
	defer target.Close()

	start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/start" {
			// /robots.txt and everything else: no robots here.
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, target.URL+"/blocked", http.StatusFound)
	}))
	defer start.Close()

	cfg := netConfig(true)
	cfg.RespectRobots = true
	f := fetch.New(cfg, allowAllEngine(t), nil, zap.NewNop())
	_, err := f.Fetch(context.Background(), start.URL+"/start", "")
	if err == nil {
		t.Fatal("expected robots denial on the redirect target")
	}
	if !isFetchCode(err, "denied") {
		t.Fatalf("expected code 'denied', got: %v", err)
	}
	if blockedHits.Load() != 0 {
		t.Fatalf("robots-denied target was contacted %d times", blockedHits.Load())
	}
}

// TestRobotsTxtCachedPerOrigin pins the per-origin cache: two fetches must not
// produce two robots.txt requests.
func TestRobotsTxtCachedPerOrigin(t *testing.T) {
	t.Parallel()
	var robotsHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			robotsHits.Add(1)
			writeBody(t, w, "User-agent: *\nDisallow: /secret\n")
		default:
			writeBody(t, w, "ok")
		}
	}))
	defer srv.Close()

	cfg := netConfig(true)
	cfg.RespectRobots = true
	f := fetch.New(cfg, allowAllEngine(t), nil, zap.NewNop())
	for _, p := range []string{"/public", "/open"} {
		if _, err := f.Fetch(context.Background(), srv.URL+p, ""); err != nil {
			t.Fatalf("fetch %s: %v", p, err)
		}
	}
	if got := robotsHits.Load(); got != 1 {
		t.Fatalf("robots.txt fetched %d times, want 1 (cached)", got)
	}
}

// TestRobotsTxtRespectsPolicyOnRobotsURL pins the other side: when policy
// denies the robots.txt URL itself, the check is skipped (fail open) instead of
// making content depend on a URL the operator forbade.
func TestRobotsTxtRespectsPolicyOnRobotsURL(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			writeBody(t, w, "User-agent: *\nDisallow: /\n")
		default:
			writeBody(t, w, "content")
		}
	}))
	defer srv.Close()

	base := strings.TrimPrefix(srv.URL, "http://")
	allow := true
	deny := false
	engine, err := rules.NewEngine([]config.Rule{
		{Match: "http://" + base + "/**", Allow: &allow},
		{Match: "http://" + base + "/robots.txt", Allow: &deny},
	}, "deny")
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	cfg := netConfig(true)
	cfg.RespectRobots = true
	f := fetch.New(cfg, engine, nil, zap.NewNop())
	res, err := f.Fetch(context.Background(), srv.URL+"/page", "")
	if err != nil {
		t.Fatalf("expected fail-open when robots.txt is policy-denied: %v", err)
	}
	if string(res.Body) != "content" {
		t.Fatalf("body = %q", res.Body)
	}
}

// --- test utilities -------------------------------------------------------

func isFetchCode(err error, code string) bool {
	var fe *fetch.Error
	if errors.As(err, &fe) {
		return fe.Code == code
	}
	return false
}

func boolPtr(b bool) *bool { return &b }

// stubResolver implements fetch.Resolver. For hosts not in the map it falls
// back to net.LookupIP so real httptest addresses (127.0.0.1 literals) still
// work.
type stubResolver map[string][]net.IP

func (s stubResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	if ips, ok := s[host]; ok {
		return ips, nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	return net.LookupIP(host)
}

// Ensure we use io so the import isn't flagged in future test additions.
var _ = io.Discard

// TestFinalRuleSurfacedAfterRedirect verifies that Result carries the rule
// matched on the final (post-redirect) URL, so the service layer can enforce
// the final rule's transform allowlist (a redirect must not deliver content
// under a transform the final rule forbids).
func TestFinalRuleSurfacedAfterRedirect(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/end", http.StatusFound)
		case "/end":
			writeBody(t, w, "arrived")
		}
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	allow := true
	e, err := rules.NewEngine([]config.Rule{
		{Match: "http://" + host + "/start", Allow: &allow, Transforms: []string{"raw", "markdown"}},
		{Match: "http://" + host + "/end", Allow: &allow, Transforms: []string{"raw"}},
	}, "deny")
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	f := fetch.New(netConfig(true), e, nil, zap.NewNop())
	res, ferr := f.Fetch(context.Background(), srv.URL+"/start", "")
	if ferr != nil {
		t.Fatalf("fetch: %v", ferr)
	}
	if res.FinalRule == nil {
		t.Fatal("FinalRule = nil, want the /end rule")
	}
	if len(res.FinalRule.Transforms) != 1 || res.FinalRule.Transforms[0] != "raw" {
		t.Fatalf("FinalRule.Transforms = %v, want [raw]", res.FinalRule.Transforms)
	}
}

// TestAuthProfileUserAgentWinsOverDefault pins the precedence: a profile
// header named User-Agent is applied (the [network] user_agent default only
// fills in when the profile left it unset). Previously the default was set
// first and the profile's UA was silently dropped.
func TestAuthProfileUserAgentWinsOverDefault(t *testing.T) {
	t.Parallel()
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	cfg := netConfig(true)
	cfg.UserAgent = "keyhole-default"
	profiles := authprofile.New([]config.AuthProfile{
		{Name: "custom-ua", Headers: map[string]string{"User-Agent": "profile-ua/1.0"}},
	})
	f := fetch.New(cfg, allowAllEngine(t), profiles, zap.NewNop())

	if _, err := f.Fetch(context.Background(), srv.URL+"/", "custom-ua"); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if gotUA != "profile-ua/1.0" {
		t.Fatalf("User-Agent = %q, want the profile value", gotUA)
	}

	// Without a profile the network default applies.
	if _, err := f.Fetch(context.Background(), srv.URL+"/", ""); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if gotUA != "keyhole-default" {
		t.Fatalf("User-Agent = %q, want the network default", gotUA)
	}
}
