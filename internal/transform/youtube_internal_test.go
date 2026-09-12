package transform

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	youtube "github.com/kkdai/youtube/v2"

	"github.com/amscotti/keyhole/internal/egress"
)

// egressNewHTTPClientForTest mirrors the production wiring in
// cmd/keyhole buildDeps: a client built by the egress choke point.
func egressNewHTTPClientForTest() *http.Client {
	return egress.NewHTTPClient(egress.Policy{}, 5*time.Second, 10)
}

// TestRealYouTubeClientNilDefaultsTimeout verifies that NewRealYouTubeClient
// never produces an HTTP client with a zero timeout (which would let a stalled
// YouTube innertube response pin a handler goroutine indefinitely). A nil
// client must fall back to a sane default, not http.DefaultClient (Timeout 0).
//
// Guards finding R1: the production wiring must apply [network].timeout, and a
// nil client must still be bounded as defense in depth.
func TestRealYouTubeClientNilDefaultsTimeout(t *testing.T) {
	t.Parallel()

	rc, ok := NewRealYouTubeClient(nil).(*realYouTubeClient)
	if !ok {
		t.Fatalf("NewRealYouTubeClient(nil) = %T, want *realYouTubeClient", rc)
	}
	hc := rc.yt.HTTPClient
	if hc == nil {
		t.Fatal("YouTube client HTTPClient is nil; expected a default client with a non-zero timeout")
	}
	if hc.Timeout <= 0 {
		t.Fatalf("YouTube client default timeout = %v, want > 0", hc.Timeout)
	}
}

// TestRealYouTubeClientHonorsInjectedTimeout verifies that an explicitly
// provided HTTP client (as the production wiring now passes) is used verbatim,
// so [network].timeout is honored on the YouTube fetch path.
func TestRealYouTubeClientHonorsInjectedTimeout(t *testing.T) {
	t.Parallel()

	want := 7 * time.Second
	rc, ok := NewRealYouTubeClient(&http.Client{Timeout: want}).(*realYouTubeClient)
	if !ok {
		t.Fatalf("NewRealYouTubeClient = %T, want *realYouTubeClient", rc)
	}
	if rc.yt.HTTPClient == nil {
		t.Fatal("expected the injected HTTP client to be used")
	}
	if rc.yt.HTTPClient.Timeout != want {
		t.Fatalf("timeout = %v, want %v", rc.yt.HTTPClient.Timeout, want)
	}
}

// TestParseTimedText verifies the timedtext XML fallback parser used by the real
// YouTube client. The kkdai library's innertube get_transcript endpoint returns
// HTTP 400 against current YouTube, so the client fetches the caption track's
// signed BaseURL directly (PLAN.md:208 "fall back to fetching the timedtext
// captions directly"). This pins the parser against a realistic payload
// including styled <s> sub-segments, an empty paragraph, XML entity refs, and
// non-paragraph <w> window events that must be ignored.
func TestParseTimedText(t *testing.T) {
	t.Parallel()

	const payload = `<?xml version="1.0" encoding="utf-8" ?><timedtext format="3">
<head>
<ws id="0"/>
<wp id="1" ap="6" ah="20" av="100" rc="2" cc="40"/>
</head>
<body>
<w t="0" id="1" wp="1" ws="1"/>
<p t="320" d="14260" w="1">[Music]</p>
<p t="18790" w="1" a="1">
</p>
<p t="18800" d="7160" w="1"><s ac="0">We&#39;re</s><s t="239" ac="0"> no</s><s t="559" ac="0"> strangers</s></p>
</body>
</timedtext>`

	got, err := parseTimedText([]byte(payload))
	if err != nil {
		t.Fatalf("parseTimedText error: %v", err)
	}
	want := []CaptionLine{
		{Text: "[Music]", StartMs: 320},
		{Text: "We're no strangers", StartMs: 18800},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseTimedText = %#v, want %#v", got, want)
	}
}

// TestParseTimedTextEmptyAndMalformed ensures the parser never panics on empty
// or degenerate input and returns no segments rather than an error for a valid
// but empty body.
func TestParseTimedTextEmptyAndMalformed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
	}{
		{"empty body", `<?xml version="1.0"?><timedtext><body></body></timedtext>`},
		{"no body", `<?xml version="1.0"?><timedtext></timedtext>`},
		{"empty string", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseTimedText([]byte(tc.in))
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.name, err)
			}
			if len(got) != 0 {
				t.Errorf("expected no segments for %q, got %d", tc.name, len(got))
			}
		})
	}
}

// TestParseTimedTextKeepsLinesBeforeMidStreamError pins the partial-payload
// contract: a truncated caption stream must keep the segments that parsed and
// report the fault, not throw them away and claim there is no transcript.
func TestParseTimedTextKeepsLinesBeforeMidStreamError(t *testing.T) {
	t.Parallel()
	payload := `<?xml version="1.0"?><timedtext><body>` +
		`<p t="0">first</p><p t="1000">second</p><p t="2000">unterminated`
	lines, err := parseTimedText([]byte(payload))
	if err == nil {
		t.Fatal("expected a parse error for the truncated payload")
	}
	if len(lines) != 2 {
		t.Fatalf("kept %d segments, want the 2 complete ones", len(lines))
	}
	if lines[0].Text != "first" || lines[1].Text != "second" {
		t.Fatalf("lines = %+v", lines)
	}
}

func TestIsAllowedCaptionHost(t *testing.T) {
	t.Parallel()
	allow := []string{
		"www.youtube.com",
		"youtube.com",
		"m.youtube.com",
		"www.youtube-nocookie.com",
		"manifest.googlevideo.com",
		"video.google.com",
		"www.googleapis.com",
	}
	for _, h := range allow {
		if !isAllowedCaptionHost(h) {
			t.Errorf("isAllowedCaptionHost(%q) = false, want true", h)
		}
	}
	deny := []string{"evil.example", "169.254.169.254", "localhost", "metadata.google.internal"}
	for _, h := range deny {
		if isAllowedCaptionHost(h) {
			t.Errorf("isAllowedCaptionHost(%q) = true, want false", h)
		}
	}
}

func TestFetchCaptionRejectsDisallowedHost(t *testing.T) {
	t.Parallel()
	rc := NewRealYouTubeClient(nil).(*realYouTubeClient)
	_, err := rc.fetchCaption(context.Background(), "http://127.0.0.1/captions")
	if err == nil {
		t.Fatal("expected denial for loopback caption host")
	}
	ce, ok := err.(*ClientError)
	if !ok || ce.Code != CodeDenied {
		t.Fatalf("expected CodeDenied ClientError, got %v", err)
	}
}

func TestFetchCaptionEnforcesSizeCap(t *testing.T) {
	t.Parallel()
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", 100))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})
	client := NewRealYouTubeClientLimited(&http.Client{
		Transport: rt,
		Timeout:   5 * time.Second,
	}, 10).(*realYouTubeClient)
	// Ensure the underlying youtube.Client uses our transport.
	client.yt = youtube.Client{HTTPClient: &http.Client{Transport: rt, Timeout: 5 * time.Second}}

	_, err := client.fetchCaption(context.Background(), "https://www.youtube.com/api/timedtext?v=x")
	if err == nil {
		t.Fatal("expected too_large for oversized caption body")
	}
	ce, ok := err.(*ClientError)
	if !ok || ce.Code != CodeTooLarge {
		t.Fatalf("expected CodeTooLarge ClientError, got %v", err)
	}
}

func TestFetchCaptionSuccess(t *testing.T) {
	t.Parallel()
	body := `<?xml version="1.0"?><timedtext><body><p t="0" d="1000">hi</p></body></timedtext>`
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})
	client := NewRealYouTubeClientLimited(&http.Client{
		Transport: rt,
		Timeout:   5 * time.Second,
	}, 1024).(*realYouTubeClient)
	client.yt = youtube.Client{HTTPClient: &http.Client{Transport: rt, Timeout: 5 * time.Second}}

	got, err := client.fetchCaption(context.Background(), "https://www.youtube.com/api/timedtext?v=x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != body {
		t.Fatalf("body = %q, want %q", got, body)
	}
}

// --- test doubles ---------------------------------------------------------

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestFetchCaptionDoesNotFollowRedirects pins the SSRF fail-closed behavior:
// an allowlisted caption URL whose response is a redirect to a NON-allowed
// host (e.g. a cloud metadata endpoint) must not be followed — the redirect
// surfaces as an unreachable-caption error instead.
func TestFetchCaptionDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var followed *url.URL
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/redirect") {
			return &http.Response{
				StatusCode: http.StatusFound,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     http.Header{"Location": []string{"http://169.254.169.254/latest/meta-data/"}},
				Request:    req,
			}, nil
		}
		followed = req.URL
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("should never be reached")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})
	client := NewRealYouTubeClientLimited(&http.Client{
		Transport: rt,
		Timeout:   5 * time.Second,
	}, 1024).(*realYouTubeClient)
	client.yt = youtube.Client{HTTPClient: &http.Client{Transport: rt, Timeout: 5 * time.Second}}

	_, err := client.fetchCaption(context.Background(), "https://www.youtube.com/api/timedtext/redirect")
	if err == nil {
		t.Fatal("expected an error for a redirecting caption URL")
	}
	ce, ok := err.(*ClientError)
	if !ok {
		t.Fatalf("expected *ClientError, got %T %v", err, err)
	}
	if ce.Code != CodeUnreachable {
		t.Fatalf("code = %q, want %q", ce.Code, CodeUnreachable)
	}
	if followed != nil {
		t.Fatalf("redirect WAS followed to %s — the metadata host must never be contacted", followed)
	}
}

// TestRealYouTubeClientEgressGuarded is the egress-invariant lock: every
// YouTube HTTP client — the nil fallback and any production-injected client
// built by egress.NewHTTPClient — must dial through a guarded transport, so
// the DirectTransform path shares the fetcher's SSRF policy. A passed client
// is used verbatim (policy honored, not overwritten).
func TestRealYouTubeClientEgressGuarded(t *testing.T) {
	t.Parallel()

	assertGuarded := func(name string, hc *http.Client) {
		t.Helper()
		rt := hc.Transport
		// The size-cap wrapper (egress.NewSizeCappedTransport) wraps the
		// guarded transport; unwrap it to reach the dial.
		if u, ok := rt.(interface{ Unwrap() http.RoundTripper }); ok {
			rt = u.Unwrap()
		}
		tr, ok := rt.(*http.Transport)
		if !ok {
			t.Fatalf("%s: Transport = %T, want *http.Transport from egress", name, rt)
		}
		if tr.DialContext == nil {
			t.Fatalf("%s: Transport.DialContext is nil; want the egress guarded dial", name)
		}
	}

	// Nil fallback: guarded with the strict default policy.
	rc, ok := NewRealYouTubeClient(nil).(*realYouTubeClient)
	if !ok {
		t.Fatalf("NewRealYouTubeClient(nil) = %T, want *realYouTubeClient", rc)
	}
	assertGuarded("nil fallback", rc.yt.HTTPClient)

	// Injected egress client: preserved verbatim, transport intact.
	injected := egressNewHTTPClientForTest()
	rc2, ok := NewRealYouTubeClientLimited(injected, 1024).(*realYouTubeClient)
	if !ok {
		t.Fatalf("NewRealYouTubeClientLimited = %T, want *realYouTubeClient", rc2)
	}
	if rc2.yt.HTTPClient != injected {
		t.Fatal("injected client was replaced; production SSRF policy would be dropped")
	}
	assertGuarded("injected", rc2.yt.HTTPClient)
}
