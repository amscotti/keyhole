package fetch

import (
	"net/http"
	"net/url"
	"testing"

	"go.uber.org/zap"

	"github.com/amscotti/keyhole/internal/authprofile"
	"github.com/amscotti/keyhole/internal/config"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestSameOrigin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		origin string
		dst    string
		want   bool
	}{
		{"same host and scheme", "https://api.example.com/a", "https://api.example.com/b", true},
		{"explicit default port equals implicit", "https://api.example.com/a", "https://api.example.com:443/b", true},
		{"https upgrade is same origin", "http://api.example.com/a", "https://api.example.com/b", true},
		{"https downgrade is not same origin", "https://api.example.com/a", "http://api.example.com/b", false},
		{"different host", "https://api.example.com/a", "https://other.example.com/b", false},
		{"different port", "https://api.example.com/a", "https://api.example.com:8443/b", false},
		{"non-default port", "http://api.example.com:8080/a", "http://api.example.com:8080/b", true},
		{"host case-insensitive", "https://API.example.com/a", "https://api.example.com/b", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := sameOrigin(mustURL(t, tc.origin), mustURL(t, tc.dst)); got != tc.want {
				t.Fatalf("sameOrigin(%q, %q) = %v, want %v", tc.origin, tc.dst, got, tc.want)
			}
		})
	}
}

func TestCurateProfileHeadersRules(t *testing.T) {
	t.Parallel()
	profiles := authprofile.New([]config.AuthProfile{
		{Name: "a", Headers: map[string]string{"X-Api-Key": "secret-a"}},
		{Name: "b", Headers: map[string]string{"X-Api-Key": "secret-b"}},
	})
	f := &Fetcher{profiles: profiles, logger: zap.NewNop()}

	newReq := func(raw string) *http.Request {
		req := &http.Request{URL: mustURL(t, raw), Header: http.Header{}}
		req.Header.Set("X-Api-Key", "secret-a")
		return req
	}
	origin := mustURL(t, "https://api.example.com/a")

	tests := []struct {
		name    string
		dst     string
		rule    *config.Rule
		wantKey string
	}{
		{"same origin keeps inherited", "https://api.example.com/b", nil, "secret-a"},
		{"downgrade strips", "http://api.example.com/b", nil, ""},
		{"cross-host strips", "https://cdn.example.com/b", nil, ""},
		{"destination profile replaces inherited", "https://cdn.example.com/b", &config.Rule{AuthProfile: "b"}, "secret-b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := newReq(tc.dst)
			f.curateProfileHeaders(origin, req, tc.rule)
			if got := req.Header.Get("X-Api-Key"); got != tc.wantKey {
				t.Fatalf("X-Api-Key = %q, want %q", got, tc.wantKey)
			}
		})
	}
}
