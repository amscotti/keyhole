// Package rules is the policy heart of Keyhole: it normalizes URLs and decides,
// as a pure function of the loaded config and a URL, whether that URL may be
// fetched. There is no I/O here — only config and strings in, a Decision out —
// so the whole package is trivially unit-testable and never reaches the network.
//
// Normalization (Normalize) produces the canonical form every rule glob is
// matched against: lowercase scheme and host, default port stripped, fragment
// dropped, IDN hosts converted to punycode, query string preserved. The matcher
// (Engine.Evaluate) orders rules by the length of their literal prefix
// (specificity), and on a tie resolves to deny — fail closed. A deny on either
// the original URL or the final URL after a redirect blocks the request.
package rules

import (
	"bytes"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// MaxURLBytes bounds the raw URL accepted by Normalize (and therefore by
// policy evaluation and fetching). It exists so a hostile client cannot force
// the normalization pipeline to chew on a megabyte-scale path/query; the REST
// and MCP request-body caps are far larger, so without this an unauthenticated
// caller could burn CPU per request. 16 KiB is far above any real-world URL.
const MaxURLBytes = 16 * 1024

// Normalize canonicalizes a URL for matching: lowercase scheme and host, strip
// the default port (:80 for http, :443 for https), drop the fragment, convert
// an IDN host to punycode, and preserve the query string. The path is returned
// verbatim (paths are case-sensitive). A URL missing a scheme or host is an
// error rather than a best-effort guess, so policy is never evaluated against an
// ambiguous target.
//
// Only http and https are accepted: those are the only schemes the fetcher
// speaks, so a rule or request in any other scheme is a dead end, not a target
// policy should reason about.
//
// Query strings participate in matching byte-for-byte (Go's url.Parse preserves
// RawQuery exactly). Percent-encoding differences in a query therefore do not
// match each other; operators who need to deny a query value should deny the
// path (or use ignore_query) rather than rely on a query-literal rule.
func Normalize(rawURL string) (string, error) {
	if len(rawURL) > MaxURLBytes {
		return "", fmt.Errorf("normalize: URL exceeds %d bytes", MaxURLBytes)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("normalize: parse %q: %w", rawURL, err)
	}
	// Require both a scheme and a non-empty host. Note u.Host can be a stray
	// ":" (e.g. "a://:") while Hostname() is empty — that is not a fetchable
	// target, so test the hostname, not the raw authority.
	if u.Scheme == "" || u.Hostname() == "" {
		return "", fmt.Errorf("normalize: %q missing scheme or host", rawURL)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("normalize: unsupported scheme %q", u.Scheme)
	}
	u.Scheme = scheme

	// Strip userinfo: credentials must not participate in policy or ride
	// into the normalized form where logging/metrics could expose them
	// (secrets in headers get the same treatment).
	u.User = nil

	host, port, err := splitAuthority(u)
	if err != nil {
		return "", fmt.Errorf("normalize: %q: %w", rawURL, err)
	}
	normHost, err := normalizeHostname(host)
	if err != nil {
		return "", err
	}
	port, err = canonicalPort(scheme, port)
	if err != nil {
		return "", fmt.Errorf("normalize: %q: %w", rawURL, err)
	}
	u.Host = joinHostPort(normHost, port)

	// The fragment never participates in policy or fetching.
	u.Fragment = ""
	u.RawFragment = ""

	// An empty path is equivalent to "/" (RFC 3986 §3.3). Normalizing it
	// ensures a bare-host URL like "https://example.com?a=1" matches a
	// "/**" rule instead of silently falling through to the default policy.
	if u.Path == "" {
		u.Path = "/"
	}

	// Resolve "." and ".." segments (RFC 3986 §5.2.4) so a path like
	// /public/../secret resolves to /secret before matching. The upstream
	// server resolves these too, and policy must match what is actually
	// served, not the verbatim request path. Percent-encoded dots (%2e)
	// are already decoded into u.Path by url.Parse; clearing RawPath
	// ensures String() regenerates from the cleaned, decoded path so the
	// encoded form can't smuggle a traversal past the matcher.
	u.Path = resolveDotSegments(u.Path)
	u.RawPath = ""

	return u.String(), nil
}

// splitAuthority extracts the host and the explicit port from a parsed URL's
// authority. Unlike URL.Port, it also surfaces ports that net/url considers
// syntactically invalid ("h:12x") so canonicalPort can reject them instead of
// silently normalizing the target as if no port were present.
func splitAuthority(u *url.URL) (host, port string, err error) {
	host = u.Hostname()
	if host == "" {
		return "", "", fmt.Errorf("empty host")
	}
	rest := u.Host
	if strings.HasPrefix(rest, "[") {
		if idx := strings.IndexByte(rest, ']'); idx >= 0 {
			if len(rest) > idx+1 && rest[idx+1] == ':' {
				port = rest[idx+2:]
			}
			return host, port, nil
		}
		return "", "", fmt.Errorf("malformed IPv6 authority %q", rest)
	}
	if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		port = rest[i+1:]
	}
	return host, port, nil
}

// normalizeHostname lowercases a host and converts it to a canonical form:
// IP literals (including the legacy numeric forms resolvers accept) become
// their canonical address notation, and domain names become punycode via the
// idna lookup profile. Canonical IPs matter because policy matching must agree
// with what the dialer resolves: "https://2130706433/", "https://127.1/" and
// "https://[0:0:0:0:0:0:0:1]/" all dial addresses that a rule written in
// canonical form must be able to deny.
func normalizeHostname(host string) (string, error) {
	// Strip trailing dots (DNS root labels): "example.com." and "example.com"
	// resolve to the same host, so they must normalize identically — for both
	// target URLs and rule patterns — so a pattern written one way matches a
	// URL written the other. All of them, not just one: trimming a single dot
	// left "0.." as "0." and a second pass turned that into "0.0.0.0", making
	// Normalize non-idempotent (a fuzz-found bug) and accepting a bogus host
	// on the first pass.
	host = strings.TrimRight(host, ".")
	if host == "" {
		return "", fmt.Errorf("normalize: empty host")
	}
	if !utf8.ValidString(host) {
		return "", fmt.Errorf("normalize: host %q is not valid UTF-8", host)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		// Unmap ::ffff:127.0.0.1 to 127.0.0.1 so both spellings match the
		// same rule; they dial the same address.
		return ip.Unmap().String(), nil
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("normalize: host %q: %w", host, err)
	}
	if ascii == "" {
		// Some code points (e.g. U+034F COMBINING GRAPHEME JOINER) are
		// mapped away entirely. Without this check the first pass emitted a
		// host-less "http:///" and the second pass errored — non-idempotent
		// (fuzz-found).
		return "", fmt.Errorf("normalize: host %q maps to an empty name", host)
	}
	// Only accept a form that is its own IDNA fixed point. Exotic inputs can
	// otherwise map to an ACE label that the same lookup profile rejects on
	// re-parse (fuzz-found with a Balinese code point), making Normalize
	// non-idempotent. ASCII hosts pass through unchanged, so this is two
	// no-op checks in the common case.
	if again, aerr := idna.Lookup.ToASCII(ascii); aerr != nil || again != ascii {
		return "", fmt.Errorf("normalize: host %q does not have a stable IDNA form", host)
	}
	// The numeric-form check runs on the post-IDNA ASCII form: Unicode
	// digits and lookalikes are mapped by IDNA (e.g. "⁵" -> "5"), and
	// checking before the mapping left the first pass emitting "5" and the
	// second resolving it to 0.0.0.5 — non-idempotent (fuzz-found).
	if ip, ok, err := parseNumericHost(ascii); err != nil {
		return "", err
	} else if ok {
		return ip.String(), nil
	}
	return ascii, nil
}

// parseNumericHost parses the legacy inet_aton numeric host forms that system
// resolvers (getaddrinfo) accept but netip.ParseAddr does not: packed decimal
// ("2130706433"), hexadecimal ("0x7f000001"), octal ("0177.0.0.1") and short
// dotted forms ("127.1"). Without this, such a host would normalize as a domain
// name while the wire dial resolves it to an IP — policy and fetch would
// disagree, and a deny rule written against the IP would miss.
//
// It returns (addr, true, nil) for valid numeric forms, (zero, false, nil) when
// the host is not numeric-like, and an error when the host is numeric-like but
// out of range (fail closed rather than treating it as a domain).
func parseNumericHost(host string) (netip.Addr, bool, error) {
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false, nil
	}
	vals := make([]uint64, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return netip.Addr{}, false, nil
		}
		base := 10
		switch {
		case len(p) > 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X'):
			base, p = 16, p[2:]
			if p == "" {
				return netip.Addr{}, false, nil
			}
		case len(p) > 1 && p[0] == '0':
			base = 8
		}
		v, err := strconv.ParseUint(p, base, 32)
		if err != nil {
			// Not numeric-like (a normal domain label, or a malformed
			// numeric label). A digit-only label that fails to parse is a
			// malformed numeric form: reject rather than guess.
			if isAllDigits(p) {
				return netip.Addr{}, false, fmt.Errorf("normalize: malformed numeric host %q", host)
			}
			return netip.Addr{}, false, nil
		}
		vals = append(vals, v)
	}
	var b [4]byte
	switch len(vals) {
	case 4:
		for i, v := range vals {
			if v > 255 {
				return netip.Addr{}, false, fmt.Errorf("normalize: numeric host %q out of range", host)
			}
			b[i] = byte(v)
		}
	case 3:
		if vals[0] > 255 || vals[1] > 255 || vals[2] > 0xFFFF {
			return netip.Addr{}, false, fmt.Errorf("normalize: numeric host %q out of range", host)
		}
		b = [4]byte{byte(vals[0]), byte(vals[1]), byte(vals[2] >> 8), byte(vals[2])}
	case 2:
		if vals[0] > 255 || vals[1] > 0xFFFFFF {
			return netip.Addr{}, false, fmt.Errorf("normalize: numeric host %q out of range", host)
		}
		b = [4]byte{byte(vals[0]), byte(vals[1] >> 16), byte(vals[1] >> 8), byte(vals[1])}
	case 1:
		if vals[0] > 0xFFFFFFFF {
			return netip.Addr{}, false, fmt.Errorf("normalize: numeric host %q out of range", host)
		}
		b = [4]byte{byte(vals[0] >> 24), byte(vals[0] >> 16), byte(vals[0] >> 8), byte(vals[0])}
	default:
		return netip.Addr{}, false, nil
	}
	return netip.AddrFrom4(b), true, nil
}

// isAllDigits reports whether s is a non-empty run of ASCII digits.
func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// joinHostPort reassembles a host[:port], restoring IPv6 brackets. IPv6
// addresses contain colons and must be bracketed inside a URL authority.
func joinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		return host + ":" + port
	}
	return host
}

// canonicalPort validates and canonicalizes an explicit port: leading zeros are
// removed, out-of-range or non-numeric ports are errors (the dialer would
// reject or reinterpret them), and the scheme default port is stripped so
// "https://h:0443/" and "https://h/" normalize identically.
func canonicalPort(scheme, port string) (string, error) {
	if port == "" {
		return "", nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid port %q", port)
	}
	if (scheme == "http" && n == 80) || (scheme == "https" && n == 443) {
		return "", nil
	}
	return strconv.Itoa(n), nil
}

// resolveDotSegments implements the RFC 3986 §5.2.4 remove_dot_segments
// algorithm. It resolves "." and ".." path segments so that, e.g.,
// "/public/../secret" becomes "/secret". The algorithm never produces a path
// that escapes above the root: excess ".." segments at the root are silently
// dropped. Trailing slashes are preserved (unlike path.Clean, which strips
// them), because a trailing slash is semantically significant in URLs.
//
// The implementation advances an index into p and writes into one byte slice,
// so a long path is O(n); earlier versions that re-sliced by string
// concatenation ("in = \"/\" + in[3:]") were quadratic and made a large URL a
// CPU-exhaustion vector.
func resolveDotSegments(p string) string {
	i := 0
	out := make([]byte, 0, len(p))
	for i < len(p) {
		switch {
		case strings.HasPrefix(p[i:], "../"):
			i += 3
		case strings.HasPrefix(p[i:], "./"):
			i += 2
		case p[i:] == "/.":
			// RFC: "/." becomes "/", which the move step below emits.
			out = append(out, '/')
			i = len(p)
		case strings.HasPrefix(p[i:], "/./"):
			// RFC: "/./" becomes "/" — skip the dot, keep the slash.
			i += 2
		case p[i:] == "/..":
			// RFC: "/.." becomes "/" with the last output segment removed.
			out = removeLastSegment(out)
			out = append(out, '/')
			i = len(p)
		case strings.HasPrefix(p[i:], "/../"):
			// RFC: "/../" becomes "/" with the last output segment removed;
			// consume "/.." and leave the slash for the next iteration.
			out = removeLastSegment(out)
			i += 3
		case p[i:] == "." || p[i:] == "..":
			i = len(p)
		default:
			// Move the first path segment (including the initial "/" if
			// any) to the output, up to but not including the next "/".
			start := i
			if p[start] == '/' {
				start++
			}
			end := start
			for end < len(p) && p[end] != '/' {
				end++
			}
			out = append(out, p[i:end]...)
			i = end
		}
	}
	return string(out)
}

// removeLastSegment strips the last path segment (and its preceding "/") from
// out. If out has no "/", the entire slice is discarded — this is the "can't
// escape above root" case.
func removeLastSegment(out []byte) []byte {
	if i := bytes.LastIndexByte(out, '/'); i >= 0 {
		return out[:i]
	}
	return out[:0]
}
