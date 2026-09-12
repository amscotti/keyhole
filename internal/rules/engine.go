package rules

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/amscotti/keyhole/internal/config"
)

// globMetacharacters are the characters doublestar treats specially. A rule
// pattern whose authority (host) contains any of these is a wildcard host and
// gets lowercased only — IDN punycode conversion does not apply to wildcards.
const globMetacharacters = "*?[]{}"

// Decision is the outcome of evaluating policy against one URL.
type Decision struct {
	// Allowed is true when the URL may be fetched.
	Allowed bool
	// Rule is the matched rule that decided the outcome, or nil when the default
	// policy applied (no rule matched). Callers consult Rule.Transforms and
	// Rule.AuthProfile after a match.
	Rule *config.Rule
	// Reason is a human-readable, single-line explanation suitable for logs.
	Reason string
}

// Engine is a precompiled, specificity-ordered rule set plus the default policy.
// Building it once and reusing it across requests means rule patterns are
// validated and sorted only at load (and on reload), not per request.
type Engine struct {
	compiled []compiledRule
	policy   string // "allow" | "deny"
}

// compiledRule is a single rule with its glob and specificity precomputed.
type compiledRule struct {
	rule    *config.Rule
	pattern string
	// literalLen is the primary specificity: length of the literal (non-glob)
	// prefix. literalTotal is the secondary: the count of literal bytes in the
	// whole pattern. The secondary matters for same-prefix patterns such as
	// "host/**" vs "host/**/*.docx", where the prefix is identical and only
	// the suffix distinguishes the more constrained rule.
	literalLen   int
	literalTotal int
	ignoreQuery  bool
}

// NewEngine validates each rule's glob, precomputes specificity, and orders the
// rules so that the most specific (longest literal prefix) come first. An
// invalid glob is a load-time error: a typo in a pattern must never silently
// widen access.
func NewEngine(rules []config.Rule, defaultPolicy string) (*Engine, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		if !doublestar.ValidatePattern(r.Match) {
			return nil, fmt.Errorf("rules: invalid glob pattern %q", r.Match)
		}
		// When the rule opts into ignore_query, strip the query from the
		// pattern as well as the target so the match is on the path alone.
		// Without this, a pattern like "https://h/watch?v=*" would never
		// match a target whose query was already stripped.
		// Normalize the pattern's authority (scheme/host/port) to the same
		// canonical form targets use, so a deny rule written as
		// "https://EXAMPLE.com:443/**" still matches "https://example.com/a".
		// Without this, non-canonical deny rules are silently dead under
		// default-allow (blocklist mode) — a "typo must never silently weaken
		// policy" violation. A pattern that cannot be
		// canonicalized is a load error for the same reason.
		pattern, err := normalizePattern(r.Match)
		if err != nil {
			return nil, err
		}
		if hasWildcardIDNLabel(pattern) {
			// A glob metacharacter inside a Unicode label ("münchen*.de")
			// cannot be punycoded, so it can never match a normalized target —
			// a silently dead rule (fail-open under a default-allow deny).
			// Reject at load; wildcard labels must be pure ASCII.
			return nil, fmt.Errorf(
				"rules: pattern %q has a wildcard inside a non-ASCII (IDN) label; punycode the label or keep the wildcard in its own ASCII-only label",
				r.Match)
		}
		if !hasURLAuthority(pattern) {
			// Normalized targets always carry scheme + authority, so such a
			// pattern can never match — a dead rule. Under default-allow a
			// dead deny rule fails open, which the config contract forbids;
			// reject at load instead.
			return nil, fmt.Errorf(
				"rules: pattern %q must be a full URL (scheme://host[/path])",
				r.Match)
		}
		if r.IgnoreQuery {
			pattern = stripQuery(pattern)
		}
		// Escape '?' so doublestar treats it as a literal query separator,
		// not a single-char wildcard. In URL patterns '?' always means
		// "start of query string" — a bare '?' widening an allow rule is a
		// silent security hole.
		pattern = escapeQueryMark(pattern)
		compiled = append(compiled, compiledRule{
			rule:         r,
			pattern:      pattern,
			literalLen:   literalPrefixLen(pattern),
			literalTotal: literalByteLen(pattern),
			ignoreQuery:  r.IgnoreQuery,
		})
	}
	// Sort by specificity descending: longest literal prefix first, then the
	// most literal bytes overall (so "host/**/*.docx" outranks "host/**" even
	// though their prefixes are identical). Remaining ties keep deny ahead of
	// allow so the scan below encounters a deny first and fails closed.
	sort.SliceStable(compiled, func(i, j int) bool {
		if compiled[i].literalLen != compiled[j].literalLen {
			return compiled[i].literalLen > compiled[j].literalLen
		}
		if compiled[i].literalTotal != compiled[j].literalTotal {
			return compiled[i].literalTotal > compiled[j].literalTotal
		}
		return !compiled[i].rule.Allowed() && compiled[j].rule.Allowed()
	})
	return &Engine{compiled: compiled, policy: defaultPolicy}, nil
}

// Evaluate decides whether rawURL may be fetched. The URL is normalized first,
// then matched against each rule (most specific first). The most specific
// matching rule wins; if several rules share that top specificity, any deny
// among them blocks the request (fail closed). No matching rule falls back to
// the default policy.
func (e *Engine) Evaluate(rawURL string) (Decision, error) {
	norm, err := Normalize(rawURL)
	if err != nil {
		return Decision{}, err
	}
	return e.evaluateNormalized(norm), nil
}

// evaluateNormalized is the pure core: it runs the matcher against an already
// normalized URL. Splitting it out keeps the redirect helper allocation-free
// for the repeated normalization path.
func (e *Engine) evaluateNormalized(norm string) Decision {
	const noMatch = "no matching rule"
	if e.policy == "allow" {
		// Default-allow: start open and let a matching deny close it.
		fallback := Decision{Allowed: true, Rule: nil, Reason: noMatch + "; default policy allow"}
		result, matched := e.match(norm)
		if !matched {
			return fallback
		}
		return result
	}

	// Default-deny: start closed; only a matching allow opens it.
	fallback := Decision{Allowed: false, Rule: nil, Reason: noMatch + "; default policy deny"}
	result, matched := e.match(norm)
	if !matched {
		return fallback
	}
	return result
}

// match scans the precompiled rules (already specificity-ordered) and returns
// the decision among the most-specific matching rules, plus whether any rule
// matched at all. Because the slice is sorted with deny ahead of allow on ties,
// the first matching rule at the top specificity is authoritative: a deny there
// blocks; otherwise the allow holds.
func (e *Engine) match(norm string) (Decision, bool) {
	topLit := -1
	var topRule *compiledRule
	for i := range e.compiled {
		cr := &e.compiled[i]
		target := matchTarget(norm, cr.ignoreQuery)
		ok, err := doublestar.Match(cr.pattern, target)
		if err != nil {
			// Patterns are validated at NewEngine, so this is unreachable in
			// practice; treat it as a denial rather than granting access.
			return denyDecision(cr, "denied: pattern error"), true
		}
		if !ok {
			continue
		}
		if topRule == nil {
			// First match establishes the specificity tier under consideration.
			topLit = cr.literalLen
			topRule = cr
			continue
		}
		// We only care about rules tied at the top specificity. The slice is
		// sorted so a deny at this tier precedes an allow; the first match
		// already captured that. A strictly less-specific match ends the scan.
		if cr.literalLen < topLit {
			break
		}
		// Equal specificity: a deny here overrides the allow we may have kept.
		if !cr.rule.Allowed() {
			topRule = cr
		}
	}
	if topRule == nil {
		return Decision{}, false
	}
	if topRule.rule.Allowed() {
		return allowDecision(topRule), true
	}
	return denyDecision(topRule, "denied by rule"), true
}

func allowDecision(cr *compiledRule) Decision {
	return Decision{Allowed: true, Rule: cr.rule, Reason: fmt.Sprintf("allowed by rule %q", cr.pattern)}
}

func denyDecision(cr *compiledRule, reason string) Decision {
	return Decision{Allowed: false, Rule: cr.rule, Reason: fmt.Sprintf("%s %q", reason, cr.pattern)}
}

// matchTarget returns the URL to match a rule against: the normalized URL, with
// its query string stripped when the rule opts into ignore_query.
func matchTarget(norm string, ignoreQuery bool) string {
	if !ignoreQuery {
		return norm
	}
	return stripQuery(norm)
}

// stripQuery removes the query string (and the '?' separator) from a URL or
// pattern. Used by both compile time (pattern) and match time (target) so the
// two sides agree when ignore_query is in effect.
func stripQuery(s string) string {
	if i := strings.IndexByte(s, '?'); i >= 0 {
		return s[:i]
	}
	return s
}

// literalPrefixLen measures primary specificity: the length of the leading run
// of literal (non-glob) characters before the first wildcard metacharacter. A
// longer prefix means a more specific rule. Metacharacters are those doublestar
// treats specially: *, ?, [, {. A backslash escape (\x) counts as two literal
// bytes so that an escaped '?' (the query separator) is correctly treated as
// literal rather than as a wildcard.
func literalPrefixLen(pattern string) int {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '\\' && i+1 < len(pattern) {
			i++ // skip the escaped character
			continue
		}
		switch pattern[i] {
		case '*', '?', '[', '{':
			return i
		}
	}
	return len(pattern)
}

// literalByteLen counts the literal (non-glob) bytes anywhere in a pattern.
// It is the tiebreak for patterns sharing a literal prefix, e.g. "host/**"
// versus "host/**/*.docx": the latter constrains more and must win so its
// transform allowlist (and credentials, if any) applies.
func literalByteLen(pattern string) int {
	n := 0
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '\\' && i+1 < len(pattern) {
			n += 2
			i++ // skip the escaped character
			continue
		}
		switch pattern[i] {
		case '*', '?', '[', ']', '{', '}':
			// glob syntax — not a literal byte
		default:
			n++
		}
	}
	return n
}

// escapeQueryMark replaces every unescaped '?' with '\?' so doublestar treats
// the query separator as a literal character, not a single-char wildcard. In
// URL patterns '?' always means "start of query string". Already-escaped
// sequences (\?) are left intact.
func escapeQueryMark(pattern string) string {
	if !strings.ContainsRune(pattern, '?') {
		return pattern
	}
	var b strings.Builder
	b.Grow(len(pattern) + 4)
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c == '\\' && i+1 < len(pattern) {
			b.WriteByte(c)
			b.WriteByte(pattern[i+1])
			i++
			continue
		}
		if c == '?' {
			b.WriteString(`\?`)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// normalizePattern canonicalizes the authority (scheme + host + port) of a rule
// pattern so it matches targets that Normalize has already canonicalized. Only
// the authority is touched; the path and query — which carry the glob
// metacharacters — are preserved verbatim so doublestar matching is unaffected.
//
// For literal hosts the same normalization as Normalize applies: lowercase,
// canonical IP notation (packed/hex/short forms included), punycode IDN, strip
// trailing DNS dot. For wildcard hosts (containing glob metacharacters) each
// non-wildcard label is lowercased and punycoded individually — a wildcard IDN
// pattern must still match the punycoded target. The default port for the
// scheme is stripped and explicit ports are validated so a pattern written with
// ":0443" matches a target whose port was normalized away.
//
// Three target-canonicalization rules are mirrored here so a pattern written
// without them is not silently dead (Normalize applies them to every target):
//   - a bare authority (no path, no query) gets "/" appended, and a query-only
//     suffix gets "/" inserted before it, so "https://example.com" compiles to
//     "https://example.com/";
//   - the fragment portion is dropped (targets never carry one);
//   - bracketed IPv6 literals are glob-escaped ("\[", "\]") — brackets are glob
//     metacharacters and an unescaped "[::1]" compiles into a character class
//     that can never match its own host (and may match a different one).
//
// Anything that cannot match a normalized target is an error: a pattern with
// userinfo, an invalid host/IP/port, a bracketed non-IP host, or a scheme other
// than http/https. Under default-allow a dead deny rule fails open, so these
// must be loud load failures rather than silent no-ops.
func normalizePattern(pattern string) (string, error) {
	schemeEnd := strings.Index(pattern, "://")
	if schemeEnd < 0 {
		return pattern, nil // not a URL-like pattern; NewEngine rejects these
	}
	scheme := strings.ToLower(pattern[:schemeEnd])
	if !strings.ContainsAny(scheme, globMetacharacters) && scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("rules: pattern %q: unsupported scheme %q (only http/https)", pattern, scheme)
	}

	after := pattern[schemeEnd+3:] // everything past "://"
	// The authority runs up to the first path/query/fragment separator.
	authEnd := strings.IndexAny(after, "/?#")
	var auth, suffix string
	if authEnd < 0 {
		auth = after
		suffix = ""
	} else {
		auth = after[:authEnd]
		suffix = after[authEnd:]
	}
	if auth == "" {
		return pattern, nil // malformed authority; NewEngine rejects these
	}
	if strings.Contains(auth, "@") {
		// Targets have userinfo stripped before matching, so a pattern with
		// userinfo can never match anything — reject the dead rule.
		return "", fmt.Errorf("rules: pattern %q must not contain userinfo", pattern)
	}

	// Targets never carry a fragment: drop it from the pattern too.
	if i := strings.IndexByte(suffix, '#'); i >= 0 {
		suffix = suffix[:i]
	}
	// Mirror Normalize's empty-path-to-"/" rule: a bare authority (or one with
	// only a query) must compile with an explicit "/" so it can match a target
	// whose empty path was normalized to "/".
	if suffix == "" || suffix[0] == '?' {
		suffix = "/" + suffix
	}

	host, port, err := splitPatternHostPort(auth)
	if err != nil {
		return "", fmt.Errorf("rules: pattern %q: %w", pattern, err)
	}

	if !strings.ContainsAny(host, globMetacharacters) {
		host, err = normalizeHostname(host)
		if err != nil {
			return "", fmt.Errorf("rules: pattern %q: %w", pattern, err)
		}
	} else {
		host, err = normalizeWildcardHost(host)
		if err != nil {
			return "", fmt.Errorf("rules: pattern %q: %w", pattern, err)
		}
	}

	if port != "" && !strings.ContainsAny(port, globMetacharacters) {
		port, err = canonicalPort(scheme, port)
		if err != nil {
			return "", fmt.Errorf("rules: pattern %q: %w", pattern, err)
		}
	}

	return scheme + "://" + joinPatternHostPort(host, port) + suffix, nil
}

// normalizeWildcardHost canonicalizes a host that contains glob metacharacters
// (e.g. "*.example.com"): each label is processed independently so wildcard
// labels survive while literal labels get the same lowercase + punycode
// treatment Normalize applies to targets. Without this, a wildcard IDN pattern
// like "*.münchen.de" never matches its punycoded target form — a dead rule.
// A literal label that cannot be normalized makes the whole pattern invalid.
func normalizeWildcardHost(host string) (string, error) {
	host = strings.ToLower(host)
	// A trailing DNS dot is dropped on the whole host (Normalize does the
	// same); label-level punycoding happens per label below.
	host = strings.TrimSuffix(host, ".")
	labels := strings.Split(host, ".")
	for i, l := range labels {
		if strings.ContainsAny(l, globMetacharacters) {
			continue // wildcard label — leave for the matcher
		}
		if l == "" {
			return "", fmt.Errorf("empty label in host %q", host)
		}
		nl, err := normalizeHostname(l)
		if err != nil {
			return "", err
		}
		labels[i] = nl
	}
	return strings.Join(labels, "."), nil
}

// joinPatternHostPort reassembles a pattern authority, restoring IPv6 brackets
// as glob-escaped literals. Bracketed IPv6 hosts contain ':' but must not act
// as character classes in the compiled glob, so they are emitted as "\[host\]".
// A wildcard host keeps its brackets (if any) untouched — the metacharacters
// stay live for the matcher.
func joinPatternHostPort(host, port string) string {
	if strings.Contains(host, ":") && !strings.ContainsAny(host, globMetacharacters) {
		host = `\[` + host + `\]`
	}
	if port != "" {
		return host + ":" + port
	}
	return host
}

// hasURLAuthority reports whether pattern begins with a scheme and a
// non-empty authority (e.g. "https://host/..."). Normalized targets always do,
// so anything less can never match.
func hasURLAuthority(pattern string) bool {
	i := strings.Index(pattern, "://")
	if i <= 0 {
		return false
	}
	rest := pattern[i+3:]
	if rest == "" {
		return false
	}
	j := strings.IndexAny(rest, "/?#")
	return j != 0 // authority runs to the first separator; zero-length is empty
}

// hasWildcardIDNLabel reports whether the pattern's host contains a label that
// both holds a glob metacharacter and non-ASCII bytes. Per-label punycoding
// (normalizeWildcardHost) deliberately skips such labels, leaving them unable
// to match any normalized target — a dead rule the loader must reject.
func hasWildcardIDNLabel(pattern string) bool {
	i := strings.Index(pattern, "://")
	if i < 0 {
		return false
	}
	rest := pattern[i+3:]
	auth := rest
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		auth = rest[:j]
	}
	host, _, err := splitPatternHostPort(auth)
	if err != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if strings.ContainsAny(label, globMetacharacters) && !isASCII(label) {
			return true
		}
	}
	return false
}

// isASCII reports whether s consists entirely of ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// splitPatternHostPort splits an authority string into host and port, handling
// IPv6 brackets (e.g. "[::1]:8080"). Unlike net.SplitHostPort it does not error
// on missing ports — a bare host returns port "".
//
// Brackets are only treated as an IPv6 literal when the content actually parses
// as an IP address. A glob character class such as "[ab]x.example.com" is a
// valid doublestar pattern, and taking its "]" as the end of an IPv6 authority
// would silently drop the rest of the host and widen the rule ("[ab]x..." would
// compile as host "ab"). Such inputs are rejected instead: IPv6 globs are not
// expressible, so they can only be typos or dead rules.
func splitPatternHostPort(auth string) (host, port string, err error) {
	if strings.HasPrefix(auth, "[") {
		idx := strings.IndexByte(auth, ']')
		if idx < 0 {
			return "", "", fmt.Errorf("unterminated bracketed host in %q", auth)
		}
		inner := auth[1:idx]
		if _, perr := netip.ParseAddr(inner); perr != nil {
			return "", "", fmt.Errorf("bracketed host %q is not a valid IP literal", auth)
		}
		if len(auth) > idx+1 {
			if auth[idx+1] != ':' {
				return "", "", fmt.Errorf("unexpected characters after IPv6 literal in %q", auth)
			}
			port = auth[idx+2:]
		}
		return inner, port, nil
	}
	if idx := strings.LastIndexByte(auth, ':'); idx >= 0 {
		return auth[:idx], auth[idx+1:], nil
	}
	return auth, "", nil
}
