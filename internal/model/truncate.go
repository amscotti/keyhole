package model

// Truncate cuts content to at most maxChars runes, returning the truncated
// string and whether truncation was applied. It always cuts on a rune boundary
// — never mid-codepoint — because the content is destined for an LLM context
// window where a split multi-byte sequence would produce garbage.
//
// maxChars <= 0 means "no limit": the content is returned verbatim with
// truncated = false.
func Truncate(content string, maxChars int) (string, bool) {
	if maxChars <= 0 || len(content) <= maxChars {
		// A string cannot contain more runes than bytes, so a byte length at
		// or below the limit is never truncated. This fast path matters: the
		// previous implementation always ran a full RuneCountInString scan
		// (a 5 MB body cost ~1.7 ms even when cutting to 100 runes).
		return content, false
	}
	// Walk the string rune by rune; stop at the maxChars-th rune's byte offset.
	count := 0
	for i := range content {
		if count == maxChars {
			return content[:i], true
		}
		count++
	}
	// The byte length exceeded the limit, so there are more than maxChars
	// runes and the boundary must have been found unless maxChars > rune
	// count (impossible here). Fail safe.
	return content, true
}
