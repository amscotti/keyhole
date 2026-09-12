package rules

import "github.com/amscotti/keyhole/internal/config"

// AllowsTransform reports whether r permits the named transform. The semantics
// match the policy matrix:
//   - Transforms omitted (nil): the rule does not constrain transforms, so every
//     transform is permitted.
//   - Transforms set but empty: only the identity "raw" transform is permitted.
//   - Otherwise: exactly the transforms named in the list.
//
// The server consults this against the matched rule after
// Evaluate succeeds; the rules engine itself only decides allow/deny.
func AllowsTransform(r config.Rule, transform string) bool {
	if r.Transforms == nil {
		return true
	}
	if len(r.Transforms) == 0 {
		return transform == "raw"
	}
	for _, t := range r.Transforms {
		if t == transform {
			return true
		}
	}
	return false
}
