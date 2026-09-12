package model_test

import (
	"testing"

	"github.com/amscotti/keyhole/internal/model"
)

func TestTruncateNoLimit(t *testing.T) {
	t.Parallel()
	got, truncated := model.Truncate("hello world", 0)
	if got != "hello world" || truncated {
		t.Fatalf("Truncate(%q, 0) = %q, %v; want %q, false", "hello world", got, truncated, "hello world")
	}
}

func TestTruncateNegativeIsNoLimit(t *testing.T) {
	t.Parallel()
	got, truncated := model.Truncate("abc", -1)
	if got != "abc" || truncated {
		t.Fatalf("Truncate(%q, -1) = %q, %v; want %q, false", "abc", got, truncated, "abc")
	}
}

func TestTruncateShortEnough(t *testing.T) {
	t.Parallel()
	got, truncated := model.Truncate("abc", 5)
	if got != "abc" || truncated {
		t.Fatalf("Truncate(%q, 5) = %q, %v; want %q, false", "abc", got, truncated, "abc")
	}
}

func TestTruncateExactLength(t *testing.T) {
	t.Parallel()
	got, truncated := model.Truncate("abc", 3)
	if got != "abc" || truncated {
		t.Fatalf("Truncate(%q, 3) = %q, %v; want %q, false", "abc", got, truncated, "abc")
	}
}

func TestTruncateCutsAtRuneBoundary(t *testing.T) {
	t.Parallel()
	// "héllo" is 5 runes but 6 bytes (é is 2 bytes). Cutting at 2 runes must
	// produce "hé" (3 bytes), not a truncated codepoint.
	got, truncated := model.Truncate("héllo", 2)
	want := "hé"
	if got != want {
		t.Fatalf("Truncate(%q, 2) = %q, want %q", "héllo", got, want)
	}
	if !truncated {
		t.Fatal("expected truncated = true")
	}
}

func TestTruncateMultibyteContent(t *testing.T) {
	t.Parallel()
	// Each emoji is 4 bytes. 5 emojis = 20 bytes. Cutting at 3 runes should
	// give 3 emojis (12 bytes), not 12 bytes of possibly-split sequences.
	input := "😀😁😂😃😄"
	got, truncated := model.Truncate(input, 3)
	want := "😀😁😂"
	if got != want {
		t.Fatalf("Truncate(emojis, 3) = %q, want %q", got, want)
	}
	if !truncated {
		t.Fatal("expected truncated = true")
	}
}

func TestTruncateEmptyString(t *testing.T) {
	t.Parallel()
	got, truncated := model.Truncate("", 10)
	if got != "" || truncated {
		t.Fatalf(`Truncate("", 10) = %q, %v; want "", false`, got, truncated)
	}
}

func TestHTTPStatusMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		code     string
		wantStat int
	}{
		{model.CodeDenied, 403},
		{model.CodeBadRequest, 400},
		{model.CodeUnsupported, 400},
		{model.CodeTooLarge, 413},
		{model.CodeTimeout, 504},
		{model.CodeUnreachable, 502},
		{model.CodeTransformFailed, 500},
		{model.CodeUnauthorized, 401},
		{model.CodeInternal, 500},
		{model.CodeRateLimited, 429},
		{"unknown_code", 500},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			t.Parallel()
			if got := model.HTTPStatus(tc.code); got != tc.wantStat {
				t.Fatalf("HTTPStatus(%q) = %d, want %d", tc.code, got, tc.wantStat)
			}
		})
	}
}
