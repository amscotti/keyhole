package transform_test

import (
	"context"
	"sort"
	"testing"

	"github.com/amscotti/keyhole/internal/transform"
)

func TestRegistryNames(t *testing.T) {
	t.Parallel()
	r := transform.NewRegistry()
	names := r.Names()
	sort.Strings(names)
	want := []string{"article", "markdown", "raw"}
	if len(names) != len(want) {
		t.Fatalf("Names() = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("Names() = %v, want %v", names, want)
		}
	}
}

func TestErrorString(t *testing.T) {
	t.Parallel()
	err := &transform.Error{Code: transform.CodeUnsupported, Message: "nope"}
	if got := err.Error(); got != "unsupported: nope" {
		t.Fatalf("Error() = %q", got)
	}
}

func TestYouTubeNameAndApplyDelegate(t *testing.T) {
	t.Parallel()
	// Apply on a non-YouTube URL should surface unsupported without network.
	yt := transform.NewYouTube(nil, transform.YouTubeOptions{})
	if yt.Name() != "youtube" {
		t.Fatalf("Name = %q", yt.Name())
	}
	_, err := yt.Apply(nil, "text/html", "https://example.com/")
	if err == nil {
		t.Fatal("expected error for non-YouTube URL")
	}
	// ApplyDirect path is what the server uses; same rejection.
	_, err = yt.ApplyDirect(context.Background(), "https://example.com/")
	if err == nil {
		t.Fatal("expected ApplyDirect error for non-YouTube URL")
	}
}

func TestOfficeName(t *testing.T) {
	t.Parallel()
	o := transform.NewOffice(transform.OfficeOptions{})
	if o.Name() != "office" {
		t.Fatalf("Name = %q", o.Name())
	}
}
