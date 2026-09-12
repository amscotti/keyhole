//go:build integration

// Integration test for the YouTube transform. These tests make live network
// calls to YouTube and are excluded from the default gate (`mise run test`).
// Run them with `mise run test-integration` (which sets -tags=integration).
package transform_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/amscotti/keyhole/internal/transform"
)

// newIntegrationClient builds a real YouTube client with a generous timeout.
func newIntegrationClient() transform.YouTubeClient {
	return transform.NewRealYouTubeClient(&http.Client{Timeout: 60 * time.Second})
}

// integrationVideos is an ordered list of known-stable, long-public videos that
// carry English caption tracks. The integration tests try each in turn and use
// the first that is currently fetchable, so a single video being removed or
// region-blocked does not turn the Phase 5 Definition-of-Done contract red
// (finding B1: the previously hardcoded BaW_jenozKc is gone from this
// environment).
//
// Ordered by expected durability; the first available one wins.
var integrationVideos = []string{
	"https://www.youtube.com/watch?v=dQw4w9WgXcQ", // Rick Astley – Never Gonna Give You Up
	"https://www.youtube.com/watch?v=kJQP7kiw5Fk", // Luis Fonsi – Despacito
	"https://www.youtube.com/watch?v=aircAruvnKk", // 3Blue1Brown – But what is a neural network?
	"https://www.youtube.com/watch?v=fJ9rUzIMcZQ", // Queen – Bohemian Rhapsody
}

// applyFirstAvailable runs tr.ApplyDirect against each candidate URL in order
// and returns the first successful result along with the URL that produced it.
// It fails the test only when no candidate is reachable, so an availability
// failure surfaces a clear message rather than masking a real assertion
// failure. Each candidate is fetched at most once (no probe→test double fetch,
// which YouTube's innertube API rejects with HTTP 400 under rapid reuse).
func applyFirstAvailable(t *testing.T, tr *transform.YouTube, timeout time.Duration) (string, *transform.Result) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var lastErr error
	for _, u := range integrationVideos {
		res, err := tr.ApplyDirect(ctx, u)
		if err == nil {
			return u, res
		}
		lastErr = err
	}
	t.Fatalf("no integration video available among %d candidates; last error: %v",
		len(integrationVideos), lastErr)
	return "", nil
}

// TestIntegrationYouTubeMetadataAndTranscript fetches a known public video and
// asserts the envelope carries non-empty metadata and a genuine transcript for
// the configured language. This is the Phase 5 Definition-of-Done integration
// contract. The assertions are deliberately non-vacuous (finding R3): the
// content must not be the no-transcript placeholder, must span multiple
// segments, and the configured "en" must be a genuinely offered track.
func TestIntegrationYouTubeMetadataAndTranscript(t *testing.T) {
	client := newIntegrationClient()
	tr := transform.NewYouTube(client, transform.YouTubeOptions{
		TranscriptLanguage: "en",
		IncludeTimestamps:  false,
		MaxChars:           50000,
	})

	videoURL, res := applyFirstAvailable(t, tr, 90*time.Second)

	// Metadata: title and author, plus an identifying field beyond them.
	if res.Metadata["title"] == "" {
		t.Error("expected non-empty title in metadata")
	}
	if res.Metadata["author"] == "" {
		t.Error("expected non-empty author in metadata")
	}
	if res.Metadata["video_id"] == "" {
		t.Error("expected non-empty video_id in metadata")
	}
	if res.Metadata["duration"] == "" && res.Metadata["views"] == "" && res.Metadata["upload_date"] == "" {
		t.Error("expected at least one of duration/views/upload_date in metadata beyond title and author")
	}

	// Transcript: must be a real transcript, never the no-caption placeholder.
	if res.Content == "" {
		t.Fatal("expected non-empty transcript content")
	}
	if res.Content == "(no transcript available for this video)" {
		t.Fatal("content is the no-transcript placeholder, not a real transcript")
	}
	if lineCount := len(splitLines(res.Content)); lineCount < 2 {
		t.Errorf("expected a multi-segment transcript, got %d line(s):\n%s", lineCount, res.Content)
	}

	// Language pinning: the configured transcript_language "en" must be among the
	// tracks the chosen video actually offers — otherwise the test would be green
	// via a silent fallback to another language. The client caches the player
	// response, so this is a cache hit, not an extra network round trip.
	if id, ok := transform.ExtractVideoID(videoURL); ok {
		if _, langs, err := client.GetVideo(context.Background(), id); err == nil && !hasEnglishTrack(langs) {
			t.Errorf("configured transcript_language \"en\" is not among available tracks %v for %s", langs, videoURL)
		}
	}
}

// hasEnglishTrack reports whether langs contains an English caption track
// ("en" or an "en-*" variant).
func hasEnglishTrack(langs []string) bool {
	for _, l := range langs {
		if l == "en" || strings.HasPrefix(l, "en-") {
			return true
		}
	}
	return false
}

// TestIntegrationYouTubeTimestamps verifies that include_timestamps prefixes
// lines with a [mm:ss] marker on a real video.
func TestIntegrationYouTubeTimestamps(t *testing.T) {
	tr := transform.NewYouTube(newIntegrationClient(), transform.YouTubeOptions{
		TranscriptLanguage: "en",
		IncludeTimestamps:  true,
	})

	_, res := applyFirstAvailable(t, tr, 90*time.Second)

	if res.Content == "" {
		t.Fatal("expected non-empty transcript")
	}
	// With timestamps on, at least one line should carry a [..:..] prefix.
	hasTimestamp := false
	for _, line := range splitLines(res.Content) {
		if len(line) > 0 && line[0] == '[' {
			hasTimestamp = true
			break
		}
	}
	if !hasTimestamp {
		t.Errorf("expected at least one timestamped line, got:\n%s", res.Content)
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	lines = append(lines, s[start:])
	return lines
}
