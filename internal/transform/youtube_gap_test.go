package transform

import (
	"context"
	"errors"
	"testing"
	"time"

	youtube "github.com/kkdai/youtube/v2"
)

func captionTracks(langs ...string) []youtube.CaptionTrack {
	tracks := make([]youtube.CaptionTrack, 0, len(langs))
	for _, l := range langs {
		tracks = append(tracks, youtube.CaptionTrack{LanguageCode: l})
	}
	return tracks
}

func TestFindCaptionTrackExactMatch(t *testing.T) {
	t.Parallel()
	tr, ok := findCaptionTrack(captionTracks("en", "de"), "de")
	if !ok {
		t.Fatal("expected exact match for de")
	}
	if tr.LanguageCode != "de" {
		t.Fatalf("got %q, want %q", tr.LanguageCode, "de")
	}
}

func TestFindCaptionTrackPrefixFallback(t *testing.T) {
	t.Parallel()
	// Request "en" matches regional track "en-US".
	if tr, ok := findCaptionTrack(captionTracks("en-US", "de"), "en"); !ok || tr.LanguageCode != "en-US" {
		t.Fatalf("prefix fallback failed: %+v %v", tr, ok)
	}
	// Request "en-US" matches bare track "en".
	if tr, ok := findCaptionTrack(captionTracks("en", "de"), "en-US"); !ok || tr.LanguageCode != "en" {
		t.Fatalf("reverse prefix fallback failed: %+v %v", tr, ok)
	}
}

func TestFindCaptionTrackNoMatch(t *testing.T) {
	t.Parallel()
	if _, ok := findCaptionTrack(captionTracks("en", "de"), "fr"); ok {
		t.Fatal("expected no match for fr")
	}
	if _, ok := findCaptionTrack(nil, "en"); ok {
		t.Fatal("expected no match on empty track list")
	}
	// "english" must not prefix-match "en" (boundary requires '-' separator).
	if _, ok := findCaptionTrack(captionTracks("en"), "english"); ok {
		t.Fatal("expected no match: english is not a BCP-47 extension of en")
	}
}

func TestToVideoInfoMapsFields(t *testing.T) {
	t.Parallel()
	v := &youtube.Video{
		ID:          "dQw4w9WgXcQ",
		Title:       "title",
		Description: "desc",
		Author:      "author",
		ChannelID:   "channel",
		Duration:    42 * time.Second,
		Views:       1000,
		PublishDate: time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC),
	}
	got := toVideoInfo(v)
	if got.ID != v.ID || got.Title != v.Title || got.Description != v.Description ||
		got.Author != v.Author || got.ChannelID != v.ChannelID ||
		got.Duration != v.Duration || got.Views != v.Views || !got.Published.Equal(v.PublishDate) {
		t.Fatalf("toVideoInfo dropped fields: %+v", got)
	}
}

func TestClassifyYouTubeLibError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		code string
	}{
		{"login required", youtube.ErrLoginRequired, CodeUnsupported},
		{"private", youtube.ErrVideoPrivate, CodeUnsupported},
		{"not playable in embed", youtube.ErrNotPlayableInEmbed, CodeUnsupported},
		{"playability status", &youtube.ErrPlayabiltyStatus{Status: "ERROR", Reason: "gone"}, CodeUnsupported},
		{"deadline", context.DeadlineExceeded, CodeTimeout},
		{"canceled", context.Canceled, CodeUnreachable},
		{"generic", errors.New("boom"), CodeUnreachable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ce, ok := classifyYouTubeLibError(tc.err).(*ClientError)
			if !ok {
				t.Fatalf("expected *ClientError, got %T", classifyYouTubeLibError(tc.err))
			}
			if ce.Code != tc.code {
				t.Fatalf("got code %q, want %q (err: %v)", ce.Code, tc.code, ce)
			}
		})
	}
}

func TestClientErrorString(t *testing.T) {
	t.Parallel()
	e := &ClientError{Code: CodeTimeout, Message: "slow"}
	if got := e.Error(); got != CodeTimeout+": slow" {
		t.Fatalf("got %q", got)
	}
}
