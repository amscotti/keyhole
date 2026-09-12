package transform_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/amscotti/keyhole/internal/transform"
)

// fakeYouTubeClient is an in-memory stand-in for the real network client.
type fakeYouTubeClient struct {
	video     transform.VideoInfo
	languages []string
	videoErr  error

	// transcripts maps language code -> lines. GetTranscript for a lang not in
	// this map returns transform.ErrTrackNotFound.
	transcripts map[string][]transform.CaptionLine
	// transcriptErr, when set, is returned for every GetTranscript call,
	// overriding the map lookup.
	transcriptErr error

	// transcriptCalls records the (videoID, lang) pairs passed to GetTranscript.
	transcriptCalls []transcriptCall
}

type transcriptCall struct {
	videoID string
	lang    string
}

func (f *fakeYouTubeClient) GetVideo(_ context.Context, videoID string) (transform.VideoInfo, []string, error) {
	if f.videoErr != nil {
		return transform.VideoInfo{}, nil, f.videoErr
	}
	f.video.ID = videoID
	return f.video, f.languages, nil
}

func (f *fakeYouTubeClient) GetTranscript(_ context.Context, videoID, lang string) ([]transform.CaptionLine, error) {
	f.transcriptCalls = append(f.transcriptCalls, transcriptCall{videoID, lang})
	if f.transcriptErr != nil {
		return nil, f.transcriptErr
	}
	if lines, ok := f.transcripts[lang]; ok {
		return lines, nil
	}
	return nil, transform.ErrTrackNotFound
}

func sampleVideo() transform.VideoInfo {
	return transform.VideoInfo{
		Title:       "Sample Talk",
		Author:      "Sample Channel",
		ChannelID:   "UC_sample",
		Description: "A description.",
		Duration:    3*time.Minute + 45*time.Second,
		Views:       12345,
		Published:   time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	}
}

const sampleID = "dQw4w9WgXcQ"

func sampleLines() []transform.CaptionLine {
	return []transform.CaptionLine{
		{Text: "Hello world", StartMs: 0},
		{Text: "Second line", StartMs: 65000},
		{Text: "Hour mark", StartMs: 3600000},
	}
}

func TestYouTubeRejectsNonYouTubeURL(t *testing.T) {
	t.Parallel()
	tr := transform.NewYouTube(&fakeYouTubeClient{}, transform.YouTubeOptions{})
	_, err := tr.ApplyDirect(context.Background(), "https://example.com/watch?v=abc")
	if err == nil {
		t.Fatal("expected error for non-YouTube URL")
	}
	var te *transform.Error
	if !errors.As(err, &te) || te.Code != transform.CodeUnsupported {
		t.Errorf("expected unsupported error, got %v", err)
	}
}

func TestYouTubeRejectsNonVideoYouTubeURL(t *testing.T) {
	t.Parallel()
	tr := transform.NewYouTube(&fakeYouTubeClient{}, transform.YouTubeOptions{})
	_, err := tr.ApplyDirect(context.Background(), "https://www.youtube.com/feed/trending")
	if err == nil {
		t.Fatal("expected error for non-video YouTube URL")
	}
	var te *transform.Error
	if !errors.As(err, &te) || te.Code != transform.CodeUnsupported {
		t.Errorf("expected unsupported error, got %v", err)
	}
}

func TestYouTubeUnavailableVideoTypedError(t *testing.T) {
	t.Parallel()
	fc := &fakeYouTubeClient{
		videoErr: &transform.ClientError{Code: transform.CodeUnsupported, Message: "video is age-restricted or requires login"},
	}
	tr := transform.NewYouTube(fc, transform.YouTubeOptions{})
	_, err := tr.ApplyDirect(context.Background(), "https://www.youtube.com/watch?v="+sampleID)
	if err == nil {
		t.Fatal("expected error")
	}
	var te *transform.Error
	if !errors.As(err, &te) {
		t.Fatalf("expected *transform.Error, got %T", err)
	}
	if te.Code != transform.CodeUnsupported {
		t.Errorf("code = %q, want %q", te.Code, transform.CodeUnsupported)
	}
	if !strings.Contains(te.Message, "age-restricted") {
		t.Errorf("message should mention age-restricted, got %q", te.Message)
	}
}

func TestYouTubeLanguageFallback(t *testing.T) {
	t.Parallel()
	fc := &fakeYouTubeClient{
		video:     sampleVideo(),
		languages: []string{"es", "fr"}, // preferred "en" is NOT available
		transcripts: map[string][]transform.CaptionLine{
			"es": {{Text: "Hola mundo", StartMs: 0}},
		},
	}
	tr := transform.NewYouTube(fc, transform.YouTubeOptions{TranscriptLanguage: "en"})
	res, err := tr.ApplyDirect(context.Background(), "https://www.youtube.com/watch?v="+sampleID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res.Content, "Hola mundo") {
		t.Errorf("expected fallback Spanish transcript, got %q", res.Content)
	}
	// pickLanguage selects a real track upfront, so only one fetch happens —
	// against the fallback language, not the (unavailable) preferred one.
	if len(fc.transcriptCalls) != 1 {
		t.Fatalf("expected 1 transcript call, got %d", len(fc.transcriptCalls))
	}
	if fc.transcriptCalls[0].lang != "es" {
		t.Errorf("call lang = %q, want fallback es", fc.transcriptCalls[0].lang)
	}
}

func TestPickLanguage(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		preferred string
		available []string
		want      string
	}{
		{"exact match", "en", []string{"en", "es"}, "en"},
		{"prefix match", "en", []string{"en-US", "es"}, "en-US"},
		{"fallback to first", "en", []string{"es", "fr"}, "es"}, // sorted → es
		{"empty preferred", "", []string{"es", "en"}, "en"},     // sorted → en
		{"no tracks", "en", nil, ""},
		{"no match no fallback when tracks exist", "de", []string{"es"}, "es"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := transform.PickLanguage(tc.preferred, tc.available)
			if got != tc.want {
				t.Errorf("PickLanguage(%q, %v) = %q, want %q", tc.preferred, tc.available, got, tc.want)
			}
		})
	}
}

func TestYouTubeTimestampsOn(t *testing.T) {
	t.Parallel()
	fc := &fakeYouTubeClient{
		video:     sampleVideo(),
		languages: []string{"en"},
		transcripts: map[string][]transform.CaptionLine{
			"en": sampleLines(),
		},
	}
	tr := transform.NewYouTube(fc, transform.YouTubeOptions{IncludeTimestamps: true})
	res, err := tr.ApplyDirect(context.Background(), "https://youtu.be/"+sampleID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res.Content, "[00:00] Hello world") {
		t.Errorf("expected [00:00] prefix, got %q", res.Content)
	}
	if !strings.Contains(res.Content, "[01:05] Second line") {
		t.Errorf("expected [01:05] prefix, got %q", res.Content)
	}
	if !strings.Contains(res.Content, "[1:00:00] Hour mark") {
		t.Errorf("expected [1:00:00] prefix, got %q", res.Content)
	}
}

func TestYouTubeTimestampsOff(t *testing.T) {
	t.Parallel()
	fc := &fakeYouTubeClient{
		video:     sampleVideo(),
		languages: []string{"en"},
		transcripts: map[string][]transform.CaptionLine{
			"en": sampleLines(),
		},
	}
	tr := transform.NewYouTube(fc, transform.YouTubeOptions{IncludeTimestamps: false})
	res, err := tr.ApplyDirect(context.Background(), "https://youtu.be/"+sampleID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(res.Content, "[") {
		t.Errorf("expected no timestamps, got %q", res.Content)
	}
	if !strings.Contains(res.Content, "Hello world") {
		t.Errorf("expected transcript text, got %q", res.Content)
	}
}

func TestYouTubeTruncationOverMaxChars(t *testing.T) {
	t.Parallel()
	long := []transform.CaptionLine{{Text: strings.Repeat("x", 200), StartMs: 0}}
	fc := &fakeYouTubeClient{
		video:       sampleVideo(),
		languages:   []string{"en"},
		transcripts: map[string][]transform.CaptionLine{"en": long},
	}
	tr := transform.NewYouTube(fc, transform.YouTubeOptions{MaxChars: 50})
	res, err := tr.ApplyDirect(context.Background(), "https://www.youtube.com/watch?v="+sampleID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Truncated {
		t.Error("expected Truncated=true")
	}
	if len([]rune(res.Content)) > 50 {
		t.Errorf("content should be <= 50 runes, got %d", len([]rune(res.Content)))
	}
}

// TestYouTubeMetadataEmitsZeroValues verifies that views and duration are
// emitted even when zero, rather than silently dropped. A brand-new video with
// 0 views should still report "0" so the field is consistently present (finding
// M1).
func TestYouTubeMetadataEmitsZeroValues(t *testing.T) {
	t.Parallel()
	fc := &fakeYouTubeClient{
		video: transform.VideoInfo{
			Title:    "Zero Stats",
			Author:   "Nobody",
			Duration: 0,
			Views:    0,
		},
		languages:   []string{"en"},
		transcripts: map[string][]transform.CaptionLine{"en": sampleLines()},
	}
	tr := transform.NewYouTube(fc, transform.YouTubeOptions{})
	res, err := tr.ApplyDirect(context.Background(), "https://www.youtube.com/watch?v="+sampleID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v, ok := res.Metadata["views"]; !ok || v != "0" {
		t.Errorf("views = %q (ok=%v), want \"0\"", v, ok)
	}
	if d, ok := res.Metadata["duration"]; !ok || d != "0:00" {
		t.Errorf("duration = %q (ok=%v), want \"0:00\"", d, ok)
	}
}

func TestYouTubeMetadataPopulated(t *testing.T) {
	t.Parallel()
	fc := &fakeYouTubeClient{
		video:       sampleVideo(),
		languages:   []string{"en"},
		transcripts: map[string][]transform.CaptionLine{"en": sampleLines()},
	}
	tr := transform.NewYouTube(fc, transform.YouTubeOptions{})
	res, err := tr.ApplyDirect(context.Background(), "https://www.youtube.com/watch?v="+sampleID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Metadata["title"] != "Sample Talk" {
		t.Errorf("title = %q", res.Metadata["title"])
	}
	if res.Metadata["author"] != "Sample Channel" {
		t.Errorf("author = %q", res.Metadata["author"])
	}
	if res.Metadata["duration"] != "3:45" {
		t.Errorf("duration = %q, want 3:45", res.Metadata["duration"])
	}
	if res.Metadata["views"] != "12345" {
		t.Errorf("views = %q", res.Metadata["views"])
	}
	if res.Metadata["upload_date"] != "2026-01-02" {
		t.Errorf("upload_date = %q", res.Metadata["upload_date"])
	}
	if res.Metadata["video_id"] != sampleID {
		t.Errorf("video_id = %q", res.Metadata["video_id"])
	}
}

func TestYouTubeNoCaptionTracks(t *testing.T) {
	t.Parallel()
	fc := &fakeYouTubeClient{
		video:     sampleVideo(),
		languages: nil, // no caption tracks
	}
	tr := transform.NewYouTube(fc, transform.YouTubeOptions{TranscriptLanguage: "en"})
	res, err := tr.ApplyDirect(context.Background(), "https://www.youtube.com/watch?v="+sampleID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res.Content, "no transcript available") {
		t.Errorf("expected no-transcript note, got %q", res.Content)
	}
	if res.Metadata["title"] != "Sample Talk" {
		t.Errorf("metadata should still be populated even without transcript, title = %q", res.Metadata["title"])
	}
}

func TestYouTubeNetworkErrorTyped(t *testing.T) {
	t.Parallel()
	fc := &fakeYouTubeClient{
		videoErr: &transform.ClientError{Code: transform.CodeUnreachable, Message: "dial tcp: unreachable"},
	}
	tr := transform.NewYouTube(fc, transform.YouTubeOptions{})
	_, err := tr.ApplyDirect(context.Background(), "https://www.youtube.com/watch?v="+sampleID)
	if err == nil {
		t.Fatal("expected error")
	}
	var te *transform.Error
	if !errors.As(err, &te) || te.Code != transform.CodeUnreachable {
		t.Errorf("expected unreachable, got %v", err)
	}
}

func TestMarkdownRejectsYouTubeURL(t *testing.T) {
	t.Parallel()
	tr := transform.Markdown{}
	_, err := tr.Apply([]byte("<html></html>"), "text/html", "https://www.youtube.com/watch?v="+sampleID)
	if err == nil {
		t.Fatal("expected error for YouTube URL with markdown")
	}
	var te *transform.Error
	if !errors.As(err, &te) || te.Code != transform.CodeUnsupported {
		t.Errorf("expected unsupported, got %v", err)
	}
	if !strings.Contains(te.Message, "youtube") {
		t.Errorf("message should point at youtube transform, got %q", te.Message)
	}
}

// TestMarkdownAllowsNonVideoYouTubePages pins the other half of the gate:
// channel/feed/about pages are ordinary HTML and must not be refused with a
// pointer to a transform that also rejects them.
func TestMarkdownAllowsNonVideoYouTubePages(t *testing.T) {
	t.Parallel()
	for _, tr := range []transform.Transform{transform.Markdown{}, transform.Article{}} {
		if err := tr.(transform.URLValidator).ValidateURL("https://www.youtube.com/feed/subscriptions"); err != nil {
			t.Errorf("%s refused a non-video YouTube page: %v", tr.Name(), err)
		}
	}
}

func TestArticleRejectsYouTubeURL(t *testing.T) {
	t.Parallel()
	tr := transform.Article{}
	_, err := tr.Apply([]byte("<html></html>"), "text/html", "https://www.youtube.com/shorts/"+sampleID)
	if err == nil {
		t.Fatal("expected error for YouTube URL with article")
	}
	var te *transform.Error
	if !errors.As(err, &te) || te.Code != transform.CodeUnsupported {
		t.Errorf("expected unsupported, got %v", err)
	}
}

func TestCanonicalFetchURL(t *testing.T) {
	t.Parallel()
	tr := transform.NewYouTube(&fakeYouTubeClient{}, transform.YouTubeOptions{})
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"watch", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "https://www.youtube.com/watch?v=dQw4w9WgXcQ"},
		{"short link", "https://youtu.be/dQw4w9WgXcQ", "https://www.youtube.com/watch?v=dQw4w9WgXcQ"},
		{"shorts", "https://www.youtube.com/shorts/dQw4w9WgXcQ", "https://www.youtube.com/watch?v=dQw4w9WgXcQ"},
		{"live", "https://www.youtube.com/live/dQw4w9WgXcQ", "https://www.youtube.com/watch?v=dQw4w9WgXcQ"},
		{"embed", "https://www.youtube.com/embed/dQw4w9WgXcQ", "https://www.youtube.com/watch?v=dQw4w9WgXcQ"},
		{"bare id (not a URL, no canonicalization)", "dQw4w9WgXcQ", ""},
		{"non-youtube", "https://example.com/watch?v=dQw4w9WgXcQ", ""},
		{"not a video", "https://www.youtube.com/feed/trending", ""},
		{"garbage", "not a url", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := transform.CanonicalFetchURL(tc.in); got != tc.want {
				t.Errorf("CanonicalFetchURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
			// FetchTarget must agree with CanonicalFetchURL.
			if got := tr.FetchTarget(tc.in); got != tc.want {
				t.Errorf("FetchTarget(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestYouTubeURLDetection(t *testing.T) {
	t.Parallel()
	cases := []struct {
		url  string
		want bool
	}{
		{"https://www.youtube.com/watch?v=dQw4w9WgXcQ", true},
		{"https://youtube.com/watch?v=dQw4w9WgXcQ", true},
		{"https://m.youtube.com/watch?v=dQw4w9WgXcQ", true},
		{"https://music.youtube.com/watch?v=dQw4w9WgXcQ", true},
		{"https://youtu.be/dQw4w9WgXcQ", true},
		{"https://www.youtube.com/shorts/dQw4w9WgXcQ", true},
		{"https://www.youtube.com/live/dQw4w9WgXcQ", true},
		{"https://www.youtube.com/embed/dQw4w9WgXcQ", true},
		{"https://example.com/watch?v=dQw4w9WgXcQ", false},
		{"https://notyoutube.com/watch?v=dQw4w9WgXcQ", false},
	}
	for _, tc := range cases {
		id, ok := transform.ExtractVideoID(tc.url) // exported for testing
		gotYT := transform.IsYouTubeURL(tc.url)
		if gotYT != tc.want {
			t.Errorf("IsYouTubeURL(%q) = %v, want %v", tc.url, gotYT, tc.want)
		}
		if tc.want && (!ok || id != "dQw4w9WgXcQ") {
			t.Errorf("ExtractVideoID(%q) = (%q, %v), want (dQw4w9WgXcQ, true)", tc.url, id, ok)
		}
	}
}

// TestYouTubeBrokenTrackDegradesToMetadata pins the degradation contract: a
// single broken caption track (oversized body, unreachable URL, timeout) must
// not discard the already-fetched metadata — the result is metadata plus an
// honest "transcript unavailable" note, mirroring the no-tracks case.
func TestYouTubeBrokenTrackDegradesToMetadata(t *testing.T) {
	t.Parallel()
	for _, code := range []string{transform.CodeTooLarge, transform.CodeUnreachable, transform.CodeTimeout} {
		fc := &fakeYouTubeClient{
			video:         sampleVideo(),
			languages:     []string{"en"},
			transcriptErr: &transform.ClientError{Code: code, Message: "caption fetch failed"},
		}
		tr := transform.NewYouTube(fc, transform.YouTubeOptions{TranscriptLanguage: "en"})
		res, err := tr.ApplyDirect(context.Background(), "https://www.youtube.com/watch?v="+sampleID)
		if err != nil {
			t.Fatalf("code %s: expected degradation, got error %v", code, err)
		}
		if !strings.Contains(res.Content, "transcript unavailable") {
			t.Fatalf("code %s: content should carry the unavailable note, got %q", code, res.Content)
		}
		if res.Metadata["title"] != sampleVideo().Title {
			t.Fatalf("code %s: metadata must survive the track failure, got %+v", code, res.Metadata)
		}
	}
}

// TestYouTubeDeniedTrackStillErrors pins the other half of the contract: a
// caption-host allowlist denial is a policy/security signal, not a transient
// failure — it must surface as an error, not silently degrade.
func TestYouTubeDeniedTrackStillErrors(t *testing.T) {
	t.Parallel()
	fc := &fakeYouTubeClient{
		video:         sampleVideo(),
		languages:     []string{"en"},
		transcriptErr: &transform.ClientError{Code: transform.CodeDenied, Message: "caption host not allowed"},
	}
	tr := transform.NewYouTube(fc, transform.YouTubeOptions{TranscriptLanguage: "en"})
	_, err := tr.ApplyDirect(context.Background(), "https://www.youtube.com/watch?v="+sampleID)
	if err == nil {
		t.Fatal("a denied caption track must surface as an error, not degrade")
	}
	var te *transform.Error
	if !errors.As(err, &te) || te.Code != transform.CodeDenied {
		t.Fatalf("expected denied error, got %v", err)
	}
}

// TestExtractVideoIDRejectsNonYouTubeHost pins the exported-helper contract:
// the bare-11-char-ID fall-through applies only to YouTube hosts (or a bare ID
// string), never to https://example.com/dQw4w9WgXcQ.
func TestExtractVideoIDRejectsNonYouTubeHost(t *testing.T) {
	t.Parallel()
	if id, ok := transform.ExtractVideoID("https://example.com/dQw4w9WgXcQ"); ok {
		t.Fatalf("non-YouTube host returned (%q, true)", id)
	}
	// Sanity: the documented shapes still extract.
	for _, u := range []string{
		"https://www.youtube.com/watch?v=dQw4w9WgXcQ",
		"https://youtu.be/dQw4w9WgXcQ",
		"https://www.youtube.com/shorts/dQw4w9WgXcQ",
		"dQw4w9WgXcQ",
	} {
		if id, ok := transform.ExtractVideoID(u); !ok || id != "dQw4w9WgXcQ" {
			t.Errorf("ExtractVideoID(%q) = (%q, %v), want (dQw4w9WgXcQ, true)", u, id, ok)
		}
	}
}
