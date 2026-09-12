package transform

// YouTube transform.
//
// When a YouTube URL is fetched with transform "youtube", the service returns
// structured metadata plus the video transcript as plain text instead of
// scraping the watch-page HTML. Detection covers the common watch, short-link,
// shorts, and live URL shapes; anything else yields "unsupported".
//
// The data source is wrapped in a Client interface so the pure transform logic
// (URL detection, language fallback, transcript formatting, truncation, error
// classification) is fully unit-testable with a fake. The real client (backed by
// github.com/kkdai/youtube/v2) makes live network calls and is exercised only by
// the integration test suite (mise run test-integration).
//
// The transform implements DirectTransform: the server skips the generic HTTP
// fetch and lets the YouTube client fetch metadata/transcript directly. This
// avoids a wasteful double-fetch and sidesteps YouTube consent redirects that
// would otherwise be policy-rejected on the final URL.

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	youtube "github.com/kkdai/youtube/v2"

	"github.com/amscotti/keyhole/internal/egress"
	"github.com/amscotti/keyhole/internal/model"
)

// --- public options -------------------------------------------------------

// YouTubeOptions configures the YouTube transform. It mirrors [youtube] in the
// TOML config.
type YouTubeOptions struct {
	// TranscriptLanguage is the preferred caption-track language code (e.g.
	// "en"). When empty, or when no track matches it, the transform falls back
	// to any available track.
	TranscriptLanguage string
	// IncludeTimestamps prefixes each transcript line with [mm:ss].
	IncludeTimestamps bool
	// MaxChars caps the transcript content; 0 means no cap.
	MaxChars int
}

// --- data types -----------------------------------------------------------

// VideoInfo is the metadata extracted from a YouTube video, decoupled from the
// underlying library so the transform depends only on this package's types.
type VideoInfo struct {
	ID          string
	Title       string
	Description string
	Author      string
	ChannelID   string
	Duration    time.Duration
	Views       int
	Published   time.Time
}

// CaptionLine is one transcript segment.
type CaptionLine struct {
	Text    string
	StartMs int
}

// --- client interface -----------------------------------------------------

// YouTubeClient abstracts the YouTube data source. The real implementation
// (NewRealYouTubeClient) talks to YouTube over the network; tests inject a fake.
type YouTubeClient interface {
	// GetVideo returns the video metadata and the list of available caption-
	// track language codes (which may be empty when the video has no captions).
	GetVideo(ctx context.Context, videoID string) (VideoInfo, []string, error)
	// GetTranscript returns the transcript for the exact language code lang.
	// It must NOT perform language fallback itself — the transform picks the
	// language via PickLanguage before calling this.
	GetTranscript(ctx context.Context, videoID, lang string) ([]CaptionLine, error)
}

// ClientError is the typed error produced by YouTubeClient implementations. Its
// Code is a transform/model error code so the transform can pass it straight
// through to the response envelope.
type ClientError struct {
	Code    string
	Message string
}

func (e *ClientError) Error() string { return e.Code + ": " + e.Message }

// Sentinel errors used by the transcript fetch path.
var (
	// ErrNoTranscript means the video has no caption tracks at all.
	ErrNoTranscript = errors.New("no transcript available for this video")
	// ErrTrackNotFound means no caption track matches the requested language.
	ErrTrackNotFound = errors.New("no caption track for the requested language")
	// ErrPartialTranscript means some segments parsed before the timedtext
	// payload turned malformed; the returned lines are what could be read.
	ErrPartialTranscript = errors.New("partial transcript")
)

// --- the transform --------------------------------------------------------

// YouTube converts a YouTube URL into structured metadata + transcript text.
// It implements both Transform (for the registry) and DirectTransform (so the
// server uses the YouTube client instead of the generic fetcher).
type YouTube struct {
	client YouTubeClient
	opts   YouTubeOptions
}

// NewYouTube builds a YouTube transform backed by client.
func NewYouTube(client YouTubeClient, opts YouTubeOptions) *YouTube {
	if client == nil {
		client = noopYouTubeClient{}
	}
	return &YouTube{client: client, opts: opts}
}

// Name implements Transform.
func (YouTube) Name() string { return "youtube" }

// Apply implements Transform by delegating to ApplyDirect with a background
// context. In normal operation the server calls ApplyDirect directly (via the
// DirectTransform interface) so the request context is honored.
func (y *YouTube) Apply(_ []byte, _ string, sourceURL string) (*Result, error) {
	return y.apply(context.Background(), sourceURL)
}

// ApplyDirect implements DirectTransform.
func (y *YouTube) ApplyDirect(ctx context.Context, sourceURL string) (*Result, error) {
	return y.apply(ctx, sourceURL)
}

// FetchTarget implements FetchTargeter: the YouTube transform always dials the
// canonical watch endpoint, regardless of the URL shape the client supplied
// (youtu.be/, /shorts/, /live/). Returning the canonical target lets the server
// re-evaluate policy on the URL that is actually fetched and report it as
// final_url. It returns "" for non-YouTube / non-video URLs, in which case the
// server treats the source URL as the fetch target.
func (y *YouTube) FetchTarget(sourceURL string) string {
	return CanonicalFetchURL(sourceURL)
}

// CanonicalFetchURL returns the canonical https://www.youtube.com/watch?v=<id>
// URL for a YouTube video reference (watch, short-link, shorts, live, embed, or
// bare ID), or "" if sourceURL is not a recognizable YouTube video URL.
func CanonicalFetchURL(sourceURL string) string {
	if !IsYouTubeURL(sourceURL) {
		return ""
	}
	id, ok := ExtractVideoID(sourceURL)
	if !ok {
		return ""
	}
	return "https://www.youtube.com/watch?v=" + id
}

// apply is the shared core.
func (y *YouTube) apply(ctx context.Context, sourceURL string) (*Result, error) {
	if !IsYouTubeURL(sourceURL) {
		return nil, &Error{
			Code:    CodeUnsupported,
			Message: `youtube transform only applies to YouTube URLs; got ` + sourceURL,
		}
	}
	videoID, ok := ExtractVideoID(sourceURL)
	if !ok {
		return nil, &Error{
			Code:    CodeUnsupported,
			Message: `not a YouTube video URL (expected /watch?v=, youtu.be/, /shorts/, or /live/)`,
		}
	}

	info, langs, err := y.client.GetVideo(ctx, videoID)
	if err != nil {
		return nil, classifyClientError(err)
	}

	// Pick the best caption language: the configured preference, falling back to
	// any available track. When there are no tracks at all we still return the
	// metadata with a note instead of erroring — the metadata is useful on its
	// own.
	lang := PickLanguage(y.opts.TranscriptLanguage, langs)
	var lines []CaptionLine
	captionNote := ""
	partialNote := ""
	if lang == "" {
		captionNote = "(no transcript available for this video)"
	} else {
		lines, err = y.client.GetTranscript(ctx, videoID, lang)
		if err != nil {
			// A missing track for the picked language should not happen (we
			// picked from the reported list), but treat it gracefully.
			switch {
			case errors.Is(err, ErrTrackNotFound), errors.Is(err, ErrNoTranscript):
				captionNote = "(no transcript available for this video)"
			case errors.Is(err, ErrPartialTranscript):
				// Some segments parsed before the payload went bad: keep them
				// and say the transcript is incomplete instead of reporting
				// "no transcript" and dropping real content.
				partialNote = "(transcript may be incomplete)"
			default:
				// A single broken caption track (blocked URL, timeout, oversized
				// body) must not discard the already-fetched metadata — the
				// metadata is useful on its own, same as the no-tracks case.
				// Degrade for transient track failures; anything else (e.g. a
				// denial from the caption-host allowlist guard) stays an error.
				var ce *ClientError
				if errors.As(err, &ce) && (ce.Code == CodeTooLarge || ce.Code == CodeUnreachable || ce.Code == CodeTimeout) {
					captionNote = "(transcript unavailable: " + ce.Message + ")"
				} else {
					return nil, classifyClientError(err)
				}
			}
		}
	}

	content := formatTranscript(lines, y.opts.IncludeTimestamps)
	if captionNote != "" {
		content = captionNote
	}
	if partialNote != "" {
		if content != "" {
			content += "\n\n"
		}
		content += partialNote
	}

	content, truncated := model.Truncate(content, y.opts.MaxChars)

	return &Result{
		Content:    content,
		OutputType: "text/plain; charset=utf-8",
		Metadata:   videoMetadata(info, videoID),
		Truncated:  truncated,
	}, nil
}

// classifyClientError maps a YouTubeClient error to a *transform.Error suitable
// for the response envelope.
func classifyClientError(err error) *Error {
	var ce *ClientError
	if errors.As(err, &ce) {
		return &Error{Code: ce.Code, Message: ce.Message}
	}
	return &Error{Code: CodeTransformFailed, Message: err.Error()}
}

// --- transcript formatting ------------------------------------------------

// formatTranscript renders caption lines as plain text, one line per segment,
// optionally prefixed with a [mm:ss] (or [h:mm:ss]) timestamp.
func formatTranscript(lines []CaptionLine, withTimestamps bool) string {
	var b strings.Builder
	first := true
	for _, ln := range lines {
		text := strings.TrimSpace(ln.Text)
		if text == "" {
			continue
		}
		if !first {
			b.WriteByte('\n')
		}
		first = false
		if withTimestamps {
			b.WriteString(formatTimestamp(ln.StartMs))
			b.WriteByte(' ')
		}
		b.WriteString(text)
	}
	return b.String()
}

// formatTimestamp renders a millisecond offset as [mm:ss] or [h:mm:ss].
func formatTimestamp(ms int) string {
	if ms < 0 {
		ms = 0
	}
	total := ms / 1000
	s := total % 60
	m := (total / 60) % 60
	h := total / 3600
	if h > 0 {
		return fmt.Sprintf("[%d:%02d:%02d]", h, m, s)
	}
	return fmt.Sprintf("[%02d:%02d]", m, s)
}

// --- metadata ---------------------------------------------------------------

// videoMetadata builds the flat string-map metadata for the response envelope.
func videoMetadata(info VideoInfo, videoID string) map[string]string {
	m := make(map[string]string)
	if info.ID != "" {
		m["video_id"] = info.ID
	} else if videoID != "" {
		m["video_id"] = videoID
	}
	if info.Title != "" {
		m["title"] = info.Title
	}
	if info.Author != "" {
		m["author"] = info.Author
	}
	if info.ChannelID != "" {
		m["channel_id"] = info.ChannelID
	}
	// Duration and views are emitted even when zero so the fields are
	// consistently present (a brand-new video reports "0" views / "0:00"),
	// rather than silently disappearing on a zero value (finding M1).
	m["duration"] = formatDuration(info.Duration)
	m["views"] = strconv.Itoa(info.Views)
	if info.Description != "" {
		m["description"] = info.Description
	}
	if !info.Published.IsZero() {
		m["upload_date"] = info.Published.UTC().Format("2006-01-02")
	}
	return m
}

// formatDuration renders a duration as h:mm:ss (or mm:ss when under an hour).
func formatDuration(d time.Duration) string {
	total := int(d / time.Second)
	s := total % 60
	m := (total / 60) % 60
	h := total / 3600
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%d:%02d", m, s)
}

// --- language selection ---------------------------------------------------

// PickLanguage chooses the caption language: the exact preferred code if
// present, else a prefix match (so "en" matches "en-US"), else the first
// available track (fallback to any). Returns "" when no tracks exist.
func PickLanguage(preferred string, available []string) string {
	if len(available) == 0 {
		return ""
	}
	ordered := append([]string(nil), available...)
	sort.Strings(ordered)

	if preferred == "" {
		return ordered[0]
	}
	for _, l := range ordered {
		if l == preferred {
			return l
		}
	}
	prefix := strings.SplitN(preferred, "-", 2)[0]
	for _, l := range ordered {
		if l == prefix || strings.HasPrefix(l, prefix+"-") {
			return l
		}
	}
	return ordered[0]
}

// --- URL detection --------------------------------------------------------

// IsYouTubeURL reports whether sourceURL points at a YouTube host.
func IsYouTubeURL(sourceURL string) bool {
	u, err := url.Parse(sourceURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	host = strings.TrimPrefix(host, "www.")
	switch host {
	case "youtube.com", "m.youtube.com", "music.youtube.com", "youtu.be":
		return true
	}
	return false
}

// ExtractVideoID pulls the 11-character video ID from the supported URL shapes:
//
//	https://www.youtube.com/watch?v=ID
//	https://youtu.be/ID
//	https://www.youtube.com/shorts/ID
//	https://www.youtube.com/live/ID
//
// It also tolerates an 11-char ID passed directly. The ID charset matches
// YouTube's: [A-Za-z0-9_-].
func ExtractVideoID(sourceURL string) (string, bool) {
	raw := sourceURL

	if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" {
		ytHost := false
		switch strings.ToLower(u.Hostname()) {
		case "youtu.be":
			ytHost = true
			if id := pathSegment(u.Path, 0); validVideoID(id) {
				return id, true
			}
		case "youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com":
			ytHost = true
			if v := u.Query().Get("v"); validVideoID(v) {
				return v, true
			}
			trimmed := strings.Trim(u.Path, "/")
			parts := strings.SplitN(trimmed, "/", 2)
			if len(parts) == 2 {
				switch strings.ToLower(parts[0]) {
				case "shorts", "live", "embed":
					if validVideoID(parts[1]) {
						return parts[1], true
					}
				}
			}
		}
		// Fall through: maybe the path itself is a bare ID. YouTube hosts
		// only — a bare 11-char path segment on an arbitrary host
		// (https://example.com/dQw4w9WgXcQ) is not a video reference, and
		// accepting it made this exported helper looser than its contract.
		if ytHost {
			if id := pathSegment(u.Path, 0); validVideoID(id) {
				return id, true
			}
		}
		return "", false
	}

	// Last resort: the whole string might be a bare ID.
	id := strings.TrimSpace(raw)
	if i := strings.IndexByte(id, '?'); i >= 0 {
		id = id[:i]
	}
	id = strings.TrimPrefix(id, "/")
	return id, validVideoID(id)
}

// pathSegment returns the i-th non-empty segment of a URL path.
func pathSegment(p string, i int) string {
	seg := strings.Split(strings.Trim(p, "/"), "/")
	if i < 0 || i >= len(seg) {
		return ""
	}
	return seg[i]
}

// videoIDRe matches YouTube's 11-character video IDs.
const idCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

func validVideoID(id string) bool {
	if len(id) != 11 {
		return false
	}
	for _, r := range id {
		if !strings.ContainsRune(idCharset, r) {
			return false
		}
	}
	return true
}

// noopYouTubeClient is the zero-value fallback: every call errors as unsupported.
type noopYouTubeClient struct{}

func (noopYouTubeClient) GetVideo(context.Context, string) (VideoInfo, []string, error) {
	return VideoInfo{}, nil, &ClientError{Code: CodeUnsupported, Message: "no youtube client configured"}
}
func (noopYouTubeClient) GetTranscript(context.Context, string, string) ([]CaptionLine, error) {
	return nil, &ClientError{Code: CodeUnsupported, Message: "no youtube client configured"}
}

// --- real client (network) ------------------------------------------------

// parseTimedText decodes a YouTube timedtext caption payload (the XML format
// served by the signed CaptionTrack.BaseURL) into caption lines. Each <p>
// element is one segment: its "t" attribute is the start offset in ms and its
// text is the concatenation of any direct character data and nested <s> styling
// sub-segments. Non-paragraph elements (e.g. <w> window events, <head> layout)
// are ignored; empty paragraphs contribute no line.
//
// This is the timedtext fallback ("fetch the captions directly"):
// the kkdai library's innertube get_transcript endpoint returns HTTP 400 against
// current YouTube, but the signed BaseURL exposed on CaptionTrack works.
func parseTimedText(data []byte) ([]CaptionLine, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var (
		lines   []CaptionLine
		inP     bool
		startMs int
		text    strings.Builder
	)
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			if len(lines) == 0 {
				// A totally empty/non-XML body is not a transcript but not
				// worth erroring on — the caller treats "no segments" as no
				// transcript.
				return nil, nil
			}
			// Mid-stream malformed XML (truncated payload, raw control
			// characters): keep the segments parsed so far and report the
			// fault, instead of discarding real content and telling the
			// caller the video has no transcript.
			return lines, fmt.Errorf("timedtext parse: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "p" {
				inP = true
				text.Reset()
				startMs = 0
				for _, a := range t.Attr {
					if a.Name.Local == "t" {
						startMs, _ = strconv.Atoi(a.Value)
					}
				}
			}
		case xml.CharData:
			if inP {
				text.Write(t)
			}
		case xml.EndElement:
			if t.Name.Local == "p" {
				if s := strings.TrimSpace(text.String()); s != "" {
					lines = append(lines, CaptionLine{Text: s, StartMs: startMs})
				}
				inP = false
			}
		}
	}
	return lines, nil
}

// findCaptionTrack returns the caption track whose LanguageCode matches lang
// (exact, then BCP-47 prefix so "en" matches "en-US"). The second result is
// false when no track matches.
func findCaptionTrack(tracks []youtube.CaptionTrack, lang string) (youtube.CaptionTrack, bool) {
	for _, tr := range tracks {
		if tr.LanguageCode == lang {
			return tr, true
		}
	}
	prefix := strings.SplitN(lang, "-", 2)[0]
	for _, tr := range tracks {
		if tr.LanguageCode == prefix ||
			strings.HasPrefix(tr.LanguageCode, prefix+"-") {
			return tr, true
		}
	}
	return youtube.CaptionTrack{}, false
}

// realYouTubeClient adapts github.com/kkdai/youtube/v2 to the YouTubeClient
// interface. It caches fetched videos so the GetVideo → GetTranscript pair in a
// single request does not fetch the player response twice.
type realYouTubeClient struct {
	yt             youtube.Client
	mu             sync.Mutex
	cache          map[string]*youtube.Video
	maxCaptionSize int64
}

// defaultYouTubeTimeout bounds a single YouTube innertube request when no HTTP
// client (or a zero-timeout one) is supplied. It matches the generic fetcher's
// fallback so the YouTube path is never left without a deadline — a stalled
// innertube response must not pin a handler goroutine indefinitely.
const defaultYouTubeTimeout = 30 * time.Second

// defaultCaptionMaxBytes caps a single timedtext caption response. The YouTube
// path is a DirectTransform and bypasses the generic fetcher's max_size, so
// this bound is mandatory to prevent unbounded allocation.
const defaultCaptionMaxBytes int64 = 5 * 1024 * 1024

// defaultYouTubeMaxRedirects caps redirect hops on the YouTube egress client,
// matching the generic fetcher's default.
const defaultYouTubeMaxRedirects = 10

// NewRealYouTubeClient returns a YouTubeClient backed by the kkdai/youtube
// library. The HTTP client is configurable so [network].timeout can be applied;
// a nil or zero-timeout client falls back to an egress-guarded client with
// defaultYouTubeTimeout rather than http.DefaultClient (which has no deadline
// at all and no SSRF guard). Production wiring (cmd/keyhole buildDeps) passes
// a client carrying the configured timeout and SSRF policy; the fallback here
// is defense in depth with the strictest policy. Caption GETs are size-capped
// at defaultCaptionMaxBytes.
func NewRealYouTubeClient(httpClient *http.Client) YouTubeClient {
	return NewRealYouTubeClientLimited(httpClient, defaultCaptionMaxBytes)
}

// NewRealYouTubeClientLimited is like NewRealYouTubeClient but caps caption
// response bodies at maxCaptionBytes (0 → defaultCaptionMaxBytes). Production
// should pass [network].max_size so the DirectTransform path matches the
// generic fetcher's bound.
//
// The client's transport MUST be SSRF-guarded (see internal/egress): the
// passed client is used as-is so production policy is honored, and only the
// nil/zero-timeout fallback constructs a client — via egress with the strict
// default policy.
func NewRealYouTubeClientLimited(httpClient *http.Client, maxCaptionBytes int64) YouTubeClient {
	if httpClient == nil || httpClient.Timeout <= 0 {
		httpClient = egress.NewHTTPClient(egress.Policy{}, defaultYouTubeTimeout, defaultYouTubeMaxRedirects)
	}
	if maxCaptionBytes <= 0 {
		maxCaptionBytes = defaultCaptionMaxBytes
	}
	// The kkdai client reads the innertube player response with an unbounded
	// io.ReadAll; capping the transport bounds that fetch (and caption GETs)
	// by [network].max_size just like the generic fetcher.
	httpClient.Transport = egress.NewSizeCappedTransport(httpClient.Transport, maxCaptionBytes)
	c := youtube.Client{HTTPClient: httpClient}
	return &realYouTubeClient{
		yt:             c,
		cache:          make(map[string]*youtube.Video),
		maxCaptionSize: maxCaptionBytes,
	}
}

func (r *realYouTubeClient) fetchVideo(ctx context.Context, videoID string) (*youtube.Video, error) {
	r.mu.Lock()
	if v, ok := r.cache[videoID]; ok {
		r.mu.Unlock()
		return v, nil
	}
	r.mu.Unlock()

	watchURL := "https://www.youtube.com/watch?v=" + videoID
	v, err := r.yt.GetVideoContext(ctx, watchURL)
	if err != nil {
		return nil, classifyYouTubeLibError(err)
	}

	r.mu.Lock()
	r.cache[videoID] = v
	if len(r.cache) > 256 { // trivial bound to stop unbounded growth
		for k := range r.cache {
			if k != videoID {
				delete(r.cache, k)
			}
			if len(r.cache) <= 256 {
				break
			}
		}
	}
	r.mu.Unlock()
	return v, nil
}

func (r *realYouTubeClient) GetVideo(ctx context.Context, videoID string) (VideoInfo, []string, error) {
	v, err := r.fetchVideo(ctx, videoID)
	if err != nil {
		return VideoInfo{}, nil, err
	}
	langs := make([]string, 0, len(v.CaptionTracks))
	for _, t := range v.CaptionTracks {
		langs = append(langs, t.LanguageCode)
	}
	return toVideoInfo(v), langs, nil
}

func (r *realYouTubeClient) GetTranscript(ctx context.Context, videoID, lang string) ([]CaptionLine, error) {
	v, err := r.fetchVideo(ctx, videoID)
	if err != nil {
		return nil, err
	}
	// The kkdai library's innertube get_transcript endpoint (r.yt.GetTranscriptCtx)
	// returns HTTP 400 against current YouTube. Fall back to fetching the signed
	// CaptionTrack.BaseURL directly and parsing the timedtext payload — the
	// sanctioned path. The BaseURLs are already authenticated (they
	// carry the player-response signature), so a plain GET returns the captions.
	track, ok := findCaptionTrack(v.CaptionTracks, lang)
	if !ok {
		return nil, ErrTrackNotFound
	}
	body, err := r.fetchCaption(ctx, track.BaseURL)
	if err != nil {
		return nil, err
	}
	lines, perr := parseTimedText(body)
	if perr != nil {
		if len(lines) == 0 {
			return nil, classifyYouTubeLibError(perr)
		}
		return lines, fmt.Errorf("%w: %v", ErrPartialTranscript, perr)
	}
	if len(lines) == 0 {
		// A reachable track that yields no segments is effectively no transcript.
		return nil, ErrNoTranscript
	}
	return lines, nil
}

// fetchCaption GETs a signed timedtext BaseURL using the YouTube client's HTTP
// client and returns the raw body. The body is size-capped (maxCaptionSize) and
// the host is restricted to known YouTube/Google caption endpoints so a hostile
// or unexpected BaseURL cannot SSRF into private networks or OOM the process.
// Network/timeout errors are classified into the same typed codes the rest of
// the client produces.
func (r *realYouTubeClient) fetchCaption(ctx context.Context, baseURL string) ([]byte, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, &ClientError{Code: CodeTransformFailed, Message: "invalid caption URL"}
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, &ClientError{Code: CodeDenied, Message: "caption URL scheme not allowed"}
	}
	if !isAllowedCaptionHost(u.Hostname()) {
		return nil, &ClientError{
			Code:    CodeDenied,
			Message: "caption host not allowed: " + u.Hostname(),
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil, &ClientError{Code: CodeTransformFailed, Message: "build caption request: " + err.Error()}
	}
	// Do not follow redirects: the allowlist check above covers only the
	// initial URL, and the shared client's default policy would happily hop
	// to whatever target a hostile BaseURL names (e.g. a metadata IP).
	// Returning the first response fails closed — a 3xx surfaces as an
	// unreachable caption below rather than an SSRF.
	noRedirect := *r.yt.HTTPClient // shallow copy: shares Transport/timeout
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		return nil, classifyYouTubeLibError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, &ClientError{
			Code:    CodeUnreachable,
			Message: "caption fetch failed: HTTP " + strconv.Itoa(resp.StatusCode),
		}
	}
	limit := r.maxCaptionSize
	if limit <= 0 {
		limit = defaultCaptionMaxBytes
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, classifyYouTubeLibError(err)
	}
	if int64(len(data)) > limit {
		return nil, &ClientError{
			Code:    CodeTooLarge,
			Message: fmt.Sprintf("caption response exceeds max size (%d bytes)", limit),
		}
	}
	return data, nil
}

// isAllowedCaptionHost reports whether host is a known YouTube/Google caption
// endpoint. CaptionTrack.BaseURL is signed and normally points at these hosts;
// rejecting anything else closes an SSRF gap on the DirectTransform path.
func isAllowedCaptionHost(host string) bool {
	host = strings.ToLower(host)
	switch {
	case host == "youtube.com", host == "www.youtube.com", host == "m.youtube.com",
		host == "www.youtube-nocookie.com", host == "youtube-nocookie.com":
		return true
	case strings.HasSuffix(host, ".youtube.com"),
		strings.HasSuffix(host, ".googlevideo.com"),
		strings.HasSuffix(host, ".google.com"),
		strings.HasSuffix(host, ".googleapis.com"):
		return true
	default:
		return false
	}
}

// toVideoInfo maps the library Video to this package's VideoInfo.
func toVideoInfo(v *youtube.Video) VideoInfo {
	return VideoInfo{
		ID:          v.ID,
		Title:       v.Title,
		Description: v.Description,
		Author:      v.Author,
		ChannelID:   v.ChannelID,
		Duration:    v.Duration,
		Views:       v.Views,
		Published:   v.PublishDate,
	}
}

// classifyYouTubeLibError converts a kkdai/youtube error into a *ClientError.
func classifyYouTubeLibError(err error) error {
	switch {
	case errors.Is(err, youtube.ErrLoginRequired):
		return &ClientError{Code: CodeUnsupported, Message: "video is age-restricted or requires login"}
	case errors.Is(err, youtube.ErrVideoPrivate):
		return &ClientError{Code: CodeUnsupported, Message: "video is private"}
	case errors.Is(err, youtube.ErrNotPlayableInEmbed):
		return &ClientError{Code: CodeUnsupported, Message: "video is not playable"}
	}
	var ps *youtube.ErrPlayabiltyStatus
	if errors.As(err, &ps) {
		reason := ps.Reason
		if reason == "" {
			reason = ps.Status
		}
		return &ClientError{Code: CodeUnsupported, Message: "video is unavailable: " + reason}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &ClientError{Code: CodeTimeout, Message: "youtube fetch timed out"}
	}
	if errors.Is(err, context.Canceled) {
		return &ClientError{Code: CodeUnreachable, Message: "request canceled"}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return &ClientError{Code: CodeTimeout, Message: "youtube fetch timed out"}
	}
	return &ClientError{Code: CodeUnreachable, Message: "youtube fetch failed: " + err.Error()}
}
