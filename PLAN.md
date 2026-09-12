# Keyhole — Project Plan

> **Historical design document.** This plan captures the original design and the
> phase-by-phase build order for Keyhole. It is kept for the technical
> rationale, not as a current status tracker: the checkboxes below reflect the
> plan at authoring time, and README.md plus the code are the source of truth
> for current behavior.
>
> Written for the engineer (human or AI) who will implement this. Read the
> Overview and Technical sections first, then execute the phases in order.
> Phase 0 is the scaffold — every later phase builds on it and must keep
> `mise run lint` and `mise run test` green at all times.

---

## 1. Overview

Keyhole is a self-hosted "fetch for language models" service. An LLM — or any client — sends it a URL, and Keyhole goes out, retrieves the page or document, and returns the content shaped for a model's context window: clean Markdown instead of raw HTML, metadata plus transcript for YouTube videos, Markdown for Office documents, all wrapped in a JSON envelope that records provenance (final URL after redirects, fetch time, whether the content was truncated). The defining feature is policy: a single TOML file controls, at full-URL granularity, exactly what may be fetched and which transformations may be applied, with deny-by-default so a deployment can allow only internal sites — intranet docs, internal wikis, corporate portals — and explicitly block everything else. That matters because the clients are AI agents: the configuration file is the security boundary that keeps a well-meaning but over-eager model from scraping or exfiltrating things it shouldn't, and the transform pipeline is what makes retrieved content genuinely useful instead of a wall of HTML. Operationally the service is deliberately boring: JSON logs that stream straight into Datadog, a Prometheus metrics endpoint, health endpoints, an in-memory TTL cache, and hot-reload that is configurable but **off by default** so that a rogue AI with filesystem access cannot silently rewrite the deny list. Teams run it like any other small service and forget about it.

## 2. Technical Overview

Keyhole is a single Go binary built on the standard library's `net/http` server plus a small set of well-maintained libraries, each the drop-in tool for one job: `pelletier/go-toml/v2` for configuration (strict decoding so typos can't silently weaken policy), `JohannesKaufmann/html-to-markdown/v2` for HTML→Markdown, `go-shiori/go-readability` for article extraction (the "reader mode" pre-step that strips nav, ads, and boilerplate), `kkdai/youtube/v2` for YouTube metadata and caption tracks, `mark3labs/mcp-go` for the optional MCP surface, `prometheus/client_golang` for metrics, `uber-go/zap` for structured JSON logging, `bmatcuk/doublestar/v4` for glob matching, and `fsnotify` for config watching. Pandoc — an optional external binary — handles Office documents; its 3.x readers natively convert docx, pptx, and xlsx to Markdown. Code is organized as small packages under `internal/`, each with one responsibility: `config` (load, validate, env-substitute, hot-reload), `rules` (URL normalization + the policy matcher — a pure function of config and a normalized URL), `fetch` (HTTP client with timeouts, size caps, an SSRF guard, redirect handling that re-checks policy on the final URL, and named auth profiles), `transform` (a registry of transforms that each declare what they apply to and produce content), `cache` (in-memory TTL), `server` (REST handlers and middleware), `logging` (zap setup with redaction), `metrics`, `model` (envelope and error types), and `mcpserver` (a thin MCP wrapper that reuses the same policy and transform pipeline — MCP is a transport, not a separate product). The request flow: normalize URL → evaluate policy on the original URL → fetch with redirects, re-evaluating policy on the final URL → apply the requested transform → truncate → wrap in the JSON envelope. Hot-reload swaps the entire configuration atomically via `atomic.Pointer`, so a request never observes a half-applied policy. Engineering principles: favor the standard library and simple native solutions over wrappers; TDD on everything with real tests (httptest servers and fixture files under `testdata/`, never real network in unit tests); small focused packages; no package-level mutable state; errors as values mapped to typed error codes at the API boundary; YAGNI — each phase ships only what its definition of done requires. Library versions are verified at implementation time (links in References); if a dependency is archived or unmaintained, swap it for the listed alternative before proceeding.

**Working together.** The toolchain is pinned with mise (`mise.toml` at repo root): `go`, `golangci-lint`, `pandoc` — one `mise install` and every engineer (or AI assistant) has the same environment. `gofmt` is enforced (`mise run fmt`), `golangci-lint` runs with errcheck, govet, staticcheck, gocritic, and ineffassign enabled, and `mise run lint` must be green before any merge. Tests run with `-race` (`mise run test`); network- and pandoc-gated tests live behind `mise run test-integration` and are skipped in default CI. Commits are small and conventional (`feat:`, `fix:`, `chore:`, `test:`). TDD flow for every task: write the failing test, watch it fail, implement, watch it pass, commit. Secrets only ever arrive via environment variables — never in the TOML, never in logs. Every phase ends with a review pass (human or reviewing agent) before the next phase starts.

## 3. Repository layout

```
keyhole/
├── cmd/keyhole/main.go        # entrypoint: flags (--config, --mcp, --version), wiring, graceful shutdown
├── internal/
│   ├── config/                # TOML schema, validation, env substitution, hot reload
│   ├── rules/                 # URL normalization + glob matching + policy decisions
│   ├── fetch/                 # HTTP client, SSRF guard, redirects, size caps
│   ├── authprofile/           # named header/token profiles, redaction-aware logging
│   ├── transform/             # registry: raw, markdown, article, youtube, office
│   │   └── testdata/          # HTML/docx/pptx/xlsx/youtube fixtures
│   ├── cache/                 # in-memory TTL cache
│   ├── server/                # REST handlers, middleware (logging, metrics, recovery, api key)
│   ├── mcpserver/             # MCP tool wrapper (reuses rules + transform)
│   ├── logging/               # zap setup + redaction helpers
│   ├── metrics/               # Prometheus collectors
│   └── model/                 # response envelope + error types
├── testdata/                  # shared fixtures
├── .github/workflows/ci.yml   # lint + test -race on push/PR
├── mise.toml                  # pinned toolchain + tasks (mise run fmt/lint/test/build — no Makefile)
├── .golangci.yml
├── config.example.toml        # annotated reference config
├── .env.example
├── .gitignore
└── README.md
```

## 4. Configuration

The config file is the product. Reference: `config.example.toml`. Semantics:

- `default_policy = "deny"` → only URLs matching an allow rule may be fetched (allowlist mode, recommended). `"allow"` → everything is fetchable except URLs matching a deny rule (blocklist mode).
- `[[rules]]` entries: `match` is a **glob over the full normalized URL** (scheme://host/path?query), `allow` is bool, `transforms` is the list of transforms permitted for that URL, `auth_profile` optionally names a profile from `[[auth_profiles]]`.
- Matching is on the *normalized* URL: scheme and host lowercased, default port stripped, fragment stripped, IDN hosts converted to punycode, query string preserved (an `ignore_query` flag per rule can relax that). `*` matches within a path segment, `**` crosses segments: `https://example.com/*` is one level deep, `https://example.com/**` is the whole domain tree.
- Specificity: the rule with the longest literal (non-wildcard) prefix wins. On a tie, **deny wins** (fail closed). A deny rule anywhere in the chain blocks: policy is evaluated on both the original URL and the final URL after redirects — an allowed URL that 302s into a denied URL is refused.
- Unknown transform names, missing auth profile references, or a rule with no `match` are **load-time errors** — a typo must never silently weaken policy.
- `[server] reload = false` by default. When true, the file is watched (fsnotify); a change is fully parsed and validated, then swapped in atomically. An invalid edit is rejected with a logged error and the previous config stays active. Rationale: the LLM clients are the threat model — a rogue AI with write access to this file must not be able to silently rewrite the deny list.
- `[[auth_profiles]]` carry `headers` (inline table) whose values may reference environment variables as `${KEYHOLE_SOME_TOKEN}`. Header values are **never logged**; the log records only that a profile was applied ("auth profile 'github' applied to https://..."). Request logging redacts `Authorization`, `Proxy-Authorization`, `Cookie`, and `Set-Cookie` unconditionally.

### Response envelope

```json
{ "ok": true, "url": "...", "normalized_url": "...", "final_url": "...",
  "fetched_at": "2026-08-07T12:00:00Z", "status": 200, "transform": "markdown",
  "content_type": "text/markdown", "truncated": false,
  "content": "...", "metadata": { "title": "..." } }
```

Errors: `{ "ok": false, "error": { "code": "denied|bad_request|unsupported|too_large|timeout|unreachable|transform_failed", "message": "..." } }`. HTTP statuses map to the code (403/400/400/413/504/502/500).

---

## 5. Phases

Each phase: Goal (what and why), TODO (checklist — fine to tick off), Definition of Done (the real contract — every bullet verifiable with commands), and a Review Gate before moving on.

### Phase 0 — Project skeleton and toolchain

**Goal.** Stand up the repo with everything needed from day one: mise-pinned toolchain, lint/format/CI gates, logging with redaction, health endpoints, and skeleton unit tests proving the plumbing works. Nothing here is throwaway — every later phase builds on this.

**TODO**
- `git init`, `go mod init keyhole` (module path is local-only for now; rename if it ever gets published), `.gitignore` (binary, `.env`, `*.log`, `coverage.out`, `dist/`).
- `mise.toml` pinning `go`, `golangci-lint`, `pandoc` (verify current versions with `mise latest <tool>`; pin the stable ones). `mise install` must work on a clean checkout — that is the onboarding contract.
- `mise.toml` tasks (mise replaces a Makefile — `mise run <task>`): `fmt`
  (gofmt -w), `lint` (golangci-lint run), `test` (go test -race ./...),
  `test-integration` (go test -race -tags=integration ./...), `build`
  (go build -o keyhole ./cmd/keyhole), `start` (run with local config), `bench`.
- `.golangci.yml` enabling errcheck, govet, staticcheck, gocritic, ineffassign (sane settings, no aggressive rules that block CI).
- `.github/workflows/ci.yml`: on push/PR → `mise install`, `mise run fmt` (check), `mise run lint`, `mise run test`.
- `internal/logging`: zap setup — level/format/output from config, JSON production format, console dev format; a `Redact` helper and redacted request logging.
- `cmd/keyhole/main.go` skeleton: `--config` flag (default `config.toml`), `--mcp` flag placeholder, SIGTERM/SIGINT graceful shutdown, `atomic.Pointer[config.Config]` plumbing placeholder.
- `internal/server` stubs: `/healthz` (liveness, 200), `/readyz` (readiness, 200 when config loaded), `/metrics` placeholder (empty registry is fine for now).
- Skeleton unit tests: one real test per package (config parses the example file; logging redaction test — a known secret value must not appear in captured output; server returns 200 on /healthz).
- README.md quickstart, `.env.example`, `config.example.toml` (already scaffolded — make them accurate as you build).

**Definition of Done**
- [ ] `mise install` succeeds from a clean checkout with no manual steps.
- [ ] `mise run lint` exits 0 with zero findings.
- [ ] `mise run test` passes (with `-race`), including the redaction test that asserts a secret never reaches the log.
- [ ] `mise run build` produces `keyhole`; `./keyhole --config config.example.toml` starts, logs JSON to stdout, and `curl localhost:8080/healthz` returns 200 with a JSON body.
- [ ] SIGTERM shuts the process down cleanly (exit 0, "shutdown complete" log line).
- [ ] CI workflow is green on the first push.
- [ ] All files from the scaffold (`mise.toml`, `.golangci.yml`, `.github/`) exist and are committed.

**Review gate.** Read the diff with a reviewer (human or agent). Check the mise tasks actually work from scratch, not just in your shell.

---

### Phase 1 — Configuration system

**Goal.** Implement the full TOML schema with strict decoding, validation, environment substitution, and hot-reload (off by default). Everything downstream depends on config being trustworthy.

**TODO**
- `internal/config`: structs mirroring `config.example.toml` — `[server]` (listen, api_key, reload), `[logging]`, `[metrics]`, `[network]` (timeout, max_size, max_redirects, user_agent, allow_private, respect_robots), `[cache]` (enabled, ttl, max_entries), `[mcp]` (enabled, transport), `[output]` (max_chars), `[youtube]` (transcript_language, include_timestamps, max_chars), `[office]` (pandoc_path, timeout), `default_policy`, `[[rules]]`, `[[auth_profiles]]`.
- Strict decoding (`DisallowUnknownFields`) so a misspelled key is a load error, plus a validation pass: rule without `match`, rule without `allow`, unknown transform name in `transforms`, `auth_profile` referencing a missing profile, negative sizes, bad durations → clear, single-line errors naming the offending table and field.
- Environment substitution: `${KEYHOLE_*}` and `${VAR}` expansion in auth-profile header values (and only there — keep the surface small), resolved at load; missing variable → load error.
- Hot reload: `reload = true` → fsnotify watch on the config file; on change, parse+validate the new file fully, then swap via `atomic.Pointer`. Invalid new file → log error, keep old config, keep watching.
- Tests: parse happy path (example file), every validation failure path, substitution, reload-swap, reload-reject-invalid-keeps-old, unknown-key error.

**Definition of Done**
- [ ] `./keyhole --config <file-with-a-typo>` exits with a message naming the table and field (e.g. `config error: unknown field "timeoutt" in [network]`).
- [ ] A rule referencing `transforms = ["markdownn"]` is rejected at load.
- [ ] Auth header value `${KEYHOLE_GITHUB_TOKEN}` resolves only when the env var is set; otherwise a clear load error.
- [ ] With `reload = true`, editing the file updates behavior without restart (assert via a log line or `/readyz`-visible state); replacing it with invalid content logs an error and leaves the old config serving.
- [ ] With `reload = false` (default), editing the file has zero effect until restart.
- [ ] `mise run lint && mise run test` green.

**Review gate.** Confirm the security-sensitive validation paths (unknown keys, unknown transforms) have tests, not just the happy path.

---

### Phase 2 — Rules engine and policy checks

**Goal.** The heart of the product: URL normalization and the matcher, as a pure package with an exhaustive test matrix. No I/O — just config and strings in, a decision out.

**TODO**
- `internal/rules`: `Normalize(url) (string, error)` — lowercase scheme+host, strip default port (80/443), strip fragment, punycode IDN hosts (`golang.org/x/net/idna`), preserve query (rule-level `ignore_query` support).
- `Evaluate(rules, policy, rawURL) (Decision, error)` where `Decision = {Allowed bool, Rule *Rule, Reason string}`. Glob via doublestar over the normalized URL; longest-literal-prefix specificity; tie → deny; deny overrides allow.
- Precompile rules at load into a slice ordered by specificity (recompute only on reload).
- Test matrix (table-driven, this file is the crown jewel — be exhaustive): exact URL, single-segment `*`, `**` whole-domain, query preserved vs `ignore_query`, default-port strip, fragment strip, case-insensitive host, punycode (`https://bücher.example/**`), most-specific-wins, tie→deny, deny-overrides-allow, allow rule with no transform list (defaults to all), rule with empty `transforms` (allows raw only), malformed URL → error not panic.
- Wire `Evaluate` for the redirect case: given original + final URL, block if *either* is denied (unit-testable as a pure function).

**Definition of Done**
- [ ] Every case in the matrix above is a named table-test case and passes.
- [ ] `Normalize("https://EXAMPLE.com:443/a?b=c#frag")` == `https://example.com/a?b=c`.
- [ ] Deny-beats-allow on equal specificity is proven by a test, not just asserted in code.
- [ ] Malformed input returns an error, never panics (fuzz-style quick test with random strings is a bonus).
- [ ] `mise run lint && mise run test` green.

**Review gate.** This is the security surface — have the reviewer try to break the matcher (case, trailing slashes, encoded chars, IDN tricks).

---

### Phase 3 — Fetch layer, auth profiles, cache

**Goal.** Actually go get things: a hardened HTTP client with timeouts, size caps, redirect re-checking, an SSRF guard, named auth profiles that are applied but never logged, and the TTL cache.

**TODO**
- `internal/fetch`: custom `http.Client` + `Transport` — dial/TLS/header/overall timeouts from `[network]`, `max_redirects` with policy re-evaluation on the final URL (reuse `rules.Evaluate`), `max_size` via `io.LimitReader` + detect overflow → `too_large`, custom UA, optional robots.txt check (`temoto/robotstxt`) when `respect_robots = true`.
- SSRF guard: parse host; literal IP → check ranges; hostname → `net.LookupIP` and check every A/AAAA. Block loopback `127.0.0.0/8`, RFC1918 (`10/8`, `172.16/12`, `192.168/16`), link-local `169.254/16`, ULA `fc00::/7`, link-local IPv6 `fe80::/10`, multicast, unspecified, and the cloud metadata IP `169.254.169.254`. `allow_private = true` bypasses (documented: needed for internal-site use). DNS rebinding noted as known-hard; pinning is Phase 8.
- `internal/authprofile`: apply named profile headers to the request; add the "auth profile applied" log line (profile name + URL only — **values never logged**); request-log redaction of `Authorization`/`Proxy-Authorization`/`Cookie`/`Set-Cookie` and any value matching a configured secret.
- `internal/cache`: in-memory TTL cache, key = sha256(normalized URL + transform + auth profile) so cached content can never leak across identities, `ttl` + `max_entries` from config, janitor goroutine for expiry, injectable clock for tests. Cache only successful 200 text responses.
- Tests (httptest servers; no real network): redirect chain limit; allowed→denied 302 is refused; size cap → `too_large`; timeout → `timeout`; SSRF matrix (127.0.0.1, 10.x, 172.16.x, 192.168.x, 169.254.169.254, hostname resolving to private IP, literal-IP URL) blocked by default and allowed with `allow_private`; auth echo server asserts headers arrived; redaction test asserts the header value appears nowhere in captured logs; cache hit/miss/TTL-expiry/profile-isolation.

**Definition of Done**
- [ ] SSRF matrix test passes: every private-range target is refused with `denied` unless `allow_private = true`.
- [ ] A test server proves `Authorization` is sent but its value is absent from all log output.
- [ ] Redirect into a denied URL returns `denied`, not the content.
- [ ] Body over `max_size` returns `too_large` with `truncated` unset.
- [ ] Cache: second identical fetch is a hit (assert via metric/log), different auth profile is a miss, expired entry is a miss.
- [ ] `mise run lint && mise run test` green; `-race` clean.

**Review gate.** Reviewer focuses on the SSRF guard and redaction — both are the kind of thing that looks right and is wrong.

---

### Phase 4 — REST API, core transforms, observability

**Goal.** The visible product: `POST /fetch` with the JSON envelope, raw/markdown/article transforms, middleware (request logging with redaction, metrics, recovery, optional API key), full observability wiring.

**TODO**
- `internal/model`: envelope + error types; `truncated` flag set when content is cut (cut at a rune boundary, never mid-codepoint).
- `internal/server`: `POST /fetch {url, transform, max_chars?, auth_profile?}` → 200 envelope or typed error; `GET /fetch` convenience variant for simple URLs; optional `X-API-Key` check when `[server] api_key` is set; recovery middleware (panic → 500 + logged stack); request-ID middleware (header `X-Request-Id`, echoed in logs and response).
- `internal/transform` registry: `raw` (identity — returns body as-is, as "raw HTML" per the product promise), `markdown` (html-to-markdown v2 with commonmark plugin, tables; full-page conversion), `article` (go-readability first → markdown of the extracted article — "reader mode"). Each transform declares applicability (e.g. markdown/article need `text/html`); inapplicable → `unsupported`/400 with a clear message.
- Truncation: `max_chars` request param, default from `[output] max_chars`; set `truncated: true` when applied.
- `internal/metrics`: `keyhole_requests_total{transform,status}`, `keyhole_fetch_duration_seconds{status}`, `keyhole_transform_duration_seconds{transform}`, `keyhole_cache_hits_total`, `keyhole_cache_misses_total`, `keyhole_policy_denials_total`; wire `/metrics`; wire `[metrics] enabled/path`.
- Golden files: HTML fixtures under `internal/transform/testdata/` with expected `.md` outputs (a real page with headings, links, tables, code blocks, plus a nav/ads-heavy page to show article extraction). Use `-update` flag pattern for regenerating goldens deliberately.
- Graceful shutdown completes (drains in-flight requests), `SIGTERM` log lines.

**Definition of Done**
- [ ] `curl -X POST localhost:8080/fetch -d '{"url":"https://example.com","transform":"markdown"}'` returns the envelope with `ok:true` and markdown content; `transform:"raw"` returns the raw body.
- [ ] A fixture page with nav/ads converts to noisy markdown with `markdown` and clean article text with `article`.
- [ ] Oversized content returns `truncated:true`; `max_chars` overrides the config default.
- [ ] `denied` URL → 403 envelope; unknown transform → 400; non-HTML with `markdown` → 400 with clear message; fetch failure → 502/504.
- [ ] Requests appear in `/metrics` counters; `/healthz`, `/readyz`, `/metrics` all respond.
- [ ] `X-Request-Id` flows through logs and response.
- [ ] With `api_key` set, requests without the key get 401.
- [ ] `mise run lint && mise run test` green; goldens committed.

**Review gate.** Reviewer checks error-code mapping and the truncation/runeboundary logic; run the API by hand once end-to-end.

---

### Phase 5 — YouTube transform

**Goal.** When a YouTube URL is fetched, return structured metadata + transcript instead of scraping the page HTML.

**TODO**
- Detect YouTube by host/pattern (`youtube.com/watch?v=`, `youtu.be/`, `/shorts/`, `/live/`); everything else → `unsupported` (this transform only applies to YouTube).
- `kkdai/youtube/v2`: video metadata (title, author, duration, view count, description, upload date) into `metadata`; caption tracks → transcript. **Verify the current captions/transcript API at implementation time** — if the library's transcript support is thin, fall back to fetching the timedtext captions directly with a timeout.
- `[youtube] transcript_language` (fall back to any available track), `include_timestamps` (prefix `[mm:ss]`), `max_chars` truncation.
- Wrap the client in an interface so non-network paths are unit-testable with a fake; real fetch lives in `mise run test-integration`.
- Errors: age-restricted / unavailable / geo-blocked / network → typed envelope codes; **comments are explicitly NOT supported in this version** — requesting them returns 501-style `unsupported` with "comments are not supported in this version of Keyhole".

**Definition of Done**
- [ ] Integration test (`-tags=integration`) fetches a known public video and returns envelope with non-empty metadata + transcript for the configured language.
- [ ] `include_timestamps: true` prefixes timestamps; `false` doesn't.
- [ ] Transcript over `max_chars` returns `truncated:true`.
- [ ] Fake-client unit tests cover: unavailable video → typed error, language fallback, timestamp formatting.
- [ ] YouTube URL with `transform:"markdown"` returns `unsupported` with a message pointing at `transform:"youtube"`.
- [ ] `mise run lint && mise run test` green (network tests skipped without the tag).

**Review gate.** Confirm the fake/real client split keeps CI hermetic.

---

### Phase 6 — Office transform (pandoc)

**Goal.** Office documents (docx/pptx/xlsx/odt) fetched as files convert to GFM Markdown via the optional pandoc binary.

**TODO**
- Dispatch by content-type (`application/vnd.openxmlformats-officedocument.*`, ODF equivalents) with extension fallback; only allowlisted types reach pandoc.
- Execute `[office] pandoc_path` (`pandoc -f <fmt> -t gfm -`) with a timeout and output size cap (pandoc output can exceed the input cap); stdin/stdout piping, no temp files unless needed for binary formats pandoc can't take on stdin (verify — pptx/xlsx may need temp files; if so, use a temp dir cleaned in a defer).
- **Verify pandoc reader flags at implementation time** (`pandoc -f docx`, `-f pptx`, `-f xlsx` — pptx/xlsx readers exist in pandoc 3.x but flag spelling and stdin support must be checked against the installed version; `pandoc --list-input-formats`).
- Pandoc missing → 501-style `unsupported` with "office conversion requires pandoc (mise install)".
- Tests gated: fixtures under `internal/transform/testdata/` (tiny docx/pptx/xlsx); run in `mise run test-integration`; skip cleanly with a `t.Skip` message when pandoc is absent.

**Definition of Done**
- [ ] A fixture `.docx` converts to GFM with headings, lists, and tables intact (golden file).
- [ ] `.pptx` and `.xlsx` fixtures convert if the installed pandoc readers support them; if a reader is missing, the test skips with a message (and a note is filed — don't fake it).
- [ ] Pandoc absent → clean `unsupported` error, not a panic or empty content.
- [ ] Pandoc that hangs → `timeout` after `[office] timeout`.
- [ ] `mise run lint && mise run test` green; `mise run test-integration` green on a machine with mise-installed pandoc.

**Review gate.** Check temp-file handling (cleanup on all paths) and the skip-not-fail convention.

---

### Phase 7 — MCP server

**Goal.** Expose the same fetch service as an MCP tool so agents (Claude Desktop, Hermes, custom clients) can call it directly. MCP is a transport: it must enforce the exact same policy and transforms as REST.

**TODO**
- `internal/mcpserver` with `mark3labs/mcp-go` (verify current version; the official `modelcontextprotocol/go-sdk` is the fallback if mcp-go is stale — official SDK is stdio-only, so prefer mcp-go when HTTP transport is wanted).
- Tool `fetch` with JSON schema: `url` (string, required), `transform` (enum: raw/markdown/article/youtube/office), `max_chars` (int, optional), `auth_profile` (string, optional). Description written for an LLM: what it does, that content is truncated, that policy applies.
- Enable via `[mcp] enabled = true` or CLI `--mcp`; `transport = "stdio"` default, `"http"` option if mcp-go supports it at implementation time. Single binary, same config file, same rules engine.
- Result returned as the envelope (structured content + metadata); policy denial surfaces as a tool error the model can read.
- Docs: README snippet for Claude Desktop `claude_desktop_config.json` and a Hermes/other-client note.

**Definition of Done**
- [ ] `./keyhole --mcp --config config.example.toml` handshakes with an MCP client (MCP Inspector or a minimal Go test client): `tools/list` shows `fetch` with the correct schema.
- [ ] `tools/call` with a permitted URL returns the envelope content; with a denied URL returns an error the client can read.
- [ ] The same config that allows a URL over REST allows it over MCP, and vice versa — one test proves parity.
- [ ] `mise run lint && mise run test` green.

**Review gate.** Test parity between REST and MCP paths; make sure a model-facing description exists (models read the tool description, not our docs).

---

### Phase 8 — Hardening and ops polish

**Goal.** Production-readiness: container image, rate limiting, DNS-rebinding mitigation, benchmarks, and ops documentation. Only what the DoD lists — nothing speculative.

**TODO**
- Multi-stage `Dockerfile` + `.dockerignore` (builder: mise or `golang:bookworm`; runtime: `scratch`/`distroless` + optional pandoc layer); `mise run docker`.
- Rate limiting (config: `[server] rate = {rps, burst}` per client IP, applied to `/fetch`) with 429 + `Retry-After`.
- DNS-rebinding mitigation behind a flag: resolve once, pin the IP for the connection (custom `DialContext`), default off with docs on the tradeoff.
- Benchmarks: `BenchmarkEvaluate` (matcher), `BenchmarkMarkdown` (transform) → `mise run bench`.
- Ops README section: log schema (fields emitted), full metric list, Datadog ingestion snippet (`logs: - type: file, source: keyhole`, JSON), Grafana/DD dashboard pointers, `--help` output for flags.
- Optional: `keyhole doctor` subcommand — validates config, checks pandoc presence, pings /healthz. (Stretch; only if the rest is done.)

**Definition of Done**
- [ ] `docker build` succeeds; container serves `/healthz`; pandoc present in the image when built with it.
- [ ] Rate limit kicks in above configured rps with 429 and `Retry-After` (test with `-race`).
- [ ] Rebind pin flag: hostname resolving to a private IP is refused even with `allow_private` when the flag is on.
- [ ] Benchmarks run and results are recorded in the commit message (numbers change, nothing else).
- [ ] Ops README documents every metric and log field; a Datadog pipeline could be configured from it alone.
- [ ] Full suite: `mise run lint && mise run test && mise run test-integration` green.

**Review gate.** Final full review of the repo against the Overview promises — every claim in the README must be true.

---

## 6. References

- `github.com/JohannesKaufmann/html-to-markdown` — HTML→Markdown v2 (converter + commonmark plugin)
- `github.com/go-shiori/go-readability` — article extraction; `codeberg.org/readeck/go-readability` v2 fork (faster) as alternative
- `github.com/pelletier/go-toml/v2` — TOML parsing with strict decode
- `github.com/bmatcuk/doublestar/v4` — `**` glob matching
- `github.com/kkdai/youtube/v2` — YouTube metadata + captions (verify transcript API at Phase 5)
- `github.com/mark3labs/mcp-go` — MCP SDK (stdio + HTTP); official `github.com/modelcontextprotocol/go-sdk` as fallback
- `github.com/prometheus/client_golang` — metrics
- `go.uber.org/zap` — structured logging (JSON for Datadog)
- `github.com/fsnotify/fsnotify` — config hot-reload watcher
- `github.com/temoto/robotstxt` — optional robots.txt parsing
- `golang.org/x/net/idna` — IDN/punycode URL normalization
- Pandoc manual (pandoc.org/MANUAL.html) — docx/pptx/xlsx readers (`pandoc --list-input-formats`)
- Datadog — JSON log ingestion: `logs: - type: file, path: <logfile>, source: keyhole`
- mise — toolchain manager: `mise.toml` pins go/golangci-lint/pandoc
- Go stdlib — `net/http` (1.22+ pattern routing), `net/url`, `crypto/sha256`
