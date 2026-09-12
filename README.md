# Keyhole

A self-hosted fetch service for AI agents. Give it a URL; get back the
content shaped for an LLM's context window — clean Markdown, article text,
YouTube metadata + transcript, or Office documents as Markdown — wrapped in a
JSON envelope that records provenance. One TOML config controls what may be
fetched and how, URL by URL. Deny-by-default: nothing is fetchable unless a
rule allows it.

## Quickstart

```bash
mise install          # pinned toolchain: go, golangci-lint, pandoc
cp config.example.toml config.toml
# Set the secrets referenced by the example auth profiles (or: source .env.example):
export KEYHOLE_GITHUB_TOKEN=your_github_token
export KEYHOLE_INTERNAL_TOKEN=your_internal_token
mise run build
./keyhole --config config.toml
```

Fetch:

```bash
curl -X POST localhost:8080/fetch \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","transform":"article"}'
```

Response (the JSON envelope — same shape over REST and MCP):

```json
{
  "ok": true,
  "url": "https://example.com",
  "normalized_url": "https://example.com/",
  "final_url": "https://example.com/",
  "fetched_at": "2026-09-16T12:00:00Z",
  "status": 200,
  "transform": "article",
  "content_type": "text/markdown; charset=utf-8",
  "truncated": false,
  "content": "# Example Domain\n...",
  "metadata": {"title": "Example Domain"}
}
```

`metadata` is transform-specific (populated by `article` and `youtube`) and
omitted when empty. Each metadata value is capped at 4096 runes; either the
content cap or a metadata cap sets `truncated`.

| Transform  | Input → output                                          |
|------------|---------------------------------------------------------|
| `raw`      | Page HTML, verbatim (default)                           |
| `markdown` | Full page as Markdown                                   |
| `article`  | Reader-mode article extraction, then Markdown           |
| `youtube`  | Video metadata + transcript (comments not supported)    |
| `office`   | docx/pptx/xlsx/odt → Markdown (needs `pandoc`; see below) |

Health and ops:

```bash
curl localhost:8080/healthz   # liveness
curl localhost:8080/readyz    # readiness
curl localhost:8080/metrics   # Prometheus
```

## MCP

Keyhole exposes a single `fetch` tool over the Model Context Protocol so AI
agents can call it directly. MCP is a transport — it enforces the **exact same
policy and transforms** as the REST API. A URL allowed over REST is allowed over
MCP, and vice versa.

### Tool schema

| Parameter      | Type   | Required | Description                                                          |
|----------------|--------|----------|----------------------------------------------------------------------|
| `url`          | string | yes      | The URL to fetch.                                                    |
| `transform`    | enum   | no       | `raw` \| `markdown` \| `article` \| `youtube` \| `office`. Default: `raw`. |
| `max_chars`    | int    | no       | Truncate content to this many runes. Default: server `[output] max_chars`. |
| `auth_profile` | string | no       | Named auth profile. Refused with `bad_request` unless `[server] allow_client_auth_profile = true`; a profile attached to the matched rule is always applied, and naming a different one than the rule attaches is also a `bad_request`. |

The result is the JSON envelope (content, provenance, truncated flag) as
structured content, with the content text as a fallback for clients that only
read text. Policy denials surface as tool errors the model can read and react to.

### Running the MCP server

Two equivalent ways to enable it (either one starts the MCP server):

```bash
./keyhole --mcp --config config.toml          # --mcp flag (default: stdio for local agents)
# or set [mcp] enabled = true in config.toml  # config-driven, no flag needed
```

Two transports are supported via `[mcp] transport`:

- **`stdio`** (default) — JSON-RPC over stdin/stdout, for local agents that
  spawn Keyhole as a subprocess (Claude Desktop, Hermes). Logs are routed to
  stderr so stdout stays a clean JSON-RPC channel.
- **`http`** — MCP Streamable HTTP, served at `[mcp] listen` + `/mcp`, for
  remote or long-lived clients. Requires `[mcp] listen` (load fails closed if
  unset).

`[mcp] disable_localhost_protection` (default `false`) turns off the MCP
library's DNS-rebinding Host-header guard. Set it `true` only when a reverse
proxy that preserves the original Host sits in front of a loopback bind; like
the other `[mcp]` fields it is startup-only (an edit requires a restart).

**MCP mode replaces the REST API.** Enabling MCP (flag or config) means the
REST `/fetch` endpoint and the ops endpoints (`/healthz`, `/readyz`,
`/metrics`) are **not** served — MCP HTTP mounts only `/mcp`, and stdio serves
no HTTP at all. Run two processes with separate configs if you need both.

```toml
[mcp]
enabled = true
transport = "http"
listen = ":9090"
```

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "keyhole": {
      "command": "/absolute/path/to/keyhole",
      "args": ["--mcp", "--config", "/absolute/path/to/config.toml"]
    }
  }
}
```

Restart Claude Desktop. The `fetch` tool appears in the tool list automatically.

### Hermes and other MCP clients

Any client that speaks MCP over stdio can launch Keyhole as a subprocess:

```bash
keyhole --mcp --config config.toml
```

The server handshakes on the standard MCP stdio transport (JSON-RPC over
stdin/stdout). Point your client's stdio transport at the Keyhole binary and
it will discover the `fetch` tool via `tools/list`.

## Configuration

`config.example.toml` is fully annotated and is the reference. A minimal
config that fetches one site with no secrets looks like this:

```toml
default_policy = "deny"

[server]
listen = ":8080"

[[rules]]
match = "https://example.com/**"
allow = true
transforms = ["raw", "markdown"]
```

Security notes:
- `default_policy = "deny"` — only allowlisted URLs are fetchable.
- Hot-reload (`[server] reload`) defaults to **off**. When on, a valid edit
  rebuilds the policy engine, fetcher, auth profiles, transforms, and cache
  (not just the in-memory config pointer). Startup-only fields are
  **rejected** by the reloader: changing them logs `config reload rejected`
  and requires a restart, so a key rotation is never a silent no-op. That
  covers `[server] listen` / `api_key` / `rate` / `reload`, `[metrics]`,
  `[logging]`, and `[mcp]` (`enabled`, `transport`, `listen` — diffed per
  field). The clients are AI agents; a rogue model with filesystem access
  must not be able to silently rewrite the deny list.
- Auth profile header values are never logged; only the fact that a profile was applied. URLs in logs are sanitized (`scheme://host/path` — userinfo and query string are dropped).
- On redirects, profile-set headers continue only to the same origin, and never across an HTTPS→HTTP downgrade. If the redirect target's matched rule names its own `auth_profile`, that profile replaces the inherited headers; with no destination profile, custom credential headers are stripped.
- Client-selected `auth_profile` is **off by default** (`allow_client_auth_profile = false`). A client-supplied profile is then **refused with `bad_request`** rather than silently ignored; even with it enabled, naming a profile different from the one the matched rule attaches is a `bad_request`, since the wrong identity must never look like a successful fetch. Direct transforms (`youtube`) cannot apply auth profiles — a rule that attaches one to a direct-only transform fails loudly (`unsupported`) rather than silently fetching without credentials.
- `[cache] max_bytes` bounds the total cached value bytes (default 64 MiB); over budget the least-recently-used entries are evicted by bytes. `[cache] max_entries` defaults to 10000 — neither bound is ever disabled.
- Transform metadata values are capped at 4096 runes each and count toward the envelope's `truncated` flag, so metadata cannot bypass the response-size contract.
- MCP Streamable HTTP uses the same `api_key` and rate-limit ingress as REST `/fetch` (and caps request bodies at 1 MiB like REST).
- Private/loopback/link-local targets are refused unless `[network] allow_private = true` (needed for internal sites).
- `[network] max_size` defaults to 5 MiB when omitted or `0` (never unlimited).
- `POST /fetch` bodies are capped at 1 MiB.

## Development

```bash
mise run test              # unit tests with -race (cmd + internal)
mise run test-e2e          # end-to-end: real binary, REST + MCP Streamable HTTP
mise run test-all          # unit + e2e
mise run cover             # coverage profile → coverage/coverage.out + coverage.txt
mise run cover-html        # also write coverage/coverage.html
mise run lint
mise run test-integration  # network/pandoc gated (live YouTube / pandoc)
```

E2E tests live in `e2e/`. They build `./cmd/keyhole` once, start subprocesses with
generated configs, and hit them over loopback against an in-process `httptest`
upstream (no external network).

## Ops

### Flags

```
$ keyhole --help
Usage of keyhole:
  -config string
    	path to the TOML config file (default "config.toml")
  -mcp
    	run as an MCP server (stdio or Streamable HTTP per [mcp] config) instead of REST
  -version
    	print the version and exit
```

`keyhole --version` prints `keyhole <version>`. Release builds inject it with
`go build -ldflags "-X main.version=v0.1.0" ./cmd/keyhole`; an unstamped build
reports `dev`.

### Logs

Logs are structured JSON (zap production encoder) to stdout by default
(`[logging] output` can be a file path). Every line is a single JSON object
with a `level`, `ts` (RFC3339), `msg`, and context fields. Redaction is
unconditional: `Authorization`, `Proxy-Authorization`, `Cookie`, and
`Set-Cookie` are always replaced with `[REDACTED]`; auth-profile header values
are never logged at all (only the profile name).

| Message (`msg`)         | Level   | Fields                                                                                  | When                                                    |
|-------------------------|---------|-----------------------------------------------------------------------------------------|---------------------------------------------------------|
| `keyhole listening`     | info    | `addr`, `config`                                                                        | REST server bound and ready                             |
| `keyhole listening`     | info    | `addr`, `transport` (`http`), `endpoint` (`/mcp`), `api_key` (bool)                      | MCP Streamable HTTP server starting                     |
| `keyhole starting`      | info    | `mode` (`mcp`), `transport` (`stdio`/`http`), `config`                                  | MCP server starting                                     |
| `config hot-reload enabled` | info | `config`                                                                               | `[server] reload = true` at startup                     |
| `config reloaded`       | info    | `path`                                                                                  | Hot-reload applied a valid new config                   |
| `config reload rejected`| error   | `path`, `error`                                                                         | Hot-reload rejected an invalid edit (old config stays; also fires for startup-only field changes — restart required)  |
| `config watcher error`  | error   | `error`                                                                                 | fsnotify watcher failed                                 |
| `auth profile applied`  | info    | `profile`, `url`                                                                        | Auth-profile headers applied to a request (values never logged) |
| `request`               | info    | `request_id`, `method`, `path`, `status`, `duration`, `remote`                          | Every request routed through the middleware chain (`/fetch`, `/mcp`); unwrapped ops endpoints (`/healthz`, `/readyz`, `/metrics`) are not access-logged |
| `panic recovered`       | error   | `panic`, `request_id`, `stack`                                                          | A handler panicked (recovery middleware caught it)      |
| `shutdown signal received` | info | `signal`                                                                                | SIGINT/SIGTERM received (REST and MCP HTTP; the stdio transport's signals are handled by the MCP library, so this line does not appear there) |
| `graceful shutdown failed` | error | `error`                                                                               | Drain timed out or failed                               |
| `shutdown complete`     | info    | —                                                                                       | Clean exit (exit 0)                                     |
| `mcp fetch denied or failed` | debug | `url` (scheme://host/path only — userinfo and query never logged), `code`, `message` | MCP tool call denied or errored                         |

#### Datadog ingestion

Keyhole emits JSON logs to stdout (or a file). Datadog ingests them as-is — no
custom parser needed. Point the Datadog Agent at the output:

```yaml
# /etc/datadog-agent/conf.d/keyhole.d/conf.yaml
logs:
  - type: file
    path: /var/log/keyhole/*.log   # or "docker://<container>" for container stdout
    source: keyhole
    service: keyhole
```

For container stdout, the Datadog Docker integration autocollects — just set
the `DD_LOGS_CONFIG_CONTAINER_COLLECT_ALL` env var and tag the container with
`com.datadoghq.logs.source=keyhole`. The `status` field in access-log lines can
be mapped to a status remapper in a Datadog log pipeline for alerting on 4xx/5xx rates.

### Metrics

Prometheus `/metrics` at `[metrics] path` (default `/metrics`), gated by
`[metrics] enabled` (default `false` — set `enabled = true`, as the example
config does, to serve it). The path must start with `/` and cannot be
`/healthz`, `/readyz`, or `/fetch`; a bad or reserved path is a config load
error, not a boot-time route panic.

| Metric                                  | Type      | Labels            | Description                                            |
|-----------------------------------------|-----------|-------------------|--------------------------------------------------------|
| `keyhole_requests_total`                | counter   | `transform`, `status` | Total fetch requests, by transform and HTTP status class (2xx/4xx/5xx). |
| `keyhole_fetch_duration_seconds`        | histogram | `status`          | Outbound HTTP fetch latency, by status class.          |
| `keyhole_transform_duration_seconds`    | histogram | `transform`       | Transform application latency, by transform name.      |
| `keyhole_cache_hits_total`              | counter   | —                 | Cache hits.                                            |
| `keyhole_cache_misses_total`            | counter   | —                 | Cache misses.                                          |
| `keyhole_policy_denials_total`          | counter   | —                 | Requests denied by policy (deny rule or default deny). |

The `status` label groups HTTP statuses into `2xx`, `3xx`, `4xx`, `5xx`, `other`
to keep cardinality low. The `transform` label is the transform name
(`raw`, `markdown`, `article`, `youtube`, `office`, or `unknown` for pre-transform
errors like rate limiting or API-key rejection).

#### Grafana / Datadog dashboard pointers

Useful panels:
- **Request rate by status**: `rate(keyhole_requests_total[5m])` grouped by `status` — alert on 5xx > 0.
- **Policy denial rate**: `rate(keyhole_policy_denials_total[5m])` — a spike means an agent is hitting the deny list.
- **Cache hit ratio**: `rate(keyhole_cache_hits_total[5m]) / (rate(keyhole_cache_hits_total[5m]) + rate(keyhole_cache_misses_total[5m]))`.
- **Fetch latency p95**: `histogram_quantile(0.95, rate(keyhole_fetch_duration_seconds_bucket[5m]))`.
- **Transform latency by type**: `histogram_quantile(0.95, rate(keyhole_transform_duration_seconds_bucket[5m]))` grouped by `transform`.

In Datadog, use the `prometheus` check to scrape `/metrics` and import these as
metric names (prefixed with `keyhole.`).

### Container

```bash
# Full image (default) — includes pandoc for the office transform
docker build -t keyhole .
docker run -p 8080:8080 \
  -v "$PWD/config.toml:/etc/keyhole/config.toml:ro" \
  keyhole --config /etc/keyhole/config.toml

# Minimal image — binary only (office returns "unsupported"; YouTube still works)
docker build --target minimal -t keyhole:minimal .
```

The full image declares a container `HEALTHCHECK` against
`http://127.0.0.1:8080/healthz` (REST mode, default listen address). The
minimal (distroless) image omits it: distroless ships no shell or `curl`, and a
helper binary would grow the very attack surface the target exists to shrink —
point your orchestrator's external probe at `/healthz` instead.

### Transforms

See the table in Quickstart. Notes:

- `office` shells out to `pandoc` (`mise install` provides it; the `minimal`
  container image omits it, so `office` returns `unsupported` there).
- `youtube` needs no credentials and no external binary but does need egress to
  public YouTube endpoints; keep `[network] allow_private = false` (the
  default) — public IPs are unaffected by the SSRF guard.

## License

MIT — see [LICENSE](LICENSE).
