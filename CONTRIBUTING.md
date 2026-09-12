# Contributing

Thanks for helping improve Keyhole. The toolchain and all tasks are pinned and
run through [mise](https://mise.jdx.dev/).

## Setup

```bash
mise install   # go, golangci-lint, pandoc — versions pinned in mise.toml
```

## Build, test, lint

```bash
mise run build             # build the ./keyhole binary
mise run test              # unit tests with -race (cmd + internal)
mise run test-e2e          # end-to-end: real binary, REST + MCP Streamable HTTP
mise run test-all          # unit + e2e
mise run test-integration  # network/pandoc-gated (live YouTube / pandoc)
mise run lint              # golangci-lint
mise run fmt               # gofmt -w
mise run cover             # coverage profile under coverage/
```

CI runs the `gofmt` check, `mise run lint`, `mise run test`, and
`mise run test-e2e` on every push and pull request.

## Pull requests

- Keep commits small and conventional (`feat:`, `fix:`, `test:`, `docs:`,
  `chore:`).
- Add or update tests for behavior changes; TDD is the house style.
- `mise run lint && mise run test` must be green before review.
- Do not weaken deny-by-default policy or fail-closed config validation. If a
  change touches either, explain the security reasoning in the PR.
- Never commit real tokens, `config.toml`, or `.env` — secrets belong in the
  environment only.
- Update `README.md` and `config.example.toml` when behavior or config keys
  change.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Report privately via GitHub Security
Advisories, not a public issue.
