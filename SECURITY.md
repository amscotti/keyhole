# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them privately
through GitHub Security Advisories for this repository:

https://github.com/amscotti/keyhole/security/advisories/new

Include what you can: the affected version or commit, a reproducer or proof of
concept, and the impact you believe it has. You can expect an initial response
within a few days; please allow time for a fix and a release before any public
disclosure.

## Threat model

Keyhole is a self-hosted fetch service whose clients are AI agents. The
security boundary is the configuration file: `default_policy = "deny"` plus
per-rule allowlists decide what may be fetched and which transforms may run.
Anything that lets a request bypass policy, reach a target the operator did not
allow, or leak a secret is in scope.

In scope:

- Policy bypass — a URL fetched without a matching allow rule, including via
  redirects, URL normalization tricks, or DNS rebinding.
- SSRF — reaching private, loopback, link-local, or cloud-metadata addresses
  when `[network] allow_private = false`, or when `pin_dns = true`.
- Secret leakage — auth-profile header values or URL-embedded credentials
  appearing in logs, error messages, the response envelope, or the cache.
- Credential scope — profile headers reaching a redirect target they are not
  configured for, or crossing an HTTPS→HTTP downgrade.
- Resource exhaustion — unbounded response size, cache growth, or request
  floods beyond configured limits.
- Container issues that weaken the non-root, minimal-surface posture.

Known tradeoffs (not vulnerabilities by themselves):

- `[network] allow_private = true` deliberately permits private targets.
- `[server] reload = true` lets anyone with write access to the config file
  change policy; file permissions are the control.
- `[mcp] disable_localhost_protection = true` deliberately disables the MCP
  library's Host-header guard behind a trusted reverse proxy.
- Fetched upstream content is untrusted input to the transforms, but Keyhole
  does not execute it. Transform parsing bugs are in scope only when they leak
  data or crash the service.

## Supported versions

Keyhole is a single binary; security fixes land on the default branch and the
latest tagged release. Older builds are not maintained.
