# Changelog

All notable changes to Aegis are documented in this file. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Aegis adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each entry is one line that ends with a link to the pull request that made the
change. To release, run `go run ./scripts/changelog <version>` from the
repository root: it moves the entries under Unreleased into a section for that
version.

## [Unreleased]

### Added

- `web_bot_auth` directive: checks the Web Bot Auth signature of each request and writes the outcome to `{web_bot_auth.outcome}`.
- Placeholders `{web_bot_auth.signed}`, `{web_bot_auth.reason}`, `{web_bot_auth.agent}`, `{web_bot_auth.keyid}` and `{web_bot_auth.label}`.
- The `debug` log line of each signed request carries the outcome, reason, agent, key ID, label, signed flag and remote IP.
- `web_bot_auth` checks signatures against the method and URL the request arrived with, so `method`, `rewrite`, `uri`, `try_files` and `handle_path` do not break them.
- Optional settings for key discovery and signature checks, passed to samesame: `allowed_hosts`, `fetch_timeout`, `max_directory_size`, `ttl`, `min_ttl`, `max_ttl`, `negative_ttl`, `max_cache_entries`, `max_concurrent_fetches`, `max_validity`, `clock_skew` and `max_signatures`.
- `mode` setting: `observe`, the default, never blocks; `enforce` blocks invalid requests with the status code samesame suggests; `require` also blocks unverified requests with a `403` and an `Accept-Signature` challenge.
- Replay protection, always on: a request whose signature repeats the nonce of a verified signature from the same agent gets `invalid` with reason `replay`; the `max_nonces` setting sets how many nonces are remembered.
- `identity_header` setting: names a request header that `web_bot_auth` removes from every request it handles and, on a verified request, sets to the agent's key directory URL, so the app behind Caddy knows which agent sent the request and no client can fake it.
- Signatures verify behind a front server that ends TLS and sends plain HTTP, when Caddy's `trusted_proxies` holds it: `web_bot_auth` then takes the scheme from `X-Forwarded-Proto`, and the first `insecure_transport` outcome after each config load logs a warning that names the fix.
- `web_bot_auth` directives with the same key discovery settings share their downloaded key directories, and those with the same `max_nonces` share their nonces, also across config reloads, where an absent setting counts as different from one set to samesame's default: a reload that keeps those settings makes no agent wait for a download, and a replay gets `replay` at each directive that shares the nonces.

### Changed

### Deprecated

### Fixed

- Signed requests that name new agents and then disconnect no longer pile up waiting key directory downloads until Caddy runs out of memory: a lookup of an agent whose key directory has not been downloaded waits for one of `max_concurrent_fetches` slots only while a request waits for it.
