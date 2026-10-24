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

### Changed

### Deprecated

### Fixed
