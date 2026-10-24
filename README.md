# Aegis

Aegis is a Caddy module that checks
[Web Bot Auth](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/)
signatures on incoming requests and tells the rest of the Caddy config the
outcome of each check.

## Install

Build Caddy with the module using [xcaddy](https://github.com/caddyserver/xcaddy)
and Go 1.27 or later:

```sh
xcaddy build --with github.com/kauricre/aegis
```

## Minimal Caddyfile

```caddyfile
example.com {
	web_bot_auth

	@verified vars {web_bot_auth.outcome} verified
	handle @verified {
		reverse_proxy app:8080
	}

	handle {
		reverse_proxy anubis:8923
	}
}
```

`web_bot_auth` checks the signature of every request, writes the outcome
(`verified`, `invalid` or `unverified`) to the `{web_bot_auth.outcome}`
placeholder, and passes the request on. Routes decide what each outcome gets:
here, verified requests go to the app and all others to Anubis.

## Placement

`web_bot_auth` checks each signature against the method and URL the request
arrived with, so `method`, `rewrite`, `uri`, `try_files` and `handle_path` do
not break signatures, even when they run first.

Headers are checked as they are when `web_bot_auth` runs, so a directive that
changes a header the signature covers before then breaks the signature. For
example, `request_header` setting `Host` makes the outcome `invalid`.

In Caddy's default directive order, `web_bot_auth` runs before `method`, so
before `rewrite`, `uri`, `try_files`, `request_header` and `handle_path`.
Inside a `route` block, directives run in the order they are written, so put
`web_bot_auth` first there.

## Placeholders

`web_bot_auth` sets these placeholders on every request, for use in matchers,
headers and logs:

| Placeholder | Value |
|---|---|
| `{web_bot_auth.outcome}` | `verified`, `invalid` or `unverified` |
| `{web_bot_auth.signed}` | `false` when the request has no Web Bot Auth signature (reason `no_signature`), else `true` |
| `{web_bot_auth.reason}` | why the request is not verified, as one of the codes below; empty when verified |
| `{web_bot_auth.agent}` | the full URL of the agent's key directory, for example `https://chatgpt.com/.well-known/http-message-signatures-directory`; empty unless verified |
| `{web_bot_auth.keyid}` | the thumbprint of the key that verified the signature; empty unless verified |
| `{web_bot_auth.label}` | the label of the signature that verified; empty unless verified |

Reason codes: `no_signature`, `malformed`, `insecure_transport`, `profile`,
`not_yet_valid`, `expired`, `validity_too_long`, `bad_signature`,
`key_unknown`, `discovery_failed`, `nonce_required`, `replay`, `nonce_store`,
`too_many_signatures`, and `other` for an error this version of Aegis does not
know.

To route one agent, match the full URL of its key directory:

```caddyfile
@openai vars {web_bot_auth.agent} https://chatgpt.com/.well-known/http-message-signatures-directory
```

## Settings

Every setting is optional. An absent setting keeps the default of
[samesame](https://github.com/TecharoHQ/samesame), the library that checks the
signatures; Aegis sets no defaults of its own.

```caddyfile
web_bot_auth {
	allowed_hosts          <host...>
	fetch_timeout          <duration>
	max_directory_size     <size>
	ttl                    <duration>
	min_ttl                <duration>
	max_ttl                <duration>
	negative_ttl           <duration>
	max_cache_entries      <n>
	max_concurrent_fetches <n>
	max_validity           <duration>
	clock_skew             <duration>
	max_signatures         <n>
}
```

| Setting | What it sets | Default (samesame v1.0.0) |
|---|---|---|
| `allowed_hosts` | the only hosts whose key directories are downloaded | any host |
| `fetch_timeout` | how long one key directory download may take | `5s` |
| `max_directory_size` | the largest key directory accepted, after decompression | `64KiB`; samesame also accepts at most 32 keys |
| `ttl` | how long a downloaded key directory stays fresh when its response sets no cache lifetime | `1h`; a response with `no-store` or `no-cache` stays fresh for `min_ttl` |
| `min_ttl`, `max_ttl` | the shortest and longest time a downloaded key directory stays fresh, whatever its response or `ttl` says | `1m`, `24h` |
| `negative_ttl` | the base of the wait after a failed download before the next one | `30s`: the first failure waits 15s to 30s, each further failure doubles the wait, a `Retry-After` raises it, and it never exceeds 5m |
| `max_cache_entries` | the most key directories cached at once, counting those whose download failed | `10000` |
| `max_concurrent_fetches` | the most key directory downloads in flight at once, across all agents | `64` |
| `max_validity` | the longest time from `created` to `expires` accepted in a signature | `24h` |
| `clock_skew` | the tolerance applied to `created` and `expires` | `1m` |
| `max_signatures` | the most signatures one request may carry; a request with more gets `invalid` | `4` |

Durations take Caddy's units, such as `30s`, `1h` or `2d`, and sizes take
units such as `64KiB` or `1MB`. Zero and negative values fail config load, and
so does a `min_ttl` greater than `max_ttl`, where an absent one counts as
samesame's default. In JSON config, the settings are fields of the
`web_bot_auth` handler with the same names; `max_directory_size` is in bytes.

A stale key directory is downloaded again when a signed request names it.
While those downloads fail, samesame keeps using the stale directory, so
`max_ttl` does not limit how long a key keeps verifying.

Discovery is open by default: Aegis downloads the key directory of any agent
that signs a request. samesame downloads only over HTTPS, follows no
redirects, and connects only to public addresses; no setting changes that.

`allowed_hosts` limits discovery to the listed hosts. A correctly signed
request from an agent on any other host gets `unverified` with reason
`discovery_failed`, and Aegis never downloads that agent's key directory.
Write each host as it appears in the agent's `Signature-Agent` header:
lowercase, with the port only when it is not 443.

```caddyfile
web_bot_auth {
	allowed_hosts chatgpt.com
}
```

## Access log

Caddy's access log records request headers, including `Signature`. A
signature can be replayed until it expires, so delete it from the access log:

```caddyfile
log {
	format filter {
		request>headers>Signature delete
	}
}
```

To see each request's outcome in the access log, add placeholders to its
entries with `log_append`:

```caddyfile
log_append wba_outcome {web_bot_auth.outcome}
log_append wba_reason {web_bot_auth.reason}
log_append wba_agent {web_bot_auth.agent}
```

## License

AGPL-3.0, because Aegis builds on [samesame](https://github.com/TecharoHQ/samesame),
which is AGPL-3.0. See [LICENSE](LICENSE).
