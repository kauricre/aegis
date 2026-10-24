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

## Modes

`mode` decides which requests `web_bot_auth` blocks, by outcome. Unsigned
requests are `unverified`.

| Mode | `verified` | `invalid` | `unverified` |
|---|---|---|---|
| `observe` (default) | passed on | passed on | passed on |
| `enforce` | passed on | blocked | passed on |
| `require` | passed on | blocked | blocked with a challenge |

A blocked request gets the status code samesame suggests for its reason: `400`
for `malformed`, `429` for `replay`, and `403` for any other. A challenge is a
`403` response with an `Accept-Signature` header that tells the agent how to
sign its request.

Start in `observe` and read the outcomes in the [access log](#access-log)
before blocking anything. Correctly signed requests can still be `invalid`,
for example through clock skew or a server in front of Caddy that changes a
signed header.

`enforce` never blocks `unverified` requests. A key directory that cannot be
downloaded, or that lacks the signing key, says nothing against the agent, and
blocking on it would let one outage of that key directory block the agent on
every site that runs Aegis.

`require` is for endpoints meant only for agents, such as an API or a feed.
Scope it to them, never the whole site:

```caddyfile
example.com {
	handle /feed/* {
		web_bot_auth {
			mode require
		}
		reverse_proxy feed:8080
	}

	handle {
		web_bot_auth
		reverse_proxy app:8080
	}
}
```

Blocked requests go through Caddy's error handling, so `handle_errors` can
change the response, and the `{web_bot_auth.*}` placeholders are set there.

## Settings

Every setting is optional. `mode` is described in [Modes](#modes). The others
go to [samesame](https://github.com/TecharoHQ/samesame), the library that
checks the signatures: an absent one keeps samesame's default, and Aegis sets
no defaults of its own.

```caddyfile
web_bot_auth {
	mode                   observe|enforce|require
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
	max_nonces             <n>
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
| `max_nonces` | the most nonces remembered at once to detect replays, across all agents | `65536` |

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

## Replay protection

A signature stays valid until its `expires` time, so anyone with a copy of a
signed request can send it again: a replay. `web_bot_auth` remembers the
nonce of each verified signature, a random value that the agent puts into
that signature only, for as long as the signature can verify: until
`expires` plus `clock_skew`. A later request whose signature comes from the
same agent and has the same nonce gets `invalid` with reason `replay`, which
`enforce` and `require` block with a `429`. Replay protection is always on.

A correctly signed request without a nonce gets `verified`, also when it is
sent again: nothing tells a replay of it from the original.

`max_nonces` sets how many nonces `web_bot_auth` remembers at once. When it
remembers that many, each new nonce makes it forget the soonest-expiring
nonce of the agent with the most nonces, and a replay of the forgotten one
gets `verified`. Once an agent that floods the site with signed requests
holds more nonces than any other agent, each of its new nonces pushes out one
of its own.

The nonces are kept in memory, which limits the protection:

- A replay sent to another Caddy instance, for example behind a load balancer, gets `verified`.
- Each `web_bot_auth` directive remembers its own nonces. A signature that covers only the host, not the path, verifies on every path of the site, so a replay sent to a path that another `web_bot_auth` directive checks gets `verified`, once per directive. In the `require` example under [Modes](#modes), a signed request to any path outside `/feed/` can be replayed once to `/feed/`, and `require` lets it through.
- A config reload forgets every nonce.

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

The filter covers only the access log. At `debug` level, Caddy's error log
also records each request that `web_bot_auth` blocks, with its headers,
including `Signature`.

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
