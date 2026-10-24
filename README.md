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

## Identity header

`identity_header` names a request header that tells the app behind Caddy
which agent sent each verified request:

```caddyfile
web_bot_auth {
	identity_header Web-Bot-Auth-Agent
}
```

On a `verified` request, the header holds the full URL of the agent's key
directory, the value of `{web_bot_auth.agent}`.

`web_bot_auth` first removes any copy of the header that the client sent,
from every request it handles, whatever the outcome. Without that, any client
could send the header itself and pass as a verified agent. Blocked requests
lose it too, because `handle_errors` routes can still send them to the app.

Only requests that a `web_bot_auth` with `identity_header` handles lose the
client's copy. A request that its matcher skips, or that takes a route without
it, reaches the app with the copy, so put such a `web_bot_auth`, with no
matcher, in every route that reaches the app. In the `require` example under
[Modes](#modes), each of the two `web_bot_auth` directives covers only its own
route.

The header is removed before the signature is checked, so a signature that
covers it never verifies. Pick a name that agents do not send, never
`Signature`, `Signature-Input` or `Signature-Agent`.

Without `identity_header`, `web_bot_auth` neither removes nor sets any request
header.

## Settings

Every setting is optional. `mode` is described in [Modes](#modes) and
`identity_header` in [Identity header](#identity-header). The others
go to [samesame](https://github.com/TecharoHQ/samesame), the library that
checks the signatures: an absent one keeps samesame's default, and Aegis sets
no defaults of its own.

```caddyfile
web_bot_auth {
	mode                   observe|enforce|require
	identity_header        <name>
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

All `web_bot_auth` directives with the same key discovery settings, in any
site, share one cache of downloaded key directories. Those settings are
`allowed_hosts`, `fetch_timeout`, `max_directory_size`, `ttl`, `min_ttl`,
`max_ttl`, `negative_ttl`, `max_cache_entries` and `max_concurrent_fetches`.
An agent's key directory is then downloaded once for all of them, and
`max_cache_entries` and `max_concurrent_fetches` limit them together. A config
reload keeps the cache when a directive of the new config has the same
settings, so the reload makes no agent wait for a new download. Settings are
the same only when written the same: an absent setting differs from one set to
samesame's default, so a directive without `fetch_timeout` and one with
`fetch_timeout 5s` use separate caches, and a reload that adds
`fetch_timeout 5s` starts a new cache.

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

All `web_bot_auth` directives with the same `max_nonces`, in any site, share
the nonces they remember, so a replay gets `replay` whichever of them checks
it. That matters because a signature that covers only the host, not the path,
verifies on every path of the site: in the `require` example under
[Modes](#modes), a signed request to a path outside `/feed/`, replayed to
`/feed/`, gets `replay`, and `require` blocks it. A request that several
directives check, such as a site-wide `web_bot_auth` and one inside a `handle`
block, is not a replay of itself: each of them can verify it.

`max_nonces` sets how many nonces the directives with that value remember at
once, together. When they remember that many, each new nonce makes them
forget the soonest-expiring nonce of the agent with the most nonces, and a
replay of the forgotten one gets `verified`. Once an agent that floods the
site with signed requests holds more nonces than any other agent, each of its
new nonces pushes out one of its own.

A config reload keeps the nonces of each `max_nonces` value that a directive
of the new config still has. An absent `max_nonces` counts as a value of its
own, different from `max_nonces 65536`, samesame's default: directives with
one and the other remember separate nonces, and a reload from one to the
other forgets them.

The nonces are kept in memory, which limits the protection:

- A replay sent to another Caddy instance, for example behind a load balancer, gets `verified`.
- Directives with different `max_nonces` values remember separate nonces, so a replay sent to a path that a directive with another value checks gets `verified`, once per value.
- Directives that share nonces but have different `clock_skew` values remember each nonce until `expires` plus the `clock_skew` of the directive that verified it first. Until the larger `clock_skew` also runs out, a replay sent to a directive with that larger value gets `verified`.
- A config reload forgets the nonces of each `max_nonces` value that no directive of the new config has.

## Caddy behind another HTTPS server

Signatures must be sent over HTTPS. A signed request gets `invalid` with reason
`insecure_transport` unless `web_bot_auth` can tell that the client used HTTPS.
When a front server, such as a load balancer, a CDN or a tunnel, ends the
client's TLS in front of Caddy, Caddy sees only the front server's connection,
and the way that connection reaches Caddy decides whether signatures verify.

### Preferred: re-encryption or TLS passthrough

With re-encryption, the front server opens its own HTTPS connection to Caddy.
With TLS passthrough, it routes the client's TLS connection to Caddy by SNI
without decrypting it. Either way, Caddy ends TLS itself and every hop is
encrypted, so signatures verify with no setting and no trusted header.

A re-encrypting front server must:

- keep the client's `Host` header, which signatures cover;
- send SNI, or Caddy needs the `default_sni` global option to pick a certificate;
- redirect clients that use plain HTTP to HTTPS, instead of forwarding their requests to Caddy over HTTPS, which would make a signature sent in plaintext verify.

With TLS passthrough, Caddy needs certificates for the site's names, so the
front server must also pass Caddy's ACME challenges through, unless Caddy uses
the DNS challenge. To keep client IPs, have the front server send the PROXY
protocol, and put Caddy's `proxy_protocol` listener wrapper, with `allow` for
the front server, before `tls`.

### Otherwise: plain HTTP from a trusted front server

When the front server sends plain HTTP, `web_bot_auth` takes the scheme from
its `X-Forwarded-Proto` header, but only when Caddy's `trusted_proxies` server
option holds the front server. If the header appears more than once,
the last one decides: `https` or `wss` means HTTPS, anything else plain HTTP.
From any other peer, the header is ignored. `web_bot_auth` has no setting for
this.

```caddyfile
{
	servers {
		trusted_proxies static 10.0.0.5
	}
}

http://example.com {
	web_bot_auth
	reverse_proxy app:8080
}
```

The site address starts with `http://`, or Caddy redirects the front server's
plain-HTTP requests to HTTPS. For a front server that reaches Caddy over a Unix
socket, use `trusted_proxies_unix` instead.

Use this only when nobody can watch the hop from the front server to Caddy,
best with both on the same machine. Signatures cross that hop in plaintext, and
anyone who reads them there can replay them, within the limits of
[replay protection](#replay-protection).

`trusted_proxies` is not specific to `web_bot_auth`: `reverse_proxy` and the
client IP also trust headers from the peers it holds. In turn, each of those
peers can make a signature sent over plain HTTP count as HTTPS, so each must set
`X-Forwarded-Proto` itself, replacing any value from the client.

### Front server config

| Front server | Re-encryption or TLS passthrough | Plain HTTP to Caddy |
|---|---|---|
| nginx | `proxy_pass https://<caddy>;` with `proxy_set_header Host $host;`, `proxy_ssl_server_name on;` and `proxy_ssl_name $host;`. Passthrough: the `stream` module with `ssl_preread on;` | `proxy_pass http://<caddy>;` with no path after the address, `proxy_set_header Host $host;` and `proxy_set_header X-Forwarded-Proto $scheme;` |
| HAProxy | `ssl` on the `server` line; HAProxy 3.4 sends the request's host as SNI by default. Passthrough: `mode tcp`, routing on `req.ssl_sni` | `http-request set-header X-Forwarded-Proto %[ssl_fc,iif(https,http)]`, not `add-header X-Forwarded-Proto https if { ssl_fc }`, which keeps a client's own value on plain-HTTP listeners |
| Traefik | Passthrough: a TCP router with `tls.passthrough: true` | Nothing: by default, Traefik sets `X-Forwarded-Proto` and removes the client's value |
| Cloudflare | SSL/TLS encryption mode "Full (strict)" | Not "Flexible": see below |
| Cloudflare Tunnel | An `https://` service with `matchSNItoHost: true` under `originRequest` | An `http://127.0.0.1:<port>` service, with `trusted_proxies static 127.0.0.1/32`. Do not set `httpHostHeader` |
| Tailscale Funnel | `tailscale funnel --tcp=443 tcp://localhost:<port>` | `tailscale funnel <port>`, which sets `X-Forwarded-Proto: https`, with `trusted_proxies static 127.0.0.1/32`. Avoid Unix socket targets, which get `Host: localhost`, and `--set-path`, which changes the path |

Some front server setups break signatures or expose them:

- Cloudflare "Flexible" sends requests from Cloudflare to Caddy over plain HTTP, so signatures cross the internet in plaintext. Use "Full (strict)".
- nginx replaces `Host` with the address in `proxy_pass` unless `proxy_set_header Host $host;` is set, and signatures then get `invalid`.
- Traefik removes `.` and `..` segments and duplicate slashes from paths, decodes percent-encoded unreserved characters, uppercases other percent-encodings, and turns `;` into `&` in queries. A signature that covers the path or query of a request Traefik changes gets `invalid`; samesame's own signer covers only the host and `Signature-Agent`. Traefik's docs call turning `sanitizePath` off unsafe.
- Fix `Host` at the front server: `web_bot_auth` never reads `X-Forwarded-Host`, because trusting it would let a signature made for one site verify on another.

After each config load, the first signature that gets `insecure_transport`
makes `web_bot_auth` log a warning that names the fix: if the request carried
`X-Forwarded-Proto` from a peer that Caddy does not trust as a proxy, add the
front server to `trusted_proxies`, or set `trusted_proxies_unix` for a Unix
socket; otherwise, use re-encryption, or send `X-Forwarded-Proto` from a front
server that Caddy trusts as a proxy. Each `web_bot_auth` handler logs the
warning at most once per config load, so several `web_bot_auth` directives, or
one in a site on several ports, can each log it.

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
