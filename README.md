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
