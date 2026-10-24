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

## License

AGPL-3.0, because Aegis builds on [samesame](https://github.com/TecharoHQ/samesame),
which is AGPL-3.0. See [LICENSE](LICENSE).
