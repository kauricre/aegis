package aegis

import (
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/dustin/go-humanize"
)

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler Handler
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return &handler, err
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	web_bot_auth [<matcher>] {
//		mode                   observe|enforce|require
//		identity_header        <name>
//		allowed_hosts          <host...>
//		fetch_timeout          <duration>
//		max_directory_size     <size>
//		ttl                    <duration>
//		min_ttl                <duration>
//		max_ttl                <duration>
//		negative_ttl           <duration>
//		max_cache_entries      <n>
//		max_concurrent_fetches <n>
//		max_validity           <duration>
//		clock_skew             <duration>
//		max_signatures         <n>
//		max_nonces             <n>
//	}
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		var err error
		switch d.Val() {
		case "mode":
			if !d.AllArgs(&h.Mode) {
				return d.ArgErr()
			}
		case "identity_header":
			if !d.AllArgs(&h.IdentityHeader) {
				return d.ArgErr()
			}
		case "allowed_hosts":
			hosts := d.RemainingArgs()
			if len(hosts) == 0 {
				return d.ArgErr()
			}
			h.AllowedHosts = append(h.AllowedHosts, hosts...)
		case "fetch_timeout":
			h.FetchTimeout, err = arg(d, parseDuration)
		case "max_directory_size":
			h.MaxDirectorySize, err = arg(d, parseSize)
		case "ttl":
			h.TTL, err = arg(d, parseDuration)
		case "min_ttl":
			h.MinTTL, err = arg(d, parseDuration)
		case "max_ttl":
			h.MaxTTL, err = arg(d, parseDuration)
		case "negative_ttl":
			h.NegativeTTL, err = arg(d, parseDuration)
		case "max_cache_entries":
			h.MaxCacheEntries, err = arg(d, strconv.Atoi)
		case "max_concurrent_fetches":
			h.MaxConcurrentFetches, err = arg(d, strconv.Atoi)
		case "max_validity":
			h.MaxValidity, err = arg(d, parseDuration)
		case "clock_skew":
			h.ClockSkew, err = arg(d, parseDuration)
		case "max_signatures":
			h.MaxSignatures, err = arg(d, strconv.Atoi)
		case "max_nonces":
			h.MaxNonces, err = arg(d, strconv.Atoi)
		default:
			return d.Errf("unrecognized subdirective %q", d.Val())
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// arg parses the only argument of the current subdirective with parse.
func arg[T any](d *caddyfile.Dispenser, parse func(string) (T, error)) (*T, error) {
	name := d.Val()
	var s string
	if !d.AllArgs(&s) {
		return nil, d.ArgErr()
	}
	v, err := parse(s)
	if err != nil {
		return nil, d.Errf("parsing %s: %v", name, err)
	}
	return &v, nil
}

func parseDuration(s string) (caddy.Duration, error) {
	d, err := caddy.ParseDuration(s)
	return caddy.Duration(d), err
}

func parseSize(s string) (int64, error) {
	size, err := humanize.ParseBytes(s)
	return int64(size), err
}

// Interface guard
var _ caddyfile.Unmarshaler = (*Handler)(nil)
