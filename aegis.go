// Package aegis is a Caddy module that checks Web Bot Auth signatures on
// incoming requests and tells the rest of the Caddy config which outcome each
// request got.
package aegis

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/TecharoHQ/samesame"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("web_bot_auth", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("web_bot_auth", httpcaddyfile.Before, "method")
}

// tweakFetcher, when set, changes the options of the fetcher that downloads
// key directories. Only tests set it, to reach key directories on a loopback
// test server through AllowPrivateAddresses and TLSConfig, which config never
// reaches.
var tweakFetcher func(*samesame.FetcherOptions)

// fetchers and nonceStores hold the key caches and nonce stores that the loaded
// handlers share, as Handler describes. Each is dropped once no loaded handler
// uses it.
var fetchers, nonceStores = caddy.NewUsagePool(), caddy.NewUsagePool()

// Handler checks the Web Bot Auth signature of each request with samesame,
// writes the outcome and its details to the {web_bot_auth.*} placeholders, and
// passes the request on unless the mode blocks it. Every setting is optional:
// an absent mode is observe, an absent identity_header removes and sets no
// header, and any other absent setting keeps samesame's default.
//
// Handlers with the same key discovery settings share one cache of key
// directories, and handlers with the same max_nonces share the nonces they
// remember, also across config reloads. An absent setting counts as different
// from one set to samesame's default.
type Handler struct {
	// Which requests are blocked: observe, the default, blocks none; enforce
	// blocks invalid requests, with the status code samesame suggests; require
	// also blocks unverified requests, with a 403 and an Accept-Signature
	// header that asks for a signature.
	Mode string `json:"mode,omitempty"`

	// The request header that tells upstreams which agent sent a verified
	// request, set to the agent's key directory URL. Any copy a client sends
	// is removed from every request, whatever the outcome. When unset, no
	// header is removed or set.
	IdentityHeader string `json:"identity_header,omitempty"`

	// The only hosts whose agents' key directories are downloaded, each as
	// host or host:port; when unset, any host. Agents on other hosts get
	// unverified.
	AllowedHosts []string `json:"allowed_hosts,omitempty"`

	// How long one key directory download may take.
	FetchTimeout *caddy.Duration `json:"fetch_timeout,omitempty"`

	// The largest key directory accepted, in bytes after decompression.
	MaxDirectorySize *int64 `json:"max_directory_size,omitempty"`

	// How long a downloaded key directory stays fresh when its response sets
	// no cache lifetime.
	TTL *caddy.Duration `json:"ttl,omitempty"`

	// The shortest and the longest time a downloaded key directory stays
	// fresh, whatever its response or ttl says.
	MinTTL *caddy.Duration `json:"min_ttl,omitempty"`
	MaxTTL *caddy.Duration `json:"max_ttl,omitempty"`

	// The base of the wait after a failed key directory download before the
	// next one. It doubles with each consecutive failure.
	NegativeTTL *caddy.Duration `json:"negative_ttl,omitempty"`

	// The most key directories cached at once, counting those whose download
	// failed.
	MaxCacheEntries *int `json:"max_cache_entries,omitempty"`

	// The most key directory downloads in flight at once, across all agents.
	MaxConcurrentFetches *int `json:"max_concurrent_fetches,omitempty"`

	// The longest time from created to expires accepted in a signature.
	MaxValidity *caddy.Duration `json:"max_validity,omitempty"`

	// The tolerance applied to the created and expires times of a signature.
	ClockSkew *caddy.Duration `json:"clock_skew,omitempty"`

	// The most Web Bot Auth signatures one request may carry. A request with
	// more gets invalid.
	MaxSignatures *int `json:"max_signatures,omitempty"`

	// The most nonces remembered at once to detect replays, across all
	// agents.
	MaxNonces *int `json:"max_nonces,omitempty"`

	verifier *samesame.Verifier
	logger   *zap.Logger

	// The handler's keys in fetchers and nonceStores.
	fetcherKey    string
	nonceStoreKey int

	// Whether the handler has logged its warning about insecure_transport.
	// Each config load makes new handlers, so each load can warn again.
	warned *atomic.Bool
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.web_bot_auth",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision builds the verifier from the settings.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	h.warned = new(atomic.Bool)

	fetcherOpts, verifierOpts, nonceStoreSize := h.options()
	// %#v names every option and quotes each allowed host, so two handlers get
	// the same key only when samesame gets the same options.
	h.fetcherKey, h.nonceStoreKey = fmt.Sprintf("%#v", fetcherOpts), nonceStoreSize
	if tweakFetcher != nil {
		tweakFetcher(&fetcherOpts)
	}
	// A new fetcher or nonce store opens no connections and starts no
	// goroutines, so the one LoadOrStore drops when it finds a stored one
	// costs nothing to drop.
	fetcher, _ := fetchers.LoadOrStore(h.fetcherKey, samesame.NewFetcher(fetcherOpts))
	nonceStore, _ := nonceStores.LoadOrStore(h.nonceStoreKey, samesame.NewMemoryNonceStore(nonceStoreSize))
	verifierOpts.Resolver = fetcher.(*samesame.Fetcher)
	verifierOpts.NonceStore = sharedNonceStore{nonceStore.(*samesame.MemoryNonceStore)}
	verifierOpts.Scheme = clientScheme
	v, err := samesame.NewVerifier(verifierOpts)
	if err != nil {
		return err
	}
	h.verifier = v
	return nil
}

// Cleanup releases the handler's key cache and nonce store. Caddy calls it
// once for each handler whose Provision ran, also when Provision or Validate
// fails, and Provision takes both before anything can fail.
func (h *Handler) Cleanup() error {
	// Delete returns only the errors of a Destruct method, which neither
	// value has.
	_, _ = fetchers.Delete(h.fetcherKey)
	_, _ = nonceStores.Delete(h.nonceStoreKey)
	return nil
}

// sharedNonceStore is a nonce store that handlers share. A request that passes
// several of them is checked by each, and the first check records its nonces,
// so at the later checks they count as fresh for that request only; any other
// request with one of them is still a replay.
type sharedNonceStore struct{ store *samesame.MemoryNonceStore }

// recordedNonce is a nonce that a request recorded in a store. The store is
// part of it because a request can also pass a handler with another store,
// which must still record the nonce to catch replays sent to that handler.
type recordedNonce struct {
	store        *samesame.MemoryNonceStore
	scope, nonce string
}

// recordedNoncesVar names the Caddy var that holds the nonces a request has
// recorded. Caddy keeps one set of vars per request, seen by all its handlers.
const recordedNoncesVar = "web_bot_auth.recorded_nonces"

func (s sharedNonceStore) CheckAndRecord(ctx context.Context, scope, nonce string, until time.Time) (bool, error) {
	key := recordedNonce{s.store, scope, nonce}
	recorded, _ := caddyhttp.GetVar(ctx, recordedNoncesVar).(map[recordedNonce]bool)
	if recorded[key] {
		return true, nil
	}
	fresh, err := s.store.CheckAndRecord(ctx, scope, nonce, until)
	if fresh {
		if recorded == nil {
			recorded = make(map[recordedNonce]bool)
			caddyhttp.SetVar(ctx, recordedNoncesVar, recorded)
		}
		recorded[key] = true
	}
	return fresh, err
}

// options returns samesame's options for the settings, and the size of the
// nonce store. An absent setting stays zero, which samesame replaces with its
// own default.
func (h *Handler) options() (fetcher samesame.FetcherOptions, verifier samesame.VerifierOptions, nonceStoreSize int) {
	return samesame.FetcherOptions{
		AllowedHosts:         h.AllowedHosts,
		Timeout:              time.Duration(deref(h.FetchTimeout)),
		MaxBodySize:          deref(h.MaxDirectorySize),
		TTL:                  time.Duration(deref(h.TTL)),
		MinTTL:               time.Duration(deref(h.MinTTL)),
		MaxTTL:               time.Duration(deref(h.MaxTTL)),
		NegativeTTL:          time.Duration(deref(h.NegativeTTL)),
		MaxCacheEntries:      deref(h.MaxCacheEntries),
		MaxConcurrentFetches: deref(h.MaxConcurrentFetches),
	}, samesame.VerifierOptions{
		MaxValidity:   time.Duration(deref(h.MaxValidity)),
		ClockSkew:     time.Duration(deref(h.ClockSkew)),
		MaxSignatures: deref(h.MaxSignatures),
	}, deref(h.MaxNonces)
}

func deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}

// clientScheme returns the scheme the client used, which samesame uses to
// refuse signatures sent over plain HTTP and to rebuild the signed URL. It
// trusts X-Forwarded-Proto only from peers that Caddy trusts as proxies, so
// the module needs no setting of its own: from such a peer, the last line of
// the header decides; otherwise the connection's own TLS does. wss counts as
// https, because Traefik sends it for WebSocket upgrades.
func clientScheme(r *http.Request) string {
	if proto := r.Header.Values("X-Forwarded-Proto"); len(proto) > 0 && fromTrustedProxy(r) {
		switch proto[len(proto)-1] {
		case "https", "wss":
			return "https"
		}
		return "http"
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// fromTrustedProxy reports whether the trusted_proxy var marks the peer that
// sent r as a trusted proxy. Caddy sets the var from trusted_proxies and
// trusted_proxies_unix before any handler runs.
func fromTrustedProxy(r *http.Request) bool {
	// Config can set the trusted_proxy var to a value of any type.
	trusted, _ := caddyhttp.GetVar(r.Context(), caddyhttp.TrustedProxyVarKey).(bool)
	return trusted
}

// Validate rejects an unknown mode, a zero or negative number, which samesame
// would replace with its default, and a min_ttl greater than max_ttl, under
// which every key directory would stay fresh for max_ttl.
func (h *Handler) Validate() error {
	switch h.Mode {
	case "", "observe", "enforce", "require":
	default:
		return fmt.Errorf("mode must be observe, enforce or require, not %q", h.Mode)
	}

	if err := errors.Join(
		checkPositive("fetch_timeout", h.FetchTimeout),
		checkPositive("max_directory_size", h.MaxDirectorySize),
		checkPositive("ttl", h.TTL),
		checkPositive("min_ttl", h.MinTTL),
		checkPositive("max_ttl", h.MaxTTL),
		checkPositive("negative_ttl", h.NegativeTTL),
		checkPositive("max_cache_entries", h.MaxCacheEntries),
		checkPositive("max_concurrent_fetches", h.MaxConcurrentFetches),
		checkPositive("max_validity", h.MaxValidity),
		checkPositive("clock_skew", h.ClockSkew),
		checkPositive("max_signatures", h.MaxSignatures),
		checkPositive("max_nonces", h.MaxNonces),
	); err != nil {
		return err
	}

	minTTL, minName := samesame.DefaultMinTTL, "samesame's default min_ttl"
	if h.MinTTL != nil {
		minTTL, minName = time.Duration(*h.MinTTL), "min_ttl"
	}
	maxTTL, maxName := samesame.DefaultMaxTTL, "samesame's default max_ttl"
	if h.MaxTTL != nil {
		maxTTL, maxName = time.Duration(*h.MaxTTL), "max_ttl"
	}
	if minTTL > maxTTL {
		return fmt.Errorf("%s %s is greater than %s %s", minName, minTTL, maxName, maxTTL)
	}
	return nil
}

func checkPositive[T ~int | ~int64](name string, v *T) error {
	if v != nil && *v <= 0 {
		return fmt.Errorf("%s must be positive", name)
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Any client could send the identity header to pass as a verified agent,
	// so it is removed before anything else, which keeps it off every path
	// out of this handler, including blocked requests that handle_errors
	// routes send upstream. A signature that covers it never verifies.
	if h.IdentityHeader != "" {
		r.Header.Del(h.IdentityHeader)
	}

	// samesame checks the method and URL the request arrived with, which
	// Caddy stores before any handler runs, so a rewrite before this handler
	// does not break the signature. Caddy stores no headers, so a header
	// change before it still does.
	orig := r.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request)

	// httpsign, samesame's signature engine, writes the scheme and host into
	// the URL it verifies, so samesame gets a copy of r with its own copy of
	// the stored URL. When a signature covers a trailer field, httpsign also
	// reads the whole body, with no size limit, so the copy has no body.
	v := *r
	u := *orig.URL
	v.Method = orig.Method
	v.URL = &u
	v.Body = http.NoBody

	res, err := h.verifier.Verify(&v)
	outcome := samesame.OutcomeOf(err).String()
	reason := reasonOf(err)
	signed := !errors.Is(err, samesame.ErrNoSignature)
	var agent, keyID, label string
	if err == nil {
		agent, keyID, label = res.Identifier.String(), res.KeyID, res.Label
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("web_bot_auth.outcome", outcome)
	repl.Set("web_bot_auth.signed", signed)
	repl.Set("web_bot_auth.reason", reason)
	repl.Set("web_bot_auth.agent", agent)
	repl.Set("web_bot_auth.keyid", keyID)
	repl.Set("web_bot_auth.label", label)

	// Unsigned requests are most traffic, so only signed ones are logged.
	if signed {
		remoteIP, _ := repl.GetString("http.request.remote.host")
		h.logger.Debug("checked signature",
			zap.String("outcome", outcome),
			zap.String("reason", reason),
			zap.String("agent", agent),
			zap.String("keyid", keyID),
			zap.String("label", label),
			zap.Bool("signed", signed),
			zap.String("remote_ip", remoteIP),
		)

		// The module cannot read trusted_proxies to check the setup when the
		// config loads, so the handler's first insecure_transport outcome
		// after each load logs how to fix it.
		if errors.Is(err, samesame.ErrInsecureTransport) && h.warned.CompareAndSwap(false, true) {
			fix := "signatures need HTTPS; behind a front server that ends TLS, use re-encryption, or send X-Forwarded-Proto from a front server that Caddy trusts as a proxy (trusted_proxies, or trusted_proxies_unix for a Unix socket)"
			if len(r.Header.Values("X-Forwarded-Proto")) > 0 && !fromTrustedProxy(r) {
				fix = "X-Forwarded-Proto was ignored because the peer is not a trusted proxy; add the front server to trusted_proxies, or set trusted_proxies_unix for a Unix socket"
			}
			h.logger.Warn("signed request over plain HTTP got insecure_transport: "+fix, zap.String("remote_ip", remoteIP))
		}
	}

	if status, challenge := blockStatus(h.Mode, err); status != 0 {
		if challenge {
			// With the default options, WriteChallenge cannot fail.
			_ = samesame.WriteChallenge(w, samesame.ChallengeOptions{})
		}
		// handle_errors routes can show this error's text in a response, so
		// it carries no samesame error text, which can quote the client's
		// Signature-Agent header.
		return caddyhttp.Error(status, fmt.Errorf("blocked %s request: %s", outcome, reason))
	}
	if err == nil && h.IdentityHeader != "" {
		r.Header.Set(h.IdentityHeader, agent)
	}
	return next.ServeHTTP(w, r)
}

// blockStatus returns the status code with which mode blocks a request that
// samesame checked with err, and whether the response is a challenge. A zero
// status lets the request through.
func blockStatus(mode string, err error) (status int, challenge bool) {
	outcome := samesame.OutcomeOf(err)
	switch {
	case outcome == samesame.OutcomeInvalid && (mode == "enforce" || mode == "require"):
		return samesame.StatusCode(err), false
	case outcome == samesame.OutcomeUnverified && mode == "require":
		return http.StatusForbidden, true
	}
	return 0, false
}

// reasonOf returns the short code for why samesame did not verify a request,
// given the error it returned: empty when it verified, and other for an error
// the module does not know.
func reasonOf(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, samesame.ErrNoSignature):
		return "no_signature"
	case errors.Is(err, samesame.ErrMalformedSignature), errors.Is(err, samesame.ErrMalformedSignatureAgent):
		return "malformed"
	case errors.Is(err, samesame.ErrInsecureTransport):
		return "insecure_transport"
	case errors.Is(err, samesame.ErrProfile):
		return "profile"
	case errors.Is(err, samesame.ErrNotYetValid):
		return "not_yet_valid"
	case errors.Is(err, samesame.ErrExpired):
		return "expired"
	case errors.Is(err, samesame.ErrValidityTooLong):
		return "validity_too_long"
	case errors.Is(err, samesame.ErrBadSignature):
		return "bad_signature"
	case errors.Is(err, samesame.ErrKeyUnknown):
		return "key_unknown"
	case errors.Is(err, samesame.ErrDiscovery):
		return "discovery_failed"
	case errors.Is(err, samesame.ErrNonceRequired):
		return "nonce_required"
	case errors.Is(err, samesame.ErrReplay):
		return "replay"
	case errors.Is(err, samesame.ErrNonceStore):
		return "nonce_store"
	case errors.Is(err, samesame.ErrTooManySignatures):
		return "too_many_signatures"
	default:
		return "other"
	}
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
