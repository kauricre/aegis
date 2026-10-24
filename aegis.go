// Package aegis is a Caddy module that checks Web Bot Auth signatures on
// incoming requests and tells the rest of the Caddy config which outcome each
// request got.
package aegis

import (
	"errors"
	"net/http"

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
// test server; config never reaches these options.
var tweakFetcher func(*samesame.FetcherOptions)

// Handler checks the Web Bot Auth signature of each request with samesame,
// writes the outcome and its details to the {web_bot_auth.*} placeholders, and
// passes the request on.
type Handler struct {
	verifier *samesame.Verifier
	logger   *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.web_bot_auth",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision builds the verifier: open discovery with samesame's defaults.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()

	var opts samesame.FetcherOptions
	if tweakFetcher != nil {
		tweakFetcher(&opts)
	}
	v, err := samesame.NewVerifier(samesame.VerifierOptions{Resolver: samesame.NewFetcher(opts)})
	if err != nil {
		return err
	}
	h.verifier = v
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
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
	}

	return next.ServeHTTP(w, r)
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
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
