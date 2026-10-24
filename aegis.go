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
// writes the outcome to the {web_bot_auth.outcome} placeholder, and passes the
// request on.
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
	// httpsign, samesame's signature engine, writes the scheme and host into
	// the URL it verifies, so samesame gets a copy of r with its own URL.
	// When a signature covers a trailer field, httpsign also reads the whole
	// body, with no size limit, so the copy has no body.
	v := *r
	u := *r.URL
	v.URL = &u
	v.Body = http.NoBody

	_, err := h.verifier.Verify(&v)
	outcome := samesame.OutcomeOf(err).String()

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("web_bot_auth.outcome", outcome)

	// Unsigned requests are most traffic, so only signed ones are logged.
	if !errors.Is(err, samesame.ErrNoSignature) {
		h.logger.Debug("checked signature", zap.String("outcome", outcome))
	}

	return next.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
