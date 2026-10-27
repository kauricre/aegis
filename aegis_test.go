package aegis

import (
	"cmp"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TecharoHQ/samesame"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestRouteByOutcome(t *testing.T) {
	agent := newAgent(t)
	s := serve(t, `
	web_bot_auth

	@verified vars {web_bot_auth.outcome} verified
	handle @verified {
		respond "verified route: {web_bot_auth.outcome}"
	}
	handle {
		respond "other route: {web_bot_auth.outcome}"
	}`)

	for _, tc := range []struct {
		name string
		req  *http.Request
		want string
	}{
		{"signed request", sign(t, agent, get(t, s.url)), "verified route: verified"},
		{"unsigned request", get(t, s.url), "other route: unverified"},
		{"tampered signature", tamper(sign(t, agent, get(t, s.url))), "other route: invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// respond runs after web_bot_auth, so any reply shows that the
			// request reached the next handler.
			if got := s.send(t, tc.req); got != tc.want {
				t.Errorf("response = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPlaceholders(t *testing.T) {
	agent, other := newAgent(t), newAgent(t)
	s := serve(t, `
	web_bot_auth
	respond "outcome={web_bot_auth.outcome} signed={web_bot_auth.signed} reason={web_bot_auth.reason} agent={web_bot_auth.agent} keyid={web_bot_auth.keyid} label={web_bot_auth.label}"`)

	for _, tc := range []struct {
		name string
		req  *http.Request
		want string
	}{
		{
			"verified request", sign(t, agent, get(t, s.url)),
			"outcome=verified signed=true reason= agent=" + agent.directory + " keyid=" + agent.KeyID() + " label=sig1",
		},
		{
			"invalid request", tamper(sign(t, agent, get(t, s.url))),
			"outcome=invalid signed=true reason=bad_signature agent= keyid= label=",
		},
		{
			"unverified signed request", claim(sign(t, agent, get(t, s.url)), other),
			"outcome=unverified signed=true reason=key_unknown agent= keyid= label=",
		},
		{
			"unsigned request", get(t, s.url),
			"outcome=unverified signed=false reason=no_signature agent= keyid= label=",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.send(t, tc.req); got != tc.want {
				t.Errorf("response = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReasonOf(t *testing.T) {
	if got := reasonOf(nil); got != "" {
		t.Errorf("reasonOf(nil) = %q, want empty", got)
	}

	for _, tc := range []struct {
		err  error
		want string
	}{
		{samesame.ErrNoSignature, "no_signature"},
		{samesame.ErrMalformedSignature, "malformed"},
		{samesame.ErrMalformedSignatureAgent, "malformed"},
		{samesame.ErrInsecureTransport, "insecure_transport"},
		{samesame.ErrProfile, "profile"},
		{samesame.ErrNotYetValid, "not_yet_valid"},
		{samesame.ErrExpired, "expired"},
		{samesame.ErrValidityTooLong, "validity_too_long"},
		{samesame.ErrBadSignature, "bad_signature"},
		{samesame.ErrKeyUnknown, "key_unknown"},
		{samesame.ErrDiscovery, "discovery_failed"},
		{samesame.ErrNonceRequired, "nonce_required"},
		{samesame.ErrReplay, "replay"},
		{samesame.ErrNonceStore, "nonce_store"},
		{samesame.ErrTooManySignatures, "too_many_signatures"},
		{errors.New("samesame: an error added after v1.0.0"), "other"},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			// samesame returns each error in a VerifyError, most of them
			// wrapped with details.
			err := &samesame.VerifyError{Outcome: samesame.OutcomeInvalid, Err: fmt.Errorf("%w: details", tc.err)}
			if got := reasonOf(err); got != tc.want {
				t.Errorf("reasonOf = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestModes(t *testing.T) {
	agent, other := newAgent(t), newAgent(t)
	const challenge = `403 Accept-Signature: sig1=("@authority" "signature-agent";key="sig1");created;expires;tag="web-bot-auth"`

	// What each mode does with each kind of request: pass it on to the next
	// handler, block it with a status code, or block it with a challenge. The
	// invalid request has a bad signature, for which samesame suggests 403.
	for _, tc := range []struct {
		settings                                string
		verified, invalid, unverified, unsigned string
	}{
		{"", "pass", "pass", "pass", "pass"},
		{"mode observe", "pass", "pass", "pass", "pass"},
		{"mode enforce", "pass", "403", "pass", "pass"},
		{"mode require", "pass", "403", challenge, challenge},
	} {
		t.Run(cmp.Or(tc.settings, "no settings"), func(t *testing.T) {
			s := serve(t, `
	web_bot_auth {
		`+tc.settings+`
	}
	respond "next handler"`)

			for _, req := range []struct {
				name string
				r    *http.Request
				want string
			}{
				{"verified", sign(t, agent, get(t, s.url)), tc.verified},
				{"invalid", tamper(sign(t, agent, get(t, s.url))), tc.invalid},
				{"unverified signed", claim(sign(t, agent, get(t, s.url)), other), tc.unverified},
				{"unsigned", get(t, s.url), tc.unsigned},
			} {
				t.Run(req.name, func(t *testing.T) {
					resp, body := s.do(t, req.r)
					got := strconv.Itoa(resp.StatusCode)
					if body == "next handler" {
						got = "pass"
					}
					if v := resp.Header.Get("Accept-Signature"); v != "" {
						got += " Accept-Signature: " + v
					}
					if got != req.want {
						t.Errorf("response = %q, want %q", got, req.want)
					}
				})
			}
		})
	}
}

func TestBlockedInvalidRequestStatus(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{samesame.ErrMalformedSignature, http.StatusBadRequest},
		{samesame.ErrMalformedSignatureAgent, http.StatusBadRequest},
		{samesame.ErrReplay, http.StatusTooManyRequests},
		{samesame.ErrBadSignature, http.StatusForbidden},
	} {
		// samesame returns each error in a VerifyError, most of them wrapped
		// with details.
		err := &samesame.VerifyError{Outcome: samesame.OutcomeInvalid, Err: fmt.Errorf("%w: details", tc.err)}
		for _, mode := range []string{"enforce", "require"} {
			t.Run(mode+" "+tc.err.Error(), func(t *testing.T) {
				status, challenge := blockStatus(mode, err)
				if status != tc.want || challenge {
					t.Errorf("blockStatus = %d, challenge %t; want %d without a challenge", status, challenge, tc.want)
				}
			})
		}
	}
}

func TestRouteByAgent(t *testing.T) {
	agent, other := newAgent(t), newAgent(t)
	s := serve(t, `
	web_bot_auth

	@agent vars {web_bot_auth.agent} `+agent.directory+`
	handle @agent {
		respond "agent route"
	}
	handle {
		respond "other route"
	}`)

	for _, tc := range []struct {
		name string
		req  *http.Request
		want string
	}{
		{"signed by the agent", sign(t, agent, get(t, s.url)), "agent route"},
		{"signed by another agent", sign(t, other, get(t, s.url)), "other route"},
		{"another agent claiming to be the agent", claim(sign(t, other, get(t, s.url)), agent), "other route"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.send(t, tc.req); got != tc.want {
				t.Errorf("response = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSignatureSurvivesRewrites(t *testing.T) {
	agent := newAgent(t)
	for _, tc := range []struct {
		name, directives string
	}{
		{"nothing before the module", `
	web_bot_auth
	respond "{web_bot_auth.outcome}"`},
		{"method", `
	route {
		method POST
		web_bot_auth
		respond "{web_bot_auth.outcome}"
	}`},
		{"rewrite", `
	route {
		rewrite * /rewritten?x=1
		web_bot_auth
		respond "{web_bot_auth.outcome}"
	}`},
		{"uri", `
	route {
		uri strip_prefix /prefix
		web_bot_auth
		respond "{web_bot_auth.outcome}"
	}`},
		{"handle_path", `
	handle_path /prefix/* {
		web_bot_auth
		respond "{web_bot_auth.outcome}"
	}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := serve(t, tc.directives)
			r := signMethodAndURL(t, agent, get(t, s.url+"/prefix/path?q=1"))
			if got := s.send(t, r); got != "verified" {
				t.Errorf("outcome = %q, want verified", got)
			}
		})
	}
}

func TestHeaderChangeBeforeModuleBreaksSignature(t *testing.T) {
	agent := newAgent(t)
	// samesame accepts only signatures that cover @authority or @target-uri,
	// and both include the Host header.
	s := serve(t, `
	route {
		request_header Host example.com
		web_bot_auth
		respond "{web_bot_auth.outcome} {web_bot_auth.reason}"
	}`)

	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "invalid bad_signature" {
		t.Errorf("response = %q, want %q", got, "invalid bad_signature")
	}
}

func TestNextHandlerSeesUnchangedURL(t *testing.T) {
	agent := newAgent(t)
	s := serve(t, `
	web_bot_auth
	templates
	respond "{{.Req.URL}} {{.OriginalReq.URL}}"`)

	// OriginalReq is Caddy's stored copy of the request as it arrived.
	if got := s.send(t, sign(t, agent, get(t, s.url+"/path?q=1"))); got != "/path?q=1 /path?q=1" {
		t.Errorf("next handler saw URL and original URL %q, want /path?q=1 /path?q=1", got)
	}
}

func TestRequestReachesUpstreamUnchanged(t *testing.T) {
	agent := newAgent(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	}))
	t.Cleanup(upstream.Close)
	s := serve(t, `
	web_bot_auth
	reverse_proxy `+upstream.Listener.Addr().String())

	// A signature that covers a trailer field makes httpsign, samesame's
	// signature engine, read the whole request body while it verifies.
	trailer := sign(t, agent, post(t, s.url, "hello"))
	in := trailer.Header.Get("Signature-Input")
	trailer.Header.Set("Signature-Input", strings.Replace(in, `"@authority"`, `"@authority" "x-trailer";tr`, 1))

	for _, tc := range []struct {
		name string
		req  *http.Request
	}{
		{"signed request", sign(t, agent, post(t, s.url, "hello"))},
		{"signature covering a trailer", trailer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.send(t, tc.req); got != "hello" {
				t.Errorf("upstream echoed %q, want hello", got)
			}
		})
	}
}

func TestLogsSignedRequestsAtDebug(t *testing.T) {
	agent, other := newAgent(t), newAgent(t)
	s := serve(t, `
	web_bot_auth`)

	signed := sign(t, agent, get(t, s.url))
	tampered := tamper(sign(t, agent, get(t, s.url)))
	unverified := claim(sign(t, agent, get(t, s.url)), other)
	for _, r := range []*http.Request{signed, get(t, s.url), tampered, unverified} {
		s.send(t, r)
	}

	type logEntry struct {
		Level, Outcome, Reason, Agent, KeyID, Label string
		Signed                                      bool
		RemoteIP                                    string `json:"remote_ip"`
	}
	logs := s.logs(t)
	var got []logEntry
	for line := range strings.Lines(logs) {
		var entry logEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		got = append(got, entry)
	}
	// Every line is at debug, so the unverified request's Signature-Agent
	// value, which the client controls, can appear only at debug.
	want := []logEntry{
		{"debug", "verified", "", agent.directory, agent.KeyID(), "sig1", true, "127.0.0.1"},
		{"debug", "invalid", "bad_signature", "", "", "", true, "127.0.0.1"},
		{"debug", "unverified", "key_unknown", "", "", "", true, "127.0.0.1"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("log entries = %+v, want %+v", got, want)
	}

	for _, r := range []*http.Request{signed, tampered, unverified} {
		if sig := signature(r); strings.Contains(logs, sig) {
			t.Errorf("log contains the signature %s", sig)
		}
	}
}

func TestSettingsReachSamesame(t *testing.T) {
	for _, tc := range []struct {
		name, settings, json string
		fetcher              samesame.FetcherOptions
		verifier             samesame.VerifierOptions
		nonceStoreSize       int
	}{
		// Without settings, every option keeps samesame's default.
		{"no settings", "", `{}`, samesame.FetcherOptions{}, samesame.VerifierOptions{}, 0},
		{
			"allowed_hosts", "allowed_hosts a.example b.example:8443", `{"allowed_hosts":["a.example","b.example:8443"]}`,
			samesame.FetcherOptions{AllowedHosts: []string{"a.example", "b.example:8443"}}, samesame.VerifierOptions{}, 0,
		},
		{
			"allowed_hosts on two lines", "allowed_hosts a.example\nallowed_hosts b.example", `{"allowed_hosts":["a.example","b.example"]}`,
			samesame.FetcherOptions{AllowedHosts: []string{"a.example", "b.example"}}, samesame.VerifierOptions{}, 0,
		},
		{
			"fetch_timeout", "fetch_timeout 3s", `{"fetch_timeout":3000000000}`,
			samesame.FetcherOptions{Timeout: 3 * time.Second}, samesame.VerifierOptions{}, 0,
		},
		{
			"ttl", "ttl 2h", `{"ttl":7200000000000}`,
			samesame.FetcherOptions{TTL: 2 * time.Hour}, samesame.VerifierOptions{}, 0,
		},
		{
			"min_ttl", "min_ttl 5m", `{"min_ttl":300000000000}`,
			samesame.FetcherOptions{MinTTL: 5 * time.Minute}, samesame.VerifierOptions{}, 0,
		},
		{
			"max_ttl", "max_ttl 12h", `{"max_ttl":43200000000000}`,
			samesame.FetcherOptions{MaxTTL: 12 * time.Hour}, samesame.VerifierOptions{}, 0,
		},
		{
			"negative_ttl", "negative_ttl 1m", `{"negative_ttl":60000000000}`,
			samesame.FetcherOptions{NegativeTTL: time.Minute}, samesame.VerifierOptions{}, 0,
		},
		{
			"max_directory_size", "max_directory_size 32KiB", `{"max_directory_size":32768}`,
			samesame.FetcherOptions{MaxBodySize: 32768}, samesame.VerifierOptions{}, 0,
		},
		{
			"max_cache_entries", "max_cache_entries 500", `{"max_cache_entries":500}`,
			samesame.FetcherOptions{MaxCacheEntries: 500}, samesame.VerifierOptions{}, 0,
		},
		{
			"max_concurrent_fetches", "max_concurrent_fetches 8", `{"max_concurrent_fetches":8}`,
			samesame.FetcherOptions{MaxConcurrentFetches: 8}, samesame.VerifierOptions{}, 0,
		},
		{
			"max_validity", "max_validity 1h", `{"max_validity":3600000000000}`,
			samesame.FetcherOptions{}, samesame.VerifierOptions{MaxValidity: time.Hour}, 0,
		},
		{
			"clock_skew", "clock_skew 30s", `{"clock_skew":30000000000}`,
			samesame.FetcherOptions{}, samesame.VerifierOptions{ClockSkew: 30 * time.Second}, 0,
		},
		{
			"max_signatures", "max_signatures 2", `{"max_signatures":2}`,
			samesame.FetcherOptions{}, samesame.VerifierOptions{MaxSignatures: 2}, 0,
		},
		{
			"max_nonces", "max_nonces 1000", `{"max_nonces":1000}`,
			samesame.FetcherOptions{}, samesame.VerifierOptions{}, 1000,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var h Handler
			if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser("web_bot_auth {\n" + tc.settings + "\n}")); err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(h)
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != tc.json {
				t.Errorf("JSON = %s, want %s", b, tc.json)
			}

			// Caddy decodes the JSON of each module this way when it loads a
			// config.
			var decoded Handler
			if err := caddy.StrictUnmarshalJSON(b, &decoded); err != nil {
				t.Fatal(err)
			}
			fetcher, verifier, nonceStoreSize := decoded.options()
			if !reflect.DeepEqual(fetcher, tc.fetcher) {
				t.Errorf("fetcher options = %+v, want %+v", fetcher, tc.fetcher)
			}
			if !reflect.DeepEqual(verifier, tc.verifier) {
				t.Errorf("verifier options = %+v, want %+v", verifier, tc.verifier)
			}
			if nonceStoreSize != tc.nonceStoreSize {
				t.Errorf("nonce store size = %d, want %d", nonceStoreSize, tc.nonceStoreSize)
			}
		})
	}
}

func TestConfigCannotReachUnsafeOptions(t *testing.T) {
	// samesame's options that turn off its protections, named as a setting
	// for them would be.
	for _, name := range []string{"allow_private_addresses", "tls_config", "allow_test_keys", "allow_insecure"} {
		t.Run(name, func(t *testing.T) {
			var h Handler
			if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser("web_bot_auth {\n" + name + " true\n}")); err == nil {
				t.Error("the Caddyfile accepts it")
			}
			if err := caddy.StrictUnmarshalJSON([]byte(`{"`+name+`":true}`), &h); err == nil {
				t.Error("JSON accepts it")
			}
		})
	}
}

func TestValidate(t *testing.T) {
	type row struct{ json, wantErr string }
	var rows []row
	for _, name := range []string{
		"fetch_timeout", "max_directory_size", "ttl", "min_ttl", "max_ttl", "negative_ttl",
		"max_cache_entries", "max_concurrent_fetches", "max_validity", "clock_skew", "max_signatures", "max_nonces",
	} {
		for _, v := range []string{"0", "-1"} {
			rows = append(rows, row{`{"` + name + `":` + v + `}`, name + " must be positive"})
		}
	}
	rows = append(rows,
		row{`{}`, ""},
		row{`{"mode":"observe"}`, ""},
		row{`{"mode":"enforce"}`, ""},
		row{`{"mode":"require"}`, ""},
		row{`{"mode":"block"}`, `mode must be observe, enforce or require, not "block"`},
		row{`{"min_ttl":"1h","max_ttl":"1h"}`, ""},
		row{`{"min_ttl":"2h","max_ttl":"1h"}`, "min_ttl 2h0m0s is greater than max_ttl 1h0m0s"},
		// samesame's defaults are a min_ttl of 1m and a max_ttl of 24h.
		row{`{"min_ttl":"1d"}`, ""},
		row{`{"min_ttl":"2d"}`, "min_ttl 48h0m0s is greater than samesame's default max_ttl 24h0m0s"},
		row{`{"max_ttl":"1m"}`, ""},
		row{`{"max_ttl":"30s"}`, "samesame's default min_ttl 1m0s is greater than max_ttl 30s"},
	)

	for _, tc := range rows {
		t.Run(tc.json, func(t *testing.T) {
			var h Handler
			if err := caddy.StrictUnmarshalJSON([]byte(tc.json), &h); err != nil {
				t.Fatal(err)
			}
			var got string
			if err := h.Validate(); err != nil {
				got = err.Error()
			}
			if got != tc.wantErr {
				t.Errorf("Validate error = %q, want %q", got, tc.wantErr)
			}
		})
	}
}

func TestInvalidSettingFailsConfigLoad(t *testing.T) {
	for _, tc := range []struct{ setting, wantErr string }{
		{"fetch_timeout 0", "fetch_timeout must be positive"},
		{"max_concurrent_fetches -1", "max_concurrent_fetches must be positive"},
		{"mode block", `mode must be observe, enforce or require, not "block"`},
	} {
		t.Run(tc.setting, func(t *testing.T) {
			adapted, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(`{
	storage file_system `+t.TempDir()+`
}

http://127.0.0.1 {
	web_bot_auth {
		`+tc.setting+`
	}
}
`), nil)
			if err != nil {
				t.Fatal(err)
			}
			var cfg caddy.Config
			if err := json.Unmarshal(adapted, &cfg); err != nil {
				t.Fatal(err)
			}

			// Validate provisions and validates the config as loading it
			// does, but does not start it.
			if err := caddy.Validate(&cfg); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Validate error = %v, want one that says %s", err, tc.wantErr)
			}
		})
	}
}

func TestAllowedHosts(t *testing.T) {
	listed, unlisted := newAgent(t), newAgent(t)
	u, err := url.Parse(listed.directory)
	if err != nil {
		t.Fatal(err)
	}
	s := serve(t, `
	web_bot_auth {
		allowed_hosts `+u.Host+`
	}
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)

	for _, tc := range []struct {
		name  string
		agent testAgent
		want  string
	}{
		{"agent on a listed host", listed, "verified "},
		{"agent on an unlisted host", unlisted, "unverified discovery_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.send(t, sign(t, tc.agent, get(t, s.url))); got != tc.want {
				t.Errorf("response = %q, want %q", got, tc.want)
			}
		})
	}
	if n := unlisted.requests.Load(); n != 0 {
		t.Errorf("the unlisted agent's key directory server got %d requests, want 0", n)
	}
}

func TestMaxValidity(t *testing.T) {
	agent := newAgent(t)
	s := serve(t, `
	web_bot_auth {
		max_validity 30m
	}
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)

	// samesame's signer makes signatures valid for an hour.
	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "invalid validity_too_long" {
		t.Errorf("response = %q, want %q", got, "invalid validity_too_long")
	}
}

func TestReplay(t *testing.T) {
	agent := newAgent(t)
	s := serve(t, `
	web_bot_auth
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)

	for _, tc := range []struct {
		name          string
		req           *http.Request
		first, second string
	}{
		// samesame's signer puts a random nonce into every signature.
		{"signature with a nonce", sign(t, agent, get(t, s.url)), "verified ", "invalid replay"},
		{"signature without a nonce", signWithoutNonce(t, agent, get(t, s.url)), "verified ", "verified "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.send(t, tc.req); got != tc.first {
				t.Errorf("response = %q, want %q", got, tc.first)
			}
			if got := s.send(t, tc.req); got != tc.second {
				t.Errorf("response to the same request sent again = %q, want %q", got, tc.second)
			}
		})
	}
}

func TestMaxNonces(t *testing.T) {
	agent := newAgent(t)
	s := serve(t, `
	web_bot_auth {
		max_nonces 1
	}
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)

	first, second := sign(t, agent, get(t, s.url)), sign(t, agent, get(t, s.url))
	for _, step := range []struct {
		name string
		req  *http.Request
		want string
	}{
		{"first request", first, "verified "},
		{"second request", second, "verified "},
		{"second request sent again", second, "invalid replay"},
		// The store holds one nonce, so remembering the second request's
		// nonce made it forget the first's.
		{"first request sent again", first, "verified "},
	} {
		if got := s.send(t, step.req); got != step.want {
			t.Errorf("%s: response = %q, want %q", step.name, got, step.want)
		}
	}
}

func TestIdentityHeader(t *testing.T) {
	agent, other := newAgent(t), newAgent(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%q", slices.Concat(r.Header.Values("Web-Bot-Auth-Agent"), r.Header.Values("Web.Bot.Auth.Agent")))
	}))
	t.Cleanup(upstream.Close)
	addr := upstream.Listener.Addr().String()

	// The values of the header that the upstream receives from each kind of
	// request. Every request also carries two copies of the header from the
	// client, which claim to be the other agent: one as Web-Bot-Auth-Agent,
	// and one as Web.Bot.Auth.Agent, which PHP reads as the same header and
	// which Caddy v2.11.4 passes upstream.
	verified, claimed, none := fmt.Sprintf("[%q]", agent.directory), fmt.Sprintf("[%q %q]", other.directory, other.directory), "[]"
	for _, tc := range []struct {
		name, directives                        string
		verified, invalid, unverified, unsigned string
	}{
		{"identity_header", `
	web_bot_auth {
		identity_header Web-Bot-Auth-Agent
	}
	reverse_proxy ` + addr, verified, none, none, none},
		{"no identity_header", `
	web_bot_auth
	reverse_proxy ` + addr, claimed, claimed, claimed, claimed},
		{"identity_header with blocked requests sent upstream by handle_errors", `
	web_bot_auth {
		mode require
		identity_header Web-Bot-Auth-Agent
	}
	reverse_proxy ` + addr + `
	handle_errors {
		reverse_proxy ` + addr + `
	}`, verified, none, none, none},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := serve(t, tc.directives)

			for _, req := range []struct {
				name string
				r    *http.Request
				want string
			}{
				{"verified", sign(t, agent, get(t, s.url)), tc.verified},
				{"invalid", tamper(sign(t, agent, get(t, s.url))), tc.invalid},
				{"unverified signed", claim(sign(t, agent, get(t, s.url)), other), tc.unverified},
				{"unsigned", get(t, s.url), tc.unsigned},
			} {
				t.Run(req.name, func(t *testing.T) {
					req.r.Header.Set("Web-Bot-Auth-Agent", other.directory)
					req.r.Header.Set("Web.Bot.Auth.Agent", other.directory)
					if got := s.send(t, req.r); got != req.want {
						t.Errorf("upstream received %s, want %s", got, req.want)
					}
				})
			}
		})
	}
}

// TestIdentityHeaderThroughFastCGI checks the identity header that a FastCGI
// app, such as a PHP app behind php_fastcgi, receives. FastCGI passes headers
// as CGI variables, which turn '-' into '_', so a client's Web-Bot-Auth-Agent
// and the module's Web_Bot_Auth_Agent both become HTTP_WEB_BOT_AUTH_AGENT.
func TestIdentityHeaderThroughFastCGI(t *testing.T) {
	agent, other := newAgent(t), newAgent(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	// Go's FastCGI server turns HTTP_WEB_BOT_AUTH_AGENT back into the
	// Web-Bot-Auth-Agent header.
	go func() {
		_ = fcgi.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintf(w, "%q", r.Header.Values("Web-Bot-Auth-Agent"))
		}))
	}()
	s := serve(t, `
	web_bot_auth {
		identity_header Web_Bot_Auth_Agent
	}
	reverse_proxy `+l.Addr().String()+` {
		transport fastcgi
	}`)

	verified, none := fmt.Sprintf("[%q]", agent.directory), "[]"
	for _, req := range []struct {
		name string
		r    *http.Request
		want string
	}{
		{"verified", sign(t, agent, get(t, s.url)), verified},
		{"invalid", tamper(sign(t, agent, get(t, s.url))), none},
		{"unverified signed", claim(sign(t, agent, get(t, s.url)), other), none},
		{"unsigned", get(t, s.url), none},
	} {
		t.Run(req.name, func(t *testing.T) {
			req.r.Header.Set("Web-Bot-Auth-Agent", other.directory)
			if got := s.send(t, req.r); got != req.want {
				t.Errorf("FastCGI app received %s, want %s", got, req.want)
			}
		})
	}
}

// trustLoopback makes Caddy trust the test client as a proxy, so the client
// plays a front server that ends TLS and sends plain HTTP to Caddy.
const trustLoopback = `servers {
		trusted_proxies static 127.0.0.1/32
	}`

func TestSchemeFromTrustedProxies(t *testing.T) {
	agent := newAgent(t)

	type request struct {
		name  string
		proto []string // the request's X-Forwarded-Proto lines, in order
		want  string
	}
	for _, tc := range []struct {
		name, scheme, global string
		requests             []request
	}{
		{"plain HTTP from a trusted proxy", "http", trustLoopback, []request{
			{"https", []string{"https"}, "verified "},
			{"http", []string{"http"}, "invalid insecure_transport"},
			{"wss", []string{"wss"}, "verified "},
			{"http, then https", []string{"http", "https"}, "verified "},
			{"https, then http", []string{"https", "http"}, "invalid insecure_transport"},
			// The last line decides as a whole, as in Caddy's reverse_proxy.
			{"http, https on one line", []string{"http, https"}, "invalid insecure_transport"},
		}},
		{"plain HTTP from a peer not in trusted_proxies", "http", "", []request{
			{"https", []string{"https"}, "invalid insecure_transport"},
		}},
		{"HTTPS", "https", "", []request{
			{"no X-Forwarded-Proto", nil, "verified "},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := serveSite(t, tc.scheme, tc.global, `
	web_bot_auth
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)

			for _, req := range tc.requests {
				t.Run(req.name, func(t *testing.T) {
					r := sign(t, agent, get(t, s.url))
					for _, v := range req.proto {
						r.Header.Add("X-Forwarded-Proto", v)
					}
					if got := s.send(t, r); got != req.want {
						t.Errorf("response = %q, want %q", got, req.want)
					}
				})
			}
		})
	}
}

func TestInsecureTransportWarning(t *testing.T) {
	agent := newAgent(t)
	for _, tc := range []struct {
		name  string
		proto []string // the requests' X-Forwarded-Proto lines
		want  string
	}{
		{
			"X-Forwarded-Proto from a peer not in trusted_proxies", []string{"https"},
			"signed request over plain HTTP got insecure_transport: X-Forwarded-Proto was ignored because the peer is not a trusted proxy; add the front server to trusted_proxies, or set trusted_proxies_unix for a Unix socket",
		},
		{
			"no X-Forwarded-Proto", nil,
			"signed request over plain HTTP got insecure_transport: signatures need HTTPS; behind a front server that ends TLS, use re-encryption, or send X-Forwarded-Proto from a front server that Caddy trusts as a proxy (trusted_proxies, or trusted_proxies_unix for a Unix socket)",
		},
	} {
		// Each subtest loads a new config, after which the module warns again.
		t.Run(tc.name, func(t *testing.T) {
			s := serveSite(t, "http", "", `
	web_bot_auth
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)

			for range 2 {
				r := sign(t, agent, get(t, s.url))
				for _, v := range tc.proto {
					r.Header.Add("X-Forwarded-Proto", v)
				}
				if got := s.send(t, r); got != "invalid insecure_transport" {
					t.Errorf("response = %q, want %q", got, "invalid insecure_transport")
				}
			}

			type logEntry struct {
				Level, Msg string
				RemoteIP   string `json:"remote_ip"`
			}
			var got []logEntry
			for line := range strings.Lines(s.logs(t)) {
				var entry logEntry
				if err := json.Unmarshal([]byte(line), &entry); err != nil {
					t.Fatal(err)
				}
				if entry.Level == "warn" {
					got = append(got, entry)
				}
			}
			if want := []logEntry{{"warn", tc.want, "127.0.0.1"}}; !slices.Equal(got, want) {
				t.Errorf("warnings = %+v, want %+v", got, want)
			}
		})
	}
}

func TestReencryptingFrontServer(t *testing.T) {
	agent := newAgent(t)
	s := serve(t, `
	web_bot_auth
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)

	// The front server ends the client's TLS and opens its own TLS connection
	// to Caddy, keeping Host, which the signature covers.
	target, err := url.Parse(s.url)
	if err != nil {
		t.Fatal(err)
	}
	_, pool := localTLS()
	front := httptest.NewTLSServer(&httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host
		},
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	})
	t.Cleanup(front.Close)

	if got := s.send(t, sign(t, agent, get(t, front.URL))); got != "verified " {
		t.Errorf("response = %q, want %q", got, "verified ")
	}
}

func TestXForwardedHostIsIgnored(t *testing.T) {
	agent := newAgent(t)
	s := serveSite(t, "http", trustLoopback, `
	web_bot_auth
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)

	// A trusted front server that replaced Host moved the host the agent
	// signed to X-Forwarded-Host.
	r := get(t, s.url)
	r.Host = "example.com"
	sign(t, agent, r)
	r.Host = ""
	r.Header.Set("X-Forwarded-Host", "example.com")
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := s.send(t, r); got != "invalid bad_signature" {
		t.Errorf("response = %q, want %q", got, "invalid bad_signature")
	}
}

func TestKeyDirectoriesAndNoncesAcrossReloads(t *testing.T) {
	agent := newAgent(t)
	const respond = `
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`
	s := serve(t, `
	web_bot_auth`+respond)

	// samesame's signer puts a random nonce into every signature.
	r := sign(t, agent, get(t, s.url))
	if got := s.send(t, r); got != "verified " {
		t.Errorf("response = %q, want %q", got, "verified ")
	}

	// Each step reloads the config and sends r again. A kept nonce store still
	// remembers r's nonce, and a kept key cache needs no new download of the
	// agent's key directory.
	for _, step := range []struct {
		name, directives string
		want             string
		downloads        int64 // since the test started
	}{
		{"another directive changed", `
	web_bot_auth
	respond "reloaded: {web_bot_auth.outcome} {web_bot_auth.reason}"`, "reloaded: invalid replay", 1},
		{"a key discovery setting changed", `
	web_bot_auth {
		fetch_timeout 3s
	}` + respond, "invalid replay", 2},
		{"max_nonces changed", `
	web_bot_auth {
		fetch_timeout 3s
		max_nonces 1000
	}` + respond, "verified ", 2},
		// No loaded config uses the first settings any more, so their key
		// cache and nonce store are gone.
		{"the first settings again", `
	web_bot_auth` + respond, "verified ", 3},
	} {
		s.load(t, step.directives)
		if got := s.send(t, r); got != step.want {
			t.Errorf("%s: response = %q, want %q", step.name, got, step.want)
		}
		if n := agent.requests.Load(); n != step.downloads {
			t.Errorf("%s: key directory downloads = %d, want %d", step.name, n, step.downloads)
		}
	}
}

func TestDirectivesShareNonces(t *testing.T) {
	agent := newAgent(t)
	for _, tc := range []struct {
		name, settings string // of the directive for /feed/
		replayedToFeed string // the response to a request to / replayed to /feed/
	}{
		{"same max_nonces", "", "429"},
		// Directives with different max_nonces remember separate nonces.
		{"different max_nonces", "max_nonces 1000", "feed: verified "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Requests to /feed/ pass both directives.
			s := serve(t, `
	web_bot_auth
	handle /feed/* {
		web_bot_auth {
			mode require
			`+tc.settings+`
		}
		respond "feed: {web_bot_auth.outcome} {web_bot_auth.reason}"
	}
	handle {
		respond "{web_bot_auth.outcome} {web_bot_auth.reason}"
	}`)

			feed := sign(t, agent, get(t, s.url+"/feed/x"))
			home := sign(t, agent, get(t, s.url))
			// samesame's signer covers only the host and Signature-Agent, so
			// the signature of home also verifies on /feed/.
			homeToFeed := get(t, s.url+"/feed/x")
			homeToFeed.Header = home.Header.Clone()

			for _, step := range []struct {
				name string
				req  *http.Request
				want string
			}{
				{"request checked by both directives", feed, "feed: verified "},
				{"the same request sent again", feed, "429"},
				{"request to another path", home, "verified "},
				{"that request replayed to /feed/", homeToFeed, tc.replayedToFeed},
			} {
				resp, body := s.do(t, step.req)
				got := body
				if resp.StatusCode != http.StatusOK {
					got = strconv.Itoa(resp.StatusCode)
				}
				if got != step.want {
					t.Errorf("%s: response = %q, want %q", step.name, got, step.want)
				}
			}
		})
	}
}

func TestParallelRequestsDuringReload(t *testing.T) {
	agent := newAgent(t)
	s := serve(t, `
	web_bot_auth
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)

	// samesame's signing transport gives every request a new signature and
	// nonce. The client speaks HTTP/2: a server that shuts down closes its
	// socket before it ends HTTP/2 connections, so no new connection waits on
	// the first config's socket when the reload closes it, which on Linux
	// resets such connections.
	_, pool := localTLS()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: agent.Transport(transport)}
	send := func() (string, error) {
		resp, err := client.Get(s.url)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}

	// The senders send requests until the test stops them. The test reloads
	// the config once the first config has answered a number of them, and
	// stops them once the reloaded config has answered as many, or once one
	// fails.
	const senders, answers = 8, 50
	var first, reloaded atomic.Int64
	firstAnswered, reloadedAnswered, failed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var failOnce sync.Once
	stop := make(chan struct{})
	var wg sync.WaitGroup
	defer wg.Wait()
	defer close(stop)
	for range senders {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				body, err := send()
				switch {
				case err == nil && body == "verified ":
					if first.Add(1) == answers {
						close(firstAnswered)
					}
				case err == nil && body == "reloaded: verified ":
					if reloaded.Add(1) == answers {
						close(reloadedAnswered)
					}
				default:
					t.Errorf("response = %q, error %v; want verified", body, err)
					failOnce.Do(func() { close(failed) })
					return
				}
			}
		})
	}

	select {
	case <-firstAnswered:
	case <-failed:
		return
	}
	// The new fetch_timeout gives the reloaded config a new key cache, while
	// both configs share the nonce store.
	s.load(t, `
	web_bot_auth {
		fetch_timeout 3s
	}
	respond "reloaded: {web_bot_auth.outcome} {web_bot_auth.reason}"`)
	select {
	case <-reloadedAnswered:
	case <-failed:
	}
}

func TestAbandonedRequestLeavesNoDownload(t *testing.T) {
	abandoned, next := newAgent(t), newAgent(t)
	// The held download cannot time out during the test, so the only request
	// that can get discovery_failed before release is the abandoned one.
	s := serve(t, `
	web_bot_auth {
		max_concurrent_fetches 1
		fetch_timeout 1m
	}
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)
	release := holdDownloadSlot(t, s, next)

	// The client disconnects as soon as it has sent the request, which waits
	// for the slot.
	_, pool := localTLS()
	conn, err := tls.Dial("tcp", strings.TrimPrefix(s.url, "https://"), &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	if err := sign(t, abandoned, get(t, s.url)).Write(conn); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	// web_bot_auth logs the request once the request stops waiting.
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(s.logs(t), `"reason":"discovery_failed"`) {
		if time.Now().After(deadline) {
			t.Fatal("web_bot_auth logged no outcome for the abandoned request")
		}
		time.Sleep(10 * time.Millisecond)
	}

	release()
	if got := s.send(t, sign(t, next, get(t, s.url))); got != "verified " {
		t.Errorf("response once the slot is free = %q, want %q", got, "verified ")
	}
	if n := abandoned.requests.Load(); n != 0 {
		t.Errorf("the abandoned agent's key directory server got %d requests, want 0", n)
	}
}

func TestRequestsWhileDownloadSlotIsBusy(t *testing.T) {
	cached, uncached := newAgent(t), newAgent(t)
	// The held download cannot time out during the test.
	s := serve(t, `
	web_bot_auth {
		max_concurrent_fetches 1
		fetch_timeout 1m
	}
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)
	if got := s.send(t, sign(t, cached, get(t, s.url))); got != "verified " {
		t.Fatalf("response = %q, want %q", got, "verified ")
	}
	release := holdDownloadSlot(t, s, cached)

	select {
	case got := <-sendInBackground(sign(t, cached, get(t, s.url))):
		if got != "verified " {
			t.Errorf("response from the cached agent = %q, want %q", got, "verified ")
		}
	case <-time.After(5 * time.Second):
		t.Error("the cached agent's request waited for the slot")
	}

	answered := sendInBackground(sign(t, uncached, get(t, s.url)))
	select {
	case got := <-answered:
		t.Fatalf("response from the new agent while the slot is busy = %q, want none yet", got)
	case <-time.After(300 * time.Millisecond):
	}
	release()
	if got := <-answered; got != "verified " {
		t.Errorf("response from the new agent once the slot is free = %q, want %q", got, "verified ")
	}
}

func TestReplacedKeyStopsVerifyingWhileDownloadSlotIsBusy(t *testing.T) {
	// The agent's key directory server serves the directory publish last set.
	srv := httptest.NewUnstartedServer(nil)
	authority := srv.Listener.Addr().String()
	var directory atomic.Value
	publish := func(key crypto.Signer) {
		t.Helper()
		h, err := samesame.NewDirectoryHandler([]crypto.Signer{key}, samesame.DirectoryHandlerOptions{Authorities: []string{authority}})
		if err != nil {
			t.Fatal(err)
		}
		directory.Store(h)
	}
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directory.Load().(http.Handler).ServeHTTP(w, r)
	})
	key, err := samesame.GenerateKey(samesame.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	publish(key)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	signer, err := samesame.NewSigner(key, samesame.SignerOptions{AgentOrigin: "https://" + authority})
	if err != nil {
		t.Fatal(err)
	}
	agent := testAgent{Signer: signer}

	s := serve(t, `
	web_bot_auth {
		max_concurrent_fetches 1
		min_ttl 500ms
		max_ttl 500ms
	}
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)
	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "verified " {
		t.Fatalf("response = %q, want %q", got, "verified ")
	}

	// The agent replaces its key, and the cached key directory goes stale.
	other, err := samesame.GenerateKey(samesame.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}
	publish(other)
	time.Sleep(600 * time.Millisecond)
	release := holdDownloadSlot(t, s, agent)

	answered := sendInBackground(sign(t, agent, get(t, s.url)))
	select {
	case got := <-answered:
		t.Fatalf("response while the slot is busy = %q, want none yet", got)
	case <-time.After(300 * time.Millisecond):
	}
	release()
	if got := <-answered; got != "unverified key_unknown" {
		t.Errorf("response with the replaced key = %q, want %q", got, "unverified key_unknown")
	}
}

// holdDownloadSlot sends a request signed by agent whose Signature-Agent
// names a key directory that answers only once release is called, and
// returns once the download of that directory has started. On a site with
// max_concurrent_fetches 1, the download holds the only slot until then.
func holdDownloadSlot(t *testing.T, s site, agent testAgent) (release func()) {
	t.Helper()
	started, unblock := make(chan struct{}), make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-unblock
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	release = sync.OnceFunc(func() { close(unblock) })
	t.Cleanup(release)

	answered := sendInBackground(claim(sign(t, agent, get(t, s.url)), testAgent{directory: srv.URL + samesame.WellKnownPath}))
	select {
	case <-started:
	case got := <-answered:
		t.Fatalf("response to the request that names the held key directory = %q, want none yet", got)
	}
	return release
}

// sendInBackground sends r as site.do does, from another goroutine, and
// returns a channel that receives the response body, or the error, once the
// request ends.
func sendInBackground(r *http.Request) <-chan string {
	answered := make(chan string, 1)
	go func() {
		_, pool := localTLS()
		client := &http.Client{Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: pool},
			DisableKeepAlives: true,
		}}
		resp, err := client.Do(r)
		if err != nil {
			answered <- err.Error()
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			answered <- err.Error()
			return
		}
		answered <- string(body)
	}()
	return answered
}
