package aegis

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
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
	}{
		// Without settings, every option keeps samesame's default.
		{"no settings", "", `{}`, samesame.FetcherOptions{}, samesame.VerifierOptions{}},
		{
			"allowed_hosts", "allowed_hosts a.example b.example:8443", `{"allowed_hosts":["a.example","b.example:8443"]}`,
			samesame.FetcherOptions{AllowedHosts: []string{"a.example", "b.example:8443"}}, samesame.VerifierOptions{},
		},
		{
			"allowed_hosts on two lines", "allowed_hosts a.example\nallowed_hosts b.example", `{"allowed_hosts":["a.example","b.example"]}`,
			samesame.FetcherOptions{AllowedHosts: []string{"a.example", "b.example"}}, samesame.VerifierOptions{},
		},
		{
			"fetch_timeout", "fetch_timeout 3s", `{"fetch_timeout":3000000000}`,
			samesame.FetcherOptions{Timeout: 3 * time.Second}, samesame.VerifierOptions{},
		},
		{
			"ttl", "ttl 2h", `{"ttl":7200000000000}`,
			samesame.FetcherOptions{TTL: 2 * time.Hour}, samesame.VerifierOptions{},
		},
		{
			"min_ttl", "min_ttl 5m", `{"min_ttl":300000000000}`,
			samesame.FetcherOptions{MinTTL: 5 * time.Minute}, samesame.VerifierOptions{},
		},
		{
			"max_ttl", "max_ttl 12h", `{"max_ttl":43200000000000}`,
			samesame.FetcherOptions{MaxTTL: 12 * time.Hour}, samesame.VerifierOptions{},
		},
		{
			"negative_ttl", "negative_ttl 1m", `{"negative_ttl":60000000000}`,
			samesame.FetcherOptions{NegativeTTL: time.Minute}, samesame.VerifierOptions{},
		},
		{
			"max_directory_size", "max_directory_size 32KiB", `{"max_directory_size":32768}`,
			samesame.FetcherOptions{MaxBodySize: 32768}, samesame.VerifierOptions{},
		},
		{
			"max_cache_entries", "max_cache_entries 500", `{"max_cache_entries":500}`,
			samesame.FetcherOptions{MaxCacheEntries: 500}, samesame.VerifierOptions{},
		},
		{
			"max_concurrent_fetches", "max_concurrent_fetches 8", `{"max_concurrent_fetches":8}`,
			samesame.FetcherOptions{MaxConcurrentFetches: 8}, samesame.VerifierOptions{},
		},
		{
			"max_validity", "max_validity 1h", `{"max_validity":3600000000000}`,
			samesame.FetcherOptions{}, samesame.VerifierOptions{MaxValidity: time.Hour},
		},
		{
			"clock_skew", "clock_skew 30s", `{"clock_skew":30000000000}`,
			samesame.FetcherOptions{}, samesame.VerifierOptions{ClockSkew: 30 * time.Second},
		},
		{
			"max_signatures", "max_signatures 2", `{"max_signatures":2}`,
			samesame.FetcherOptions{}, samesame.VerifierOptions{MaxSignatures: 2},
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
			fetcher, verifier, _ := decoded.options()
			if !reflect.DeepEqual(fetcher, tc.fetcher) {
				t.Errorf("fetcher options = %+v, want %+v", fetcher, tc.fetcher)
			}
			if !reflect.DeepEqual(verifier, tc.verifier) {
				t.Errorf("verifier options = %+v, want %+v", verifier, tc.verifier)
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
		"max_cache_entries", "max_concurrent_fetches", "max_validity", "clock_skew", "max_signatures",
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
