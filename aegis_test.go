package aegis

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/TecharoHQ/samesame"
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

func TestNextHandlerSeesUnchangedURL(t *testing.T) {
	agent := newAgent(t)
	s := serve(t, `
	web_bot_auth
	templates
	respond "{{.Req.URL}}"`)

	if got := s.send(t, sign(t, agent, get(t, s.url+"/path?q=1"))); got != "/path?q=1" {
		t.Errorf("next handler saw URL %q, want /path?q=1", got)
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
