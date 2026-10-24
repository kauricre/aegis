package aegis

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
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
	agent := newAgent(t)
	s := serve(t, `
	web_bot_auth`)

	signed := sign(t, agent, get(t, s.url))
	tampered := tamper(sign(t, agent, get(t, s.url)))
	for _, r := range []*http.Request{signed, get(t, s.url), tampered} {
		s.send(t, r)
	}

	logs := s.logs(t)
	var got []string
	for line := range strings.Lines(logs) {
		var entry struct{ Level, Outcome string }
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		got = append(got, entry.Level+" "+entry.Outcome)
	}
	if want := []string{"debug verified", "debug invalid"}; !slices.Equal(got, want) {
		t.Errorf("log entries = %q, want %q", got, want)
	}

	for _, r := range []*http.Request{signed, tampered} {
		if sig := signature(r); strings.Contains(logs, sig) {
			t.Errorf("log contains the signature %s", sig)
		}
	}
}
