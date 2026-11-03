package aegis

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(testStore{})
}

// testBackends holds the backends of the test nonce stores by name. Every
// testStore with a name uses the backend of that name, as Caddy instances that
// share a Redis do.
var (
	testBackendsMu sync.Mutex
	testBackends   = map[string]*testBackend{}
)

// testBackend is the nonces behind a test nonce store.
type testBackend struct {
	calls atomic.Int64 // the CheckAndRecord calls so far

	mu      sync.Mutex
	entries map[[2]string]time.Time // (scope, nonce) to until
	fail    error                   // returned by CheckAndRecord when set
	block   bool                    // CheckAndRecord waits for its context when set
}

// backend returns the backend called name, which the test nonce stores with
// that name create on first use. Tests that use it call resetTestBackends first.
func backend(name string) *testBackend {
	testBackendsMu.Lock()
	defer testBackendsMu.Unlock()
	b := testBackends[name]
	if b == nil {
		b = &testBackend{entries: make(map[[2]string]time.Time)}
		testBackends[name] = b
	}
	return b
}

func resetTestBackends(t *testing.T) {
	t.Helper()
	reset := func() {
		testBackendsMu.Lock()
		defer testBackendsMu.Unlock()
		testBackends = map[string]*testBackend{}
	}
	reset()
	t.Cleanup(reset)
}

func (b *testBackend) CheckAndRecord(ctx context.Context, scope, nonce string, until time.Time) (bool, error) {
	b.calls.Add(1)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.block {
		b.mu.Unlock()
		<-ctx.Done()
		b.mu.Lock()
		return false, ctx.Err()
	}
	if b.fail != nil {
		return false, b.fail
	}
	key := [2]string{scope, nonce}
	if _, ok := b.entries[key]; ok {
		return false, nil
	}
	b.entries[key] = until
	return true, nil
}

// testStore is a nonce store module whose nonces live in a testBackend.
type testStore struct {
	Name string `json:"name"`

	*testBackend
}

func (testStore) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.web_bot_auth.nonce_stores.test",
		New: func() caddy.Module { return new(testStore) },
	}
}

func (s *testStore) Provision(caddy.Context) error {
	s.testBackend = backend(s.Name)
	return nil
}

func (s *testStore) NonceStoreKey() string { return "test " + s.Name }

func (s *testStore) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the module name
	for d.NextBlock(0) {
		switch d.Val() {
		case "name":
			if !d.AllArgs(&s.Name) {
				return d.ArgErr()
			}
		default:
			return d.Errf("unrecognized subdirective %q", d.Val())
		}
	}
	return nil
}

var (
	_ NonceStore            = (*testStore)(nil)
	_ caddy.Provisioner     = (*testStore)(nil)
	_ caddyfile.Unmarshaler = (*testStore)(nil)
)

var expiresRe = regexp.MustCompile(`expires=(\d+)`)

func TestNonceStoreRecordsNonces(t *testing.T) {
	resetTestBackends(t)
	agent := newAgent(t)
	s := serve(t, `
	web_bot_auth {
		nonce_store test {
			name a
		}
	}
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)

	r := sign(t, agent, get(t, s.url))
	if got := s.send(t, r); got != "verified " {
		t.Errorf("response = %q, want %q", got, "verified ")
	}

	a := backend("a")
	a.mu.Lock()
	entries := len(a.entries)
	var scope string
	var until time.Time
	for k, v := range a.entries {
		scope, until = k[0], v
	}
	a.mu.Unlock()
	if entries != 1 {
		t.Fatalf("backend a holds %d entries, want 1", entries)
	}
	if scope != agent.directory {
		t.Errorf("scope = %q, want %q", scope, agent.directory)
	}
	sec, err := strconv.ParseInt(expiresRe.FindStringSubmatch(r.Header.Get("Signature-Input"))[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	// The default clock_skew is 1m.
	if d := until.Sub(time.Unix(sec, 0).Add(time.Minute)); math.Abs(d.Seconds()) > 2 {
		t.Errorf("until = %s, want within 2s of expires + 1m (%s)", until, time.Unix(sec, 0).Add(time.Minute))
	}

	if got := s.send(t, r); got != "invalid replay" {
		t.Errorf("response to the same request sent again = %q, want %q", got, "invalid replay")
	}
}

func TestNonceStoreOutlivesInstance(t *testing.T) {
	for _, tc := range []struct{ name, settings, want string }{
		{"with nonce_store", "nonce_store test {\n\t\t\tname a\n\t\t}", "invalid replay"},
		// Memory alone forgets the nonce when the instance stops.
		{"without nonce_store", "", "verified "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetTestBackends(t)
			agent := newAgent(t)
			directives := `
	web_bot_auth {
		` + tc.settings + `
	}
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`
			s := serve(t, directives)

			r := sign(t, agent, get(t, s.url))
			if got := s.send(t, r); got != "verified " {
				t.Errorf("response = %q, want %q", got, "verified ")
			}

			if err := caddy.Stop(); err != nil {
				t.Fatal(err)
			}
			s.load(t, directives)
			if got := s.send(t, r); got != tc.want {
				t.Errorf("response after the instance restarted = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDirectivesShareNonceStore(t *testing.T) {
	resetTestBackends(t)
	agent := newAgent(t)
	// Requests to /feed/ pass both directives.
	s := serve(t, `
	web_bot_auth {
		nonce_store test {
			name a
		}
	}
	handle /feed/* {
		web_bot_auth {
			mode require
			nonce_store test {
				name a
			}
		}
		respond "feed: {web_bot_auth.outcome} {web_bot_auth.reason}"
	}
	handle {
		respond "{web_bot_auth.outcome} {web_bot_auth.reason}"
	}`)

	feed := sign(t, agent, get(t, s.url+"/feed/x"))
	home := sign(t, agent, get(t, s.url))
	// samesame's signer covers only the host and Signature-Agent, so the
	// signature of home also verifies on /feed/.
	homeToFeed := get(t, s.url+"/feed/x")
	homeToFeed.Header = home.Header.Clone()

	for _, step := range []struct {
		name string
		req  *http.Request
		want string
	}{
		{"request checked by both directives", feed, "feed: verified "},
		{"request to another path", home, "verified "},
		{"that request replayed to /feed/", homeToFeed, "429"},
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
}

// A handler with nonce_store takes no entry of the in-memory nonce stores, so
// it must not release one that another handler holds.
func TestMemoryStoreSurvivesReloadNextToNonceStore(t *testing.T) {
	resetTestBackends(t)
	agent := newAgent(t)
	directives := func(feed string) string {
		return `
	web_bot_auth
	handle /feed/* {
		web_bot_auth {
			nonce_store test {
				name a
			}
		}
		respond "` + feed + `"
	}
	handle {
		respond "{web_bot_auth.outcome} {web_bot_auth.reason}"
	}`
	}
	s := serve(t, directives("feed"))

	r := sign(t, agent, get(t, s.url))
	if got := s.send(t, r); got != "verified " {
		t.Errorf("response = %q, want %q", got, "verified ")
	}

	// Caddy provisions the new config before it cleans up the old one. The
	// first reload gets the store from the pool before the wrong release, and
	// only the second reload asks the pool after it.
	s.load(t, directives("feed 2"))
	s.load(t, directives("feed 3"))
	if got := s.send(t, r); got != "invalid replay" {
		t.Errorf("response after two reloads = %q, want %q", got, "invalid replay")
	}
}

func TestNonceStoreWithTimeout(t *testing.T) {
	resetTestBackends(t)
	agent := newAgent(t)
	s := serve(t, `
	web_bot_auth {
		nonce_store test {
			name a
		}
		nonce_store_timeout 250ms
	}
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)

	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "verified " {
		t.Errorf("response = %q, want %q", got, "verified ")
	}
}

func TestUnknownNonceStoreFailsConfigLoad(t *testing.T) {
	const want = "module not registered: http.web_bot_auth.nonce_stores.nosuch"
	t.Run("Caddyfile", func(t *testing.T) {
		_, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(`http://127.0.0.1 {
	web_bot_auth {
		nonce_store nosuch
	}
}
`), nil)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Adapt error = %v, want one that says %s", err, want)
		}
	})
	t.Run("JSON", func(t *testing.T) {
		var cfg caddy.Config
		if err := json.Unmarshal([]byte(`{
	"admin": {"disabled": true},
	"apps": {"http": {"servers": {"srv0": {
		"listen": ["127.0.0.1:0"],
		"routes": [{"handle": [{"handler": "web_bot_auth", "nonce_store": {"store": "nosuch"}}]}]
	}}}}
}`), &cfg); err != nil {
			t.Fatal(err)
		}
		// Validate provisions the config, and cleans it up when that fails.
		err := caddy.Validate(&cfg)
		if err == nil || !strings.Contains(err.Error(), "http.web_bot_auth.nonce_stores.nosuch") {
			t.Errorf("Validate error = %v, want one that names http.web_bot_auth.nonce_stores.nosuch", err)
		}
	})
}
