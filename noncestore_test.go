package aegis

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"regexp"
	"slices"
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
	calls    atomic.Int64 // the CheckAndRecord calls so far
	keyCalls atomic.Int64 // the NonceStoreKey calls so far

	mu      sync.Mutex
	entries map[[2]string]time.Time // (scope, nonce) to until
	fail    error                   // returned by CheckAndRecord when set
	block   bool                    // CheckAndRecord waits for its context when set
	hang    chan struct{}           // CheckAndRecord waits for it to close, whatever its context, when set
	hold    chan struct{}           // the next CheckAndRecord takes it, waits for it to close and then checks
	panics  any                     // CheckAndRecord panics with it when set
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
	if b.hang != nil {
		hang := b.hang
		b.mu.Unlock()
		<-hang
		b.mu.Lock()
		return false, ctx.Err()
	}
	if b.hold != nil {
		hold := b.hold
		b.hold = nil
		b.mu.Unlock()
		<-hold
		b.mu.Lock()
	}
	if b.panics != nil {
		panic(b.panics)
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

func (s *testStore) NonceStoreKey() string {
	s.keyCalls.Add(1)
	return "test " + s.Name
}

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

// storeLogEntry is a line that the module logs at warn or info.
type storeLogEntry struct {
	Level, Msg, Store, Error string
}

// storeLogs returns the lines that the module has logged at warn or info so
// far.
func storeLogs(t *testing.T, s site) []storeLogEntry {
	t.Helper()
	var got []storeLogEntry
	for line := range strings.Lines(s.logs(t)) {
		var entry storeLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		if entry.Level == "warn" || entry.Level == "info" {
			got = append(got, entry)
		}
	}
	return got
}

const (
	storeFailed  = "nonce store failed: signed requests get unverified with reason nonce_store until it answers"
	storeAnswers = "nonce store answers again"
)

// lowerRetryAfter sets nonceStoreRetryAfter to d until the test ends.
func lowerRetryAfter(t *testing.T, d time.Duration) {
	t.Helper()
	retryAfter := nonceStoreRetryAfter
	nonceStoreRetryAfter = d
	t.Cleanup(func() { nonceStoreRetryAfter = retryAfter })
}

// failingStore makes the backend of test a fail and serves a site whose
// web_bot_auth uses it with settings, which go into the directive's block.
func failingStore(t *testing.T, settings string) (*testBackend, site) {
	t.Helper()
	a := backend("a")
	a.mu.Lock()
	a.fail = errors.New("store down")
	a.mu.Unlock()
	return a, serve(t, `
	web_bot_auth {
		nonce_store test {
			name a
		}
		`+settings+`
	}
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)
}

// The second request comes within the default 10s after the failure.
func TestNonceStoreFailure(t *testing.T) {
	resetTestBackends(t)
	agent := newAgent(t)
	a, s := failingStore(t, "")

	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "unverified nonce_store" {
		t.Errorf("response while the store fails = %q, want %q", got, "unverified nonce_store")
	}
	calls := a.calls.Load()
	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "unverified nonce_store" {
		t.Errorf("response right after the failure = %q, want %q", got, "unverified nonce_store")
	}
	if n := a.calls.Load() - calls; n != 0 {
		t.Errorf("store calls right after the failure = %d, want 0", n)
	}

	want := []storeLogEntry{{"warn", storeFailed, "test a", "store down"}}
	if got := storeLogs(t, s); !slices.Equal(got, want) {
		t.Errorf("warn and info lines = %+v, want %+v", got, want)
	}
}

// Each sleep outlasts the lowered window, so every check after one asks the
// store. The checks and their log lines never call NonceStoreKey, because a
// module that blocks there would hold every check of its store.
func TestNonceStoreRecovery(t *testing.T) {
	lowerRetryAfter(t, 50*time.Millisecond)
	resetTestBackends(t)
	agent := newAgent(t)
	a, s := failingStore(t, "")
	keyCalls := a.keyCalls.Load()

	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "unverified nonce_store" {
		t.Errorf("response while the store fails = %q, want %q", got, "unverified nonce_store")
	}
	time.Sleep(100 * time.Millisecond)
	calls := a.calls.Load()
	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "unverified nonce_store" {
		t.Errorf("response after the window while the store fails = %q, want %q", got, "unverified nonce_store")
	}
	if n := a.calls.Load() - calls; n != 1 {
		t.Errorf("store calls after the window = %d, want 1", n)
	}

	a.mu.Lock()
	a.fail = nil
	a.mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "verified " {
		t.Errorf("response once the store answers = %q, want %q", got, "verified ")
	}

	want := []storeLogEntry{
		{"warn", storeFailed, "test a", "store down"},
		{"info", storeAnswers, "test a", ""},
	}
	if got := storeLogs(t, s); !slices.Equal(got, want) {
		t.Errorf("warn and info lines = %+v, want %+v", got, want)
	}
	if n := a.keyCalls.Load() - keyCalls; n != 0 {
		t.Errorf("NonceStoreKey calls during the checks = %d, want 0", n)
	}
}

// checkNonceStoreTimeout serves a site whose store test a has a 50ms
// nonce_store_timeout, and lets a signed request verify, which downloads the
// agent's key directory. It then calls stall with the backend's mutex held,
// and checks that the next signed request gets unverified with reason
// nonce_store once the timeout has passed, long before the store answers, and
// that the timeout counts as a failure of the store.
func checkNonceStoreTimeout(t *testing.T, agent testAgent, stall func(*testBackend)) {
	t.Helper()
	s := serve(t, `
	web_bot_auth {
		nonce_store test {
			name a
		}
		nonce_store_timeout 50ms
	}
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)
	// The timed request finds the key directory downloaded, so the time
	// bounds below measure the check of the store and not the download.
	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "verified " {
		t.Errorf("response before the store stalls = %q, want %q", got, "verified ")
	}
	a := backend("a")
	a.mu.Lock()
	stall(a)
	a.mu.Unlock()

	// A request that the store holds fails the test in seconds, not at the
	// end of go test's timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	got := s.send(t, sign(t, agent, get(t, s.url).WithContext(ctx)))
	elapsed := time.Since(start)
	if got != "unverified nonce_store" {
		t.Errorf("response = %q, want %q", got, "unverified nonce_store")
	}
	if elapsed < 50*time.Millisecond || elapsed >= time.Second {
		t.Errorf("response took %s, want at least 50ms and less than 1s", elapsed)
	}
	want := []storeLogEntry{{"warn", storeFailed, "test a", "context deadline exceeded"}}
	if got := storeLogs(t, s); !slices.Equal(got, want) {
		t.Errorf("warn and info lines = %+v, want %+v", got, want)
	}
}

func TestNonceStoreTimeout(t *testing.T) {
	resetTestBackends(t)
	agent := newAgent(t)
	checkNonceStoreTimeout(t, agent, func(a *testBackend) { a.block = true })
}

func TestNonceStoreTimeoutWhenStoreIgnoresContext(t *testing.T) {
	resetTestBackends(t)
	agent := newAgent(t)
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	checkNonceStoreTimeout(t, agent, func(a *testBackend) { a.hang = hang })
}

// Directives with the same store, and the directives of the config that a
// reload brings, share whether the store fails, so the store's failure logs
// one warning.
func TestNonceStoreHealthSharedByDirectivesAndReloads(t *testing.T) {
	resetTestBackends(t)
	agent := newAgent(t)
	a := backend("a")
	a.mu.Lock()
	a.fail = errors.New("store down")
	a.mu.Unlock()
	// Requests to /feed/ pass both directives.
	directives := func(feed string) string {
		return `
	web_bot_auth {
		nonce_store test {
			name a
		}
	}
	handle /feed/* {
		web_bot_auth {
			nonce_store test {
				name a
			}
		}
		respond "` + feed + `: {web_bot_auth.outcome} {web_bot_auth.reason}"
	}`
	}
	s := serve(t, directives("feed"))

	if got := s.send(t, sign(t, agent, get(t, s.url+"/feed/x"))); got != "feed: unverified nonce_store" {
		t.Errorf("response = %q, want %q", got, "feed: unverified nonce_store")
	}
	s.load(t, directives("feed 2"))
	if got := s.send(t, sign(t, agent, get(t, s.url+"/feed/x"))); got != "feed 2: unverified nonce_store" {
		t.Errorf("response after the reload = %q, want %q", got, "feed 2: unverified nonce_store")
	}

	var warnings int
	for _, entry := range storeLogs(t, s) {
		if entry.Level == "warn" {
			warnings++
		}
	}
	if warnings != 1 {
		t.Errorf("warnings = %d, want 1", warnings)
	}
}

// A request whose client disconnects during the check says nothing about the
// store, so it starts no skip window and logs no warning.
func TestNonceStoreCheckOfDisconnectedClient(t *testing.T) {
	resetTestBackends(t)
	agent := newAgent(t)
	s := serve(t, `
	web_bot_auth {
		nonce_store test {
			name a
		}
		nonce_store_timeout 1m
	}
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)
	// The agent's key directory is downloaded first, because a request that
	// waits for the download stops waiting when its client disconnects, and
	// never reaches the store.
	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "verified " {
		t.Errorf("response = %q, want %q", got, "verified ")
	}

	a := backend("a")
	a.mu.Lock()
	a.block = true
	a.mu.Unlock()
	calls := a.calls.Load()
	_, pool := localTLS()
	conn, err := tls.Dial("tcp", strings.TrimPrefix(s.url, "https://"), &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	if err := sign(t, agent, get(t, s.url)).Write(conn); err != nil {
		t.Fatal(err)
	}
	// The client disconnects once the store holds the request.
	deadline := time.Now().Add(10 * time.Second)
	for a.calls.Load() == calls {
		if time.Now().After(deadline) {
			t.Fatal("the request never reached the store")
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn.Close()
	// web_bot_auth logs the request once the check has given up.
	for !strings.Contains(s.logs(t), `"reason":"nonce_store"`) {
		if time.Now().After(deadline) {
			t.Fatal("web_bot_auth logged no outcome for the disconnected request")
		}
		time.Sleep(10 * time.Millisecond)
	}

	a.mu.Lock()
	a.block = false
	a.mu.Unlock()
	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "verified " {
		t.Errorf("response after the client disconnected = %q, want %q", got, "verified ")
	}
	if got := storeLogs(t, s); len(got) != 0 {
		t.Errorf("warn and info lines = %+v, want none", got)
	}
}

// holdStore makes the next check of backend a wait until the test calls
// release. The cleanup also calls it, and runs before Caddy stops when
// holdStore is called after serve, so a failed test leaves no handler waiting.
func holdStore(t *testing.T, a *testBackend) (release func()) {
	t.Helper()
	hold := make(chan struct{})
	a.mu.Lock()
	a.hold = hold
	a.mu.Unlock()
	release = sync.OnceFunc(func() { close(hold) })
	t.Cleanup(release)
	return release
}

// waitForCalls waits until backend a has had n calls.
func waitForCalls(t *testing.T, a *testBackend, n int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for a.calls.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("store calls after 10s = %d, want %d", a.calls.Load(), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A store that panics fails the check, and Caddy keeps running.
func TestNonceStorePanic(t *testing.T) {
	resetTestBackends(t)
	agent := newAgent(t)
	a := backend("a")
	a.mu.Lock()
	a.panics = "store bug"
	a.mu.Unlock()
	s := serve(t, `
	web_bot_auth {
		nonce_store test {
			name a
		}
	}
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)

	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "unverified nonce_store" {
		t.Errorf("response = %q, want %q", got, "unverified nonce_store")
	}
	want := []storeLogEntry{{"warn", storeFailed, "test a", "nonce store panicked: store bug"}}
	if got := storeLogs(t, s); !slices.Equal(got, want) {
		t.Errorf("warn and info lines = %+v, want %+v", got, want)
	}
}

// A check that started before the failure was recorded says nothing about the
// store when it succeeds after it, so the store stays failing.
func TestNonceStoreSuccessStartedBeforeFailure(t *testing.T) {
	resetTestBackends(t)
	agent := newAgent(t)
	s := serve(t, `
	web_bot_auth {
		nonce_store test {
			name a
		}
		nonce_store_timeout 1m
	}
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)
	a := backend("a")
	release := holdStore(t, a)

	held := sendInBackground(sign(t, agent, get(t, s.url)))
	waitForCalls(t, a, 1)
	a.mu.Lock()
	a.fail = errors.New("store down")
	a.mu.Unlock()
	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "unverified nonce_store" {
		t.Errorf("response while the store fails = %q, want %q", got, "unverified nonce_store")
	}
	a.mu.Lock()
	a.fail = nil
	a.mu.Unlock()
	release()
	if got := <-held; got != "verified " {
		t.Errorf("response to the held request = %q, want %q", got, "verified ")
	}

	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "unverified nonce_store" {
		t.Errorf("response after the held check succeeded = %q, want %q", got, "unverified nonce_store")
	}
	if n := a.calls.Load(); n != 2 {
		t.Errorf("store calls = %d, want 2", n)
	}
	want := []storeLogEntry{{"warn", storeFailed, "test a", "store down"}}
	if got := storeLogs(t, s); !slices.Equal(got, want) {
		t.Errorf("warn and info lines = %+v, want %+v", got, want)
	}
}

// After the window, one check asks the failing store, and the checks that come
// while it waits fail without asking. The held check cannot time out during
// the test, so the second request meets it whatever the runner's speed.
func TestNonceStoreOneProbe(t *testing.T) {
	lowerRetryAfter(t, 50*time.Millisecond)
	resetTestBackends(t)
	agent := newAgent(t)
	a, s := failingStore(t, "nonce_store_timeout 1m")
	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "unverified nonce_store" {
		t.Errorf("response while the store fails = %q, want %q", got, "unverified nonce_store")
	}

	a.mu.Lock()
	a.fail = nil
	a.mu.Unlock()
	release := holdStore(t, a)
	time.Sleep(100 * time.Millisecond)
	calls := a.calls.Load()
	probe := sendInBackground(sign(t, agent, get(t, s.url)))
	waitForCalls(t, a, calls+1)
	if got := s.send(t, sign(t, agent, get(t, s.url))); got != "unverified nonce_store" {
		t.Errorf("response while the probe waits = %q, want %q", got, "unverified nonce_store")
	}
	if n := a.calls.Load() - calls; n != 1 {
		t.Errorf("store calls since the window = %d, want 1", n)
	}
	release()
	if got := <-probe; got != "verified " {
		t.Errorf("response to the probe = %q, want %q", got, "verified ")
	}

	want := []storeLogEntry{
		{"warn", storeFailed, "test a", "store down"},
		{"info", storeAnswers, "test a", ""},
	}
	if got := storeLogs(t, s); !slices.Equal(got, want) {
		t.Errorf("warn and info lines = %+v, want %+v", got, want)
	}
}
