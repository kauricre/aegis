package aegis

import (
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/TecharoHQ/samesame"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	"github.com/yaronf/httpsign"
)

// localTLS returns the certificate that every httptest TLS server uses and a
// pool that trusts it. Caddy serves the same certificate, so the pool trusts
// Caddy and every key directory.
var localTLS = sync.OnceValues(func() (tls.Certificate, *x509.CertPool) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv.TLS.Certificates[0], pool
})

// testAgent is samesame's signer for an agent, with the URL of the agent's key
// directory, the agent's private key, and the number of requests the server of
// its key directory has received.
type testAgent struct {
	*samesame.Signer
	directory string
	key       ed25519.PrivateKey
	requests  *atomic.Int64
}

// newAgent returns a new agent whose key directory is served from a local
// HTTPS server until the test ends.
func newAgent(t *testing.T) testAgent {
	t.Helper()
	key, err := samesame.GenerateKey(samesame.AlgEd25519)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewUnstartedServer(nil)
	authority := srv.Listener.Addr().String()
	directory, err := samesame.NewDirectoryHandler([]crypto.Signer{key}, samesame.DirectoryHandlerOptions{
		Authorities: []string{authority},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(samesame.WellKnownPath, directory)
	requests := new(atomic.Int64)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		mux.ServeHTTP(w, r)
	})
	srv.StartTLS()
	t.Cleanup(srv.Close)

	signer, err := samesame.NewSigner(key, samesame.SignerOptions{AgentOrigin: "https://" + authority})
	if err != nil {
		t.Fatal(err)
	}
	return testAgent{signer, "https://" + authority + samesame.WellKnownPath, key.(ed25519.PrivateKey), requests}
}

// site is Caddy running in-process with one site.
type site struct {
	url string
	log string // file that receives the module's logs
}

// serve runs Caddy with one HTTPS site that holds directives, as serveSite
// does.
func serve(t *testing.T, directives string) site {
	t.Helper()
	return serveSite(t, "https", "", directives)
}

// serveSite runs Caddy from a real Caddyfile whose only site, on a free local
// port with scheme https or http, holds directives. global goes into the
// global options. Caddy stops when the test ends. The config keeps Caddy away
// from the user's own Caddy data and config directories.
func serveSite(t *testing.T, scheme, global, directives string) site {
	t.Helper()
	dir := t.TempDir()

	cert, pool := localTLS()
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeFile(t, certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	writeFile(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))

	// Key directories run on loopback with a test certificate, which
	// samesame refuses unless told otherwise.
	tweakFetcher = func(o *samesame.FetcherOptions) {
		o.AllowPrivateAddresses = true
		o.TLSConfig = &tls.Config{RootCAs: pool}
	}
	t.Cleanup(func() { tweakFetcher = nil })

	s := site{url: scheme + "://" + freeAddr(t), log: filepath.Join(dir, "aegis.log")}
	var certs string
	if scheme == "https" {
		certs = "tls " + certFile + " " + keyFile
	}
	caddyfile := fmt.Sprintf(`{
	admin off
	persist_config off
	storage file_system %s
	storage_clean_interval off
	auto_https off
	default_bind 127.0.0.1
	%s
	log aegis {
		output file %s
		format json
		level DEBUG
		include http.handlers.web_bot_auth
	}
}

%s {
	%s
	%s
}
`, dir, global, s.log, s.url, certs, directives)

	cfg, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(caddyfile), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(cfg, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func (s site) send(t *testing.T, r *http.Request) string {
	t.Helper()
	_, body := s.do(t, r)
	return body
}

// do sends r and returns the response with its body read.
func (s site) do(t *testing.T, r *http.Request) (*http.Response, string) {
	t.Helper()
	_, pool := localTLS()
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool},
		DisableKeepAlives: true,
	}}
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

// logs returns what the module has logged so far, one JSON object per line.
func (s site) logs(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(s.log)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func get(t *testing.T, url string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func post(t *testing.T, url, body string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func sign(t *testing.T, agent testAgent, r *http.Request) *http.Request {
	t.Helper()
	if err := agent.Sign(r); err != nil {
		t.Fatal(err)
	}
	return r
}

// signWithoutNonce signs r as agent, as sign does, but leaves the nonce out of
// the signature.
func signWithoutNonce(t *testing.T, agent testAgent, r *http.Request) *http.Request {
	t.Helper()
	origin := strings.TrimSuffix(agent.directory, samesame.WellKnownPath)
	signer, err := samesame.NewSigner(agent.key, samesame.SignerOptions{AgentOrigin: origin, DisableNonce: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Sign(r); err != nil {
		t.Fatal(err)
	}
	return r
}

// signMethodAndURL signs r as agent with httpsign, samesame's signature engine.
// Unlike sign, the signature also covers r's method and full URL (@method and
// @target-uri), which samesame's signer never covers, and has no nonce.
func signMethodAndURL(t *testing.T, agent testAgent, r *http.Request) *http.Request {
	t.Helper()
	origin := strings.TrimSuffix(agent.directory, samesame.WellKnownPath)
	r.Header.Set("Signature-Agent", fmt.Sprintf("%s=%q", samesame.DefaultLabel, origin))

	cfg := httpsign.NewSignConfig().
		SetTag(samesame.TagWebBotAuth).
		SetKeyID(agent.KeyID()).
		SetExpiresAfter(int64(samesame.DefaultExpiry.Seconds()))
	fields := httpsign.NewFields().
		AddHeaders("@method", "@target-uri", "@authority").
		AddDictHeader("signature-agent", samesame.DefaultLabel)
	signer, err := httpsign.NewEd25519Signer(agent.key, cfg, *fields)
	if err != nil {
		t.Fatal(err)
	}
	input, sig, err := httpsign.SignRequest(samesame.DefaultLabel, *signer, r)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Signature-Input", input)
	r.Header.Set("Signature", sig)
	return r
}

// tamper changes the first byte of r's signature and returns r.
func tamper(r *http.Request) *http.Request {
	sig := signature(r)
	c := "A"
	if sig[0] == 'A' {
		c = "B"
	}
	r.Header.Set("Signature", samesame.DefaultLabel+"=:"+c+sig[1:]+":")
	return r
}

// claim sets r's Signature-Agent header to agent's origin, whose key directory
// does not hold the key r is signed with, and returns r.
func claim(r *http.Request, agent testAgent) *http.Request {
	origin := strings.TrimSuffix(agent.directory, samesame.WellKnownPath)
	r.Header.Set("Signature-Agent", fmt.Sprintf("%s=%q", samesame.DefaultLabel, origin))
	return r
}

// signature returns the base64 signature in r's Signature header, which
// samesame's signer writes as sig1=:<base64>:.
func signature(r *http.Request) string {
	sig := r.Header.Get("Signature")
	return strings.TrimSuffix(strings.TrimPrefix(sig, samesame.DefaultLabel+"=:"), ":")
}

// freeAddr returns a loopback address that nothing listens on.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func writeFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
