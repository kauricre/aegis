package aegis

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TecharoHQ/samesame"
)

func TestConformance(t *testing.T) {
	dir, err := samesame.ParseDirectory([]byte(vectorDirectory), samesame.DirectoryOptions{AllowTestKeys: true})
	if err != nil {
		t.Fatal(err)
	}
	keys := directories{"https://signature-agent.test" + samesame.WellKnownPath: dir}

	// The vectors are signed at fixed times, some of them long expired, with
	// the RFC 9421 test keys, which samesame refuses by default, and name a
	// key directory on a host that does not exist. Only this hook, never
	// config, reaches the verifier's clock and its source of keys.
	var now atomic.Int64
	tweakVerifier = func(o *samesame.VerifierOptions) {
		o.Now = func() time.Time { return time.Unix(now.Load(), 0) }
		o.Resolver = keys
	}
	t.Cleanup(func() { tweakVerifier = nil })

	s := serve(t, `
	web_bot_auth {
		max_validity `+vectorValidity.String()+`
	}
	respond "{web_bot_auth.outcome} {web_bot_auth.reason}"`)

	for _, v := range slices.Concat(cloudflareVectors, parallaxGrainVectors) {
		t.Run(v.name, func(t *testing.T) {
			now.Store(v.now)
			u, err := url.Parse(v.url)
			if err != nil {
				t.Fatal(err)
			}
			r, err := http.NewRequest(v.method, s.url+u.RequestURI(), strings.NewReader(v.body))
			if err != nil {
				t.Fatal(err)
			}
			r.Host = u.Host
			for name, value := range v.header {
				r.Header.Set(name, value)
			}
			got := s.send(t, r)
			if got != v.want {
				t.Errorf("response = %q, want %q", got, v.want)
			}

			// samesame alone, given the request as the agent sent it, must
			// agree. web_bot_auth gives samesame an empty body, and the
			// Content-Digest of NV-08 is that of an empty body, so if samesame
			// ever compares the two, only this check notices that web_bot_auth
			// still verifies NV-08.
			verifier, err := samesame.NewVerifier(samesame.VerifierOptions{
				Resolver:    keys,
				MaxValidity: vectorValidity,
				Now:         func() time.Time { return time.Unix(v.now, 0) },
			})
			if err != nil {
				t.Fatal(err)
			}
			alone := httptest.NewRequest(v.method, v.url, strings.NewReader(v.body))
			alone.Header = r.Header
			_, err = verifier.Verify(alone)
			if want := samesame.OutcomeOf(err).String() + " " + reasonOf(err); got != want {
				t.Errorf("response = %q, but samesame alone gives %q", got, want)
			}
		})
	}
}

// directories is a samesame.KeyResolver over fixed key directories, by URL.
type directories map[string]*samesame.Directory

func (d directories) Resolve(_ context.Context, id *url.URL) (*samesame.Directory, error) {
	if dir, ok := d[id.String()]; ok {
		return dir, nil
	}
	return nil, fmt.Errorf("no key directory at %s", id)
}

// vector is a request from a published set of Web Bot Auth test vectors.
type vector struct {
	name        string
	now         int64 // the Unix time at which the request is checked
	method, url string
	header      map[string]string
	body        string
	want        string // the outcome and reason that web_bot_auth gives it
}

// vectorValidity is the time from created to expires of most vectors, from
// 2025-01-01 to 2124-12-08. Only a max_validity at least this long accepts
// them.
const vectorValidity = 36500 * 24 * time.Hour

// vectorDirectory is the key directory of https://signature-agent.test, the
// agent that signs the vectors. It holds the public halves of the RFC 9421
// test keys test-key-ed25519 (Appendix B.1.4) and test-key-rsa-pss (Appendix
// B.1.2).
const vectorDirectory = `{"keys": [
	{"kty": "OKP", "crv": "Ed25519", "kid": "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U", "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs", "use": "sig"},
	{"kty": "RSA", "kid": "oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA", "n": "r4tmm3r20Wd_PbqvP1s2-QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct-Lh1GH45x28Rw3Ry53mm-oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL-Wokqltd11nqqzi-bJ9cvSKADYdUAAN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4aOT9v6d-nb4bnNkQVklLQ3fVAvJm-xdDOp9LCNCN48V2pnDOkFV6-U9nV5oyc6XI2w", "e": "AQAB", "use": "sig"}
]}`

// cloudflareVectors are the request vectors of cloudflare/web-bot-auth at
// commit c9e5a23, licensed Apache-2.0, from the files
// web_bot_auth_architecture_v1.json and web_bot_auth_architecture_v2.json in
// packages/web-bot-auth/test/test_data, each checked one minute after it was
// signed. The sig2 vectors are those of the protocol draft's Appendix E. The
// sig1 vectors carry no Signature-Agent, so samesame could verify them only
// with keys configured out of band, which web_bot_auth does not take.
var cloudflareVectors = []vector{
	{
		name: "Cloudflare architecture_v1 rsa-pss sig1", now: 1735689660,
		method: "GET", url: "https://example.com/path/to/resource",
		header: map[string]string{
			"Signature-Input": `sig1=("@authority");created=1735689600;keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA";alg="rsa-pss-sha512";expires=1735693200;nonce="yT+sZR1glKOTemVLbmPDFwPScbB1Zj/sMNPEFZcjwJW5jK/taa7HviOXovVwiZOfrrLHS2SbLFUQBxPYZChf7g==";tag="web-bot-auth"`,
			"Signature":       `sig1=:ppXhcGjVp7xaoHGIa7V+hsSxuRgFt8i04K4FWz9ORJtn57t8duD3cyavsnh9grdWWOJHER8ITNBaqe4mKmPq193S+7hSW31IzXSH4/9WfsdrjUBwyJ0fhBU7oNn3UGDqwdhr5TMgVI2/EX8saV5GrOunM09zMEA+d4QWYyKRFJmg+asCs253l2IYPpVp4N55H0uRK7qhb7acng8LNiEPTQZD2s+Kha95LgeciKQSO0jgR/h59fX/dXqLdFIvRMn8Ggs2VUzF/f/MMEXH83gufVnh4SYl/rKMSKWDBsK+OiLpobAVIuIz+HLCVlMnxlkXkhCW2J/Pmo8jht9N5k/y1A==:`,
		},
		want: "unverified key_unknown",
	},
	{
		name: "Cloudflare architecture_v1 rsa-pss sig2", now: 1735689660,
		method: "GET", url: "https://example.com/path/to/resource",
		header: map[string]string{
			"Signature-Agent": `"https://signature-agent.test"`,
			"Signature-Input": `sig2=("@authority" "signature-agent");created=1735689600;keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA";alg="rsa-pss-sha512";expires=1735693200;nonce="XSHtZVCThSIAksXsH9WBs6AtxtXC0eQGiIcUGSoJstFs8lAWakjhrfwzLhyjtme5iXMZvmFWqDEs6cT3Jf+BbQ==";tag="web-bot-auth"`,
			"Signature":       `sig2=:I1QWNzGXdP1a4dSvOHLCVOOanEYHDk+ZsVxM9MLX/p4ko69ghKwR5EOtAD96g7g4GWP7lmpM/jFAf9q8EFRDTPLjUXySwMv4YPgabv2LQihTJG2y8a2m6IGltyruwQNiqSJVUuRaG9+b17CGmAMFZh30X6GXLdQJrCARpeTqPwp2DC+a8haDE/VE5EruqzjA5/2mKwvrkzkSqeW5tOVtFwWRRHIOidquf/8Je6kM9mhgkg4arudLA5SL4wyyYE1jURIgcOl8agrfdJ5Def23DIRtiOLRa8jT9cpTLFAuFHN+mrZA/LH9h0gSIg1cPb+0cMASee5uku1KjWcFer7jWA==:`,
		},
		want: "verified ",
	},
	{
		name: "Cloudflare architecture_v1 ed25519 sig1", now: 1735689660,
		method: "GET", url: "https://example.com/path/to/resource",
		header: map[string]string{
			"Signature-Input": `sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="mYotfW3CUjI68sbGw6oKd7kyXqPjZEtU8xFPGWFrqOAf5qC6MDe3pys3SWWCudB0MvwslHy32WXUpkR7u0lt/w==";tag="web-bot-auth"`,
			"Signature":       `sig1=:+NA/cssf4Y2bQTMTkyvTGRCaVzp9quyUevdwwMtMOWhhOOZ2T1subBj0BtvdnrpDEuwSAbiTeElXDzHL3WWKCw==:`,
		},
		want: "unverified key_unknown",
	},
	{
		name: "Cloudflare architecture_v1 ed25519 sig2", now: 1735689660,
		method: "GET", url: "https://example.com/path/to/resource",
		header: map[string]string{
			"Signature-Agent": `"https://signature-agent.test"`,
			"Signature-Input": `sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"`,
			"Signature":       `sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:`,
		},
		want: "verified ",
	},
	{
		name: "Cloudflare architecture_v2 rsa-pss sig1", now: 1735689660,
		method: "GET", url: "https://example.com/path/to/resource",
		header: map[string]string{
			"Signature-Input": `sig1=("@authority");created=1735689600;keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA";alg="rsa-pss-sha512";expires=4889289600;nonce="JojDFWJ90jf+gZhdKeTyJYsu1XvNPZSFAGhvYq5SuV3gneOEUAhq+xl792WGuD1W+Dr6NRmx+m+t06NsYnL4iA==";tag="web-bot-auth"`,
			"Signature":       `sig1=:hWPaj85MWQiRkzU4jnIKvdPQiDfMCPIoxOP8nZveNc3aFQ7r/UmXWCwGNImw588iRvTFey5TR3fVEgnXpcttlyK+u5pN831z9Wlr+IMNfub4uEM3SuO+SKFygJZyLG0pf7OAiRcU4C0gyx1BS/+z9ydQTRzDLr88wCkBBRqwGRrSi8HTwxkqg1jugobh93hcnU6gV8MK1n+VnhRprIgl2RQSO6q5cfbB4OS8C4t/8ndW0lYmP2SWzKZJXnpX5Wrj17PuLqnVW6MO8pJnLAMXNvxUdx32KHeq/cHFrzZazZsua3UOoP+k+niHwoQ8bBWj1Vi4mM1mYJK+fk366cCLsQ==:`,
		},
		want: "unverified key_unknown",
	},
	{
		name: "Cloudflare architecture_v2 rsa-pss sig2", now: 1735689660,
		method: "GET", url: "https://example.com/path/to/resource",
		header: map[string]string{
			"Signature-Agent": `agent2="https://signature-agent.test"`,
			"Signature-Input": `sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA";alg="rsa-pss-sha512";expires=4889289600;nonce="wcfPQPh7SzkvrIVvhD00vNk9PkxJNY2NVbYl2PVBB4zmUoluSwE7W6bPtF60QA3k8g06FU7PPCD+J58YofY1zg==";tag="web-bot-auth"`,
			"Signature":       `sig2=:gHzpLNeHaHIO19NaJH9YMW5dcVSi2s0wOMBr6p18vcofS106sfC4KBIS0/szPlBBd1vIcyQ88B6CTEWIhRAiVrb9zfX0mx1aG12CSGWcYkSirHeyTxhbuJvXd27ed6skWoy4PjXItq38936ivUQjfdIwXh1aX6HxkAC3vRnEdSNfntkLWeEuIQ5BLIOBGE39fSwg27Qjq6OVWYas/9/aFUr3HA34MXWYdp+//cvlEKDp3kRoLOw9ro0AOr6srHrTeEtxon2afcws1aZVSlPdd2fZSEIGmw9HAHLDCEkFTERu1gH2k/zIEqgy7CAYXI9E5slog0cLg/Vc6+f8gih33g==:`,
		},
		want: "verified ",
	},
	{
		name: "Cloudflare architecture_v2 ed25519 sig1", now: 1735689660,
		method: "GET", url: "https://example.com/path/to/resource",
		header: map[string]string{
			"Signature-Input": `sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="zIW8+cdmA3vdYagbxojpONwa/l0EKJ/O3/wD486VvsQjO/RxPaSt6ZxvQaMcQzNnqKN/mQ6hpGiFro2L2qkz5A==";tag="web-bot-auth"`,
			"Signature":       `sig1=:QKN4fTdIYfh82fvoZCQiQA1weuozfCS/Led2zTMbewMMqH8PI2Wsy/5c4ao6B6D09nraNQdBNOADg8aM1MqfCg==:`,
		},
		want: "unverified key_unknown",
	},
	{
		name: "Cloudflare architecture_v2 ed25519 sig2", now: 1735689660,
		method: "GET", url: "https://example.com/path/to/resource",
		header: map[string]string{
			"Signature-Agent": `agent2="https://signature-agent.test"`,
			"Signature-Input": `sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"`,
			"Signature":       `sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:`,
		},
		want: "verified ",
	},
}

// parallaxGrainVectors are the 17 requests of
// ParallaxGrain/webbotauth-negative-vectors at commit b786dd8, licensed
// CC0-1.0, that must not verify, each checked at the time the set gives. Each
// name ends in the reason the set expects. samesame disagrees with the set
// on 3 of them, marked below.
var parallaxGrainVectors = []vector{
	{
		name: "ParallaxGrain NV-01 target-not-covered", now: 1735689660,
		method: "GET", url: "https://example.com/",
		header: map[string]string{
			"Signature-Agent": `sig1="https://signature-agent.test"`,
			"Signature-Input": `sig1=("signature-agent";key="sig1");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="web-bot-auth"`,
			"Signature":       `sig1=:OfqFF7JEZnSAkthXM22HF3Ghlrslj4CHN1ZO9HMaOlf4rCCCSHcaQT82AtaWrXV0avoXjS4A7LJUMkdamFXLCg==:`,
		},
		want: "invalid profile",
	},
	{
		name: "ParallaxGrain NV-03 missing-fields", now: 1735689660,
		method: "GET", url: "https://example.com/",
		header: map[string]string{
			"Signature-Agent": `sig1="https://signature-agent.test"`,
			"Signature-Input": `sig1=("@authority" "signature-agent";key="sig1");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";tag="web-bot-auth"`,
			"Signature":       `sig1=:vwMiAiACovfQ9Cnj5b145eU183Ce2YGO02p+H5n/86NQiOeaZPLmiA1Cry2TUqmj+uAqzw5pHvLu33Q4dRS1CQ==:`,
		},
		want: "invalid profile",
	},
	{
		name: "ParallaxGrain NV-04 expired", now: 1735696800,
		method: "GET", url: "https://example.com/",
		header: map[string]string{
			"Signature-Agent": `sig1="https://signature-agent.test"`,
			"Signature-Input": `sig1=("@authority" "signature-agent";key="sig1");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;tag="web-bot-auth"`,
			"Signature":       `sig1=:PGCXcZbx5FaCr8JzBK0Rcs/h+eV0s+o6JhsQpiWfoBZnvREvjbmZexFna9jGiNfvbXfZ4Q/nO7wDc9RJzF8SDw==:`,
		},
		want: "invalid expired",
	},
	{
		name: "ParallaxGrain NV-05 clock-ahead", now: 1735686000,
		method: "GET", url: "https://example.com/",
		header: map[string]string{
			"Signature-Agent": `sig1="https://signature-agent.test"`,
			"Signature-Input": `sig1=("@authority" "signature-agent";key="sig1");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="web-bot-auth"`,
			"Signature":       `sig1=:JE1yD+mpEKRsD1jC6gpbZXXFMoupdDH6EEwU1+QKgwDGXftEABdV3XbSANQzNQxU7UtgavuSgunABEfoHBxtDQ==:`,
		},
		want: "invalid not_yet_valid",
	},
	{
		name: "ParallaxGrain NV-06 bad-signature", now: 1735689660,
		method: "GET", url: "https://example.com/",
		header: map[string]string{
			"Signature-Agent": `sig1="https://signature-agent.test"`,
			"Signature-Input": `sig1=("@authority" "signature-agent";key="sig1");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="web-bot-auth"`,
			"Signature":       `sig1=:tlN1YC7fkMH5W7SBtB/uwrm65jP8d1la9pAPxphRsBrR+dAYAEPF+BVvJpX8oIf7DJZrsAaq65Iil6YdKCuGDg==:`,
		},
		want: "invalid bad_signature",
	},
	{
		name: "ParallaxGrain NV-07 canonicalization-mismatch", now: 1735689660,
		method: "GET", url: "https://example.com/",
		header: map[string]string{
			"Signature-Agent": `sig1="https://signature-agent.test"`,
			"Signature-Input": `sig1=("@authority" "@path" "signature-agent";key="sig1");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="web-bot-auth"`,
			"Signature":       `sig1=:gVyV1O4BnincHcl/dIHWUaGagmEldaC7JN4KtkCsRtbOGwxrRJTdm0HHyKBcOYW3uA4R7FjcdaERQBbDJSzRAg==:`,
		},
		want: "invalid bad_signature",
	},
	// The set expects invalid, but samesame does not compare Content-Digest
	// with the body.
	{
		name: "ParallaxGrain NV-08 content-digest-mismatch", now: 1735689660,
		method: "POST", url: "https://example.com/",
		header: map[string]string{
			"Signature-Agent": `sig1="https://signature-agent.test"`,
			"Content-Digest":  `sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:`,
			"Signature-Input": `sig1=("@authority" "content-digest" "signature-agent";key="sig1");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="web-bot-auth"`,
			"Signature":       `sig1=:6xuRq2Nf1ZbzTCosEy2cFaQ6Nx/NzDjCzlbEN4uqnEhkp3iNLr8xrTFc+vdPWtqTq+FAVHzPoGPDbL7m6y9eCw==:`,
		},
		body: `{"hello":"world"}`,
		want: "verified ",
	},
	{
		name: "ParallaxGrain NV-09 missing-component", now: 1735689660,
		method: "GET", url: "https://example.com/",
		header: map[string]string{
			"Signature-Agent": `sig1="https://signature-agent.test"`,
			"Signature-Input": `sig1=("@authority" "content-digest" "signature-agent";key="sig1");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="web-bot-auth"`,
			"Signature":       `sig1=:6xuRq2Nf1ZbzTCosEy2cFaQ6Nx/NzDjCzlbEN4uqnEhkp3iNLr8xrTFc+vdPWtqTq+FAVHzPoGPDbL7m6y9eCw==:`,
		},
		want: "invalid bad_signature",
	},
	{
		name: "ParallaxGrain NV-10 signature-input-unreadable", now: 1735689660,
		method: "GET", url: "https://example.com/",
		header: map[string]string{
			"Signature-Agent": `sig1="https://signature-agent.test"`,
			"Signature-Input": `sig1=("@authority" "signature-agent";key="sig1";created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="web-bot-auth"`,
			"Signature":       `sig1=:JE1yD+mpEKRsD1jC6gpbZXXFMoupdDH6EEwU1+QKgwDGXftEABdV3XbSANQzNQxU7UtgavuSgunABEfoHBxtDQ==:`,
		},
		want: "invalid malformed",
	},
	{
		name: "ParallaxGrain NV-11 signature-value-unreadable", now: 1735689660,
		method: "GET", url: "https://example.com/",
		header: map[string]string{
			"Signature-Agent": `sig1="https://signature-agent.test"`,
			"Signature-Input": `sig1=("@authority" "signature-agent";key="sig1");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="web-bot-auth"`,
			"Signature":       `sig9=:JE1yD+mpEKRsD1jC6gpbZXXFMoupdDH6EEwU1+QKgwDGXftEABdV3XbSANQzNQxU7UtgavuSgunABEfoHBxtDQ==:`,
		},
		want: "invalid malformed",
	},
	// The set expects invalid: RFC 9421 Section 2.5 forbids a signature base
	// that holds a component twice, but httpsign, samesame's signature engine,
	// builds one.
	{
		name: "ParallaxGrain NV-19 duplicate-component", now: 1735689660,
		method: "GET", url: "https://example.com/",
		header: map[string]string{
			"Signature-Agent": `sig1="https://signature-agent.test"`,
			"Signature-Input": `sig1=("@authority" "@authority" "signature-agent";key="sig1");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="web-bot-auth"`,
			"Signature":       `sig1=:pI8eHSuMEPbVLPtEQK368TDMssBWtvsVc6NCuQyp1T6oMnk/Pkpxc4yJhm/kzHLNwqelACukRNMMgh0/FqtFBA==:`,
		},
		want: "verified ",
	},
	{
		name: "ParallaxGrain NV-12 signature-agent-absent", now: 1735689660,
		method: "GET", url: "https://example.com/",
		header: map[string]string{
			"Signature-Input": `sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="web-bot-auth"`,
			"Signature":       `sig1=:emtWW7ctXrq/Jxc/GrRNbHSTol22e5tabmwNFjtFnpl62D/XwZuJNpa4dUhOmI5Q3pYJNxMkA3bnLBUnm8xzBQ==:`,
		},
		want: "unverified key_unknown",
	},
	{
		name: "ParallaxGrain NV-13 signature-agent-ambiguous-member", now: 1735689660,
		method: "GET", url: "https://example.com/",
		header: map[string]string{
			"Signature-Agent": `first="https://signature-agent.test", second="https://other-agent.test"`,
			"Signature-Input": `sig1=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="web-bot-auth"`,
			"Signature":       `sig1=:+1vomCIkcZg+3SGgA/XX2FFlS13bVmSPQjBgCclNhatOKs08sckrIx723RIJ/gTAJPGvXfnP3O6W70q41C+BDg==:`,
		},
		want: "invalid profile",
	},
	{
		name: "ParallaxGrain NV-14 signature-agent-member-missing", now: 1735689660,
		method: "GET", url: "https://example.com/",
		header: map[string]string{
			"Signature-Agent": `other="https://signature-agent.test"`,
			"Signature-Input": `sig1=("@authority" "signature-agent";key="sig1");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="web-bot-auth"`,
			"Signature":       `sig1=:JE1yD+mpEKRsD1jC6gpbZXXFMoupdDH6EEwU1+QKgwDGXftEABdV3XbSANQzNQxU7UtgavuSgunABEfoHBxtDQ==:`,
		},
		want: "invalid profile",
	},
	// The set expects invalid, but samesame ignores a Signature-Agent member
	// that is not https, which leaves it no key directory.
	{
		name: "ParallaxGrain NV-16 signature-agent-not-https", now: 1735689660,
		method: "GET", url: "https://example.com/",
		header: map[string]string{
			"Signature-Agent": `sig1="http://signature-agent.test"`,
			"Signature-Input": `sig1=("@authority" "signature-agent";key="sig1");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="web-bot-auth"`,
			"Signature":       `sig1=:Mwv2BtF7JrgdsyTdpxNJzjc7BMWu0IvufR7FjzCJaYx1VZFDvSFvqnCyHQOBpH5HUmGfMmZHwmp2LAKsFt6cCA==:`,
		},
		want: "unverified key_unknown",
	},
	{
		name: "ParallaxGrain NV-17 signature-agent-not-origin", now: 1735689660,
		method: "GET", url: "https://example.com/",
		header: map[string]string{
			"Signature-Agent": `sig1="https://signature-agent.test/keys"`,
			"Signature-Input": `sig1=("@authority" "signature-agent";key="sig1");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="web-bot-auth"`,
			"Signature":       `sig1=:vIPkgnOG178b20lu4tMkGgyEPpsAOOFODichdLIrrNt0Y/KMQtoLxWrODh4srzzLySJtihrYgoP4bLWV+jweDw==:`,
		},
		want: "unverified key_unknown",
	},
	{
		name: "ParallaxGrain NV-18 signature-agent-unparsable", now: 1735689660,
		method: "GET", url: "https://example.com/",
		header: map[string]string{
			"Signature-Agent": `sig1="https://signature-agent.test`,
			"Signature-Input": `sig1=("@authority" "signature-agent";key="sig1");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;tag="web-bot-auth"`,
			"Signature":       `sig1=:JE1yD+mpEKRsD1jC6gpbZXXFMoupdDH6EEwU1+QKgwDGXftEABdV3XbSANQzNQxU7UtgavuSgunABEfoHBxtDQ==:`,
		},
		want: "invalid malformed",
	},
}
