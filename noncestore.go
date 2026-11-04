package aegis

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// NonceStore is implemented by the modules in the http.web_bot_auth.nonce_stores
// namespace, which keep the nonces of verified signatures where several Caddy
// instances can share them.
//
// CheckAndRecord must check and record atomically, and return true when nonce
// is fresh in scope. scope is the agent's key directory URL, or "keyid:" and
// the keyid for static keys. until is the signature's expires plus clock_skew,
// after which the nonce may be forgotten. ctx carries the nonce_store_timeout
// deadline, and CheckAndRecord must return once ctx is done. Aegis calls it
// concurrently.
//
// CheckAndRecord returns an error only when the store cannot answer. Every
// error makes the request unverified, with reason nonce_store, and counts as
// the store failing, so checks of that store fail at once for at least 10s,
// in every handler whose store returns the same NonceStoreKey.
//
// NonceStoreKey is equal for two stores exactly when they read and write the
// same nonces. Handlers whose stores return the same key share nonces. It must
// not contain secrets, because Aegis logs it.
type NonceStore interface {
	CheckAndRecord(ctx context.Context, scope, nonce string, until time.Time) (bool, error)
	NonceStoreKey() string
}

// nonceStoreRetryAfter is how long a nonce store goes unasked after it failed.
// Tests lower it.
var nonceStoreRetryAfter = 10 * time.Second

// defaultNonceStoreTimeout is how long one check waits for a nonce store when
// nonce_store_timeout is absent.
const defaultNonceStoreTimeout = 250 * time.Millisecond

// storeHealths holds a *storeHealth for each NonceStoreKey. Handlers with the
// same store share it, also across config reloads, so that neither a second
// directive nor a reload asks a failing store again or logs its failure again.
var storeHealths = caddy.NewUsagePool()

// storeHealth is whether a nonce store is failing, when it last failed, and
// whether a check asks it while it fails.
type storeHealth struct {
	mu       sync.Mutex
	failing  bool
	failedAt time.Time
	probing  bool
}

// guardedStore is a nonce store module behind a time limit for each check.
// Once the module fails, every check fails at once without asking it until
// nonceStoreRetryAfter has passed since its last failure. Then one check at a
// time asks it, and the others still fail at once. guardedStore logs when the
// module starts failing and when it answers again.
//
// key is the module's NonceStoreKey, read once at Provision, so that no check
// waits for the module while it holds health.mu.
type guardedStore struct {
	store   NonceStore
	key     string
	health  *storeHealth
	timeout time.Duration
	logger  *zap.Logger
}

func (g guardedStore) CheckAndRecord(ctx context.Context, scope, nonce string, until time.Time) (bool, error) {
	g.health.mu.Lock()
	if g.health.failing && (g.health.probing || time.Since(g.health.failedAt) < nonceStoreRetryAfter) {
		g.health.mu.Unlock()
		return false, errors.New("nonce store failed recently")
	}
	// The check that comes after the window asks the failing store alone, so
	// a burst of requests waits for one timeout and not one each.
	probe := g.health.failing
	if probe {
		g.health.probing = true
	}
	start := time.Now()
	g.health.mu.Unlock()

	type answer struct {
		fresh bool
		err   error
	}
	// The channel holds the answer, so the goroutine of a store that answers
	// after the check gave up still ends.
	answers := make(chan answer, 1)
	sctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	go func() {
		// net/http recovers a panic only on the request's goroutine, so a
		// panic of the store here would stop Caddy. It becomes the answer
		// instead, the only one sent.
		defer func() {
			if v := recover(); v != nil {
				answers <- answer{err: fmt.Errorf("nonce store panicked: %v", v)}
			}
		}()
		fresh, err := g.store.CheckAndRecord(sctx, scope, nonce, until)
		answers <- answer{fresh, err}
	}()
	// Waiting for sctx and not only for the store keeps a store that ignores
	// sctx from holding the request.
	var a answer
	select {
	case a = <-answers:
	case <-sctx.Done():
		a.err = sctx.Err()
	}

	g.health.mu.Lock()
	defer g.health.mu.Unlock()
	if probe {
		g.health.probing = false
	}
	switch {
	case a.err != nil && ctx.Err() != nil:
		// The request ended, as when its client disconnects, which says
		// nothing about the store.
	case a.err != nil:
		if !g.health.failing {
			g.health.failing = true
			g.logger.Warn("nonce store failed: signed requests get unverified with reason nonce_store until it answers",
				zap.String("store", g.key), zap.Error(a.err))
		}
		g.health.failedAt = time.Now()
	case g.health.failing && start.After(g.health.failedAt):
		// A check that started before the last failure can succeed after it,
		// which says nothing about the store now.
		g.health.failing = false
		g.logger.Info("nonce store answers again", zap.String("store", g.key))
	}
	return a.fresh, a.err
}
