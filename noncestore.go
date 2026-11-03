package aegis

import (
	"context"
	"time"
)

// NonceStore is implemented by the modules in the http.web_bot_auth.nonce_stores
// namespace, which keep the nonces of verified signatures where several Caddy
// instances can share them.
//
// CheckAndRecord must check and record atomically, and return true when nonce
// is fresh in scope. scope is the agent's key directory URL, or "keyid:" and
// the keyid for static keys. until is the signature's expires plus clock_skew,
// after which the nonce may be forgotten. ctx carries the nonce_store_timeout deadline.
// An error makes the request unverified, with reason nonce_store.
//
// NonceStoreKey is equal for two stores exactly when they read and write the
// same nonces. Handlers whose stores return the same key share nonces. It must
// not contain secrets, because Aegis logs it.
type NonceStore interface {
	CheckAndRecord(ctx context.Context, scope, nonce string, until time.Time) (bool, error)
	NonceStoreKey() string
}
