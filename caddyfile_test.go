package aegis

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
)

func TestCaddyfile(t *testing.T) {
	for _, tc := range []struct {
		name      string
		directive string
		wantErr   bool
	}{
		{"bare directive", "web_bot_auth", false},
		{"with a matcher", "web_bot_auth /api/*", false},
		{"with an argument", "web_bot_auth enforce", true},
		{"with a block", "web_bot_auth {\n\t\tmode enforce\n\t}", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caddyfile := "example.com {\n\t" + tc.directive + "\n}\n"
			_, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(caddyfile), nil)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("Adapt error = %v, want error: %t", err, tc.wantErr)
			}
		})
	}
}
