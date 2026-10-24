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
		{"with an unknown subdirective", "web_bot_auth {\n\t\tno_such_setting on\n\t}", true},
		{"allowed_hosts without a host", "web_bot_auth {\n\t\tallowed_hosts\n\t}", true},
		{"a setting without a value", "web_bot_auth {\n\t\tfetch_timeout\n\t}", true},
		{"a setting with two values", "web_bot_auth {\n\t\tfetch_timeout 1s 2s\n\t}", true},
		{"a duration that does not parse", "web_bot_auth {\n\t\tfetch_timeout soon\n\t}", true},
		{"a size that does not parse", "web_bot_auth {\n\t\tmax_directory_size big\n\t}", true},
		{"a count that does not parse", "web_bot_auth {\n\t\tmax_signatures many\n\t}", true},
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
