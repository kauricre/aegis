package aegis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
)

// TestExamples loads each example Caddyfile as caddy validate does: it adapts
// the file and provisions every module without starting a server. An adapter
// warning, such as the one for a file that caddy fmt would change, fails the
// test too, because a Caddyfile copied from the example would print it on
// every start.
func TestExamples(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("examples", "*.caddyfile"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no example Caddyfiles in examples/")
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			body, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			adapted, warnings, err := caddyconfig.GetAdapter("caddyfile").Adapt(body, map[string]any{"filename": file})
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range warnings {
				t.Errorf("adapter warning: %s", w)
			}
			var cfg *caddy.Config
			if err := caddy.StrictUnmarshalJSON(caddy.RemoveMetaFields(adapted), &cfg); err != nil {
				t.Fatal(err)
			}
			if err := caddy.Validate(cfg); err != nil {
				t.Fatal(err)
			}
		})
	}
}
