package main

import (
	"strings"
	"testing"
)

func TestRelease(t *testing.T) {
	for _, tc := range []struct {
		name      string
		changelog string
		version   string
		want      string
	}{
		{
			name: "after an earlier release",
			changelog: `# Changelog

Intro.

## [Unreleased]

### Added

- New directive. [#3](https://github.com/kauricre/aegis/pull/3)

### Changed

### Deprecated

### Fixed

- Fixed a bug. [#4](https://github.com/kauricre/aegis/pull/4)

## [1.0.0] - 2026-10-24

### Added

- First release. [#1](https://github.com/kauricre/aegis/pull/1)
`,
			version: "1.1.0",
			want: `# Changelog

Intro.

## [Unreleased]

### Added

### Changed

### Deprecated

### Fixed

## [1.1.0] - 2026-11-02

### Added

- New directive. [#3](https://github.com/kauricre/aegis/pull/3)

### Fixed

- Fixed a bug. [#4](https://github.com/kauricre/aegis/pull/4)

## [1.0.0] - 2026-10-24

### Added

- First release. [#1](https://github.com/kauricre/aegis/pull/1)
`,
		},
		{
			name: "first release",
			changelog: `# Changelog

## [Unreleased]

### Added

- First release. [#1](https://github.com/kauricre/aegis/pull/1)

### Changed

### Deprecated

### Fixed
`,
			version: "1.0.0",
			want: `# Changelog

## [Unreleased]

### Added

### Changed

### Deprecated

### Fixed

## [1.0.0] - 2026-11-02

### Added

- First release. [#1](https://github.com/kauricre/aegis/pull/1)
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := release(tc.changelog, tc.version, "2026-11-02")
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("release() =\n%s\nwant:\n%s", got, tc.want)
			}
		})
	}
}

func TestReleaseRefuses(t *testing.T) {
	const unreleased = "## [Unreleased]\n\n### Added\n\n- New directive. [#3](https://github.com/kauricre/aegis/pull/3)\n"

	for _, tc := range []struct {
		name      string
		changelog string
		version   string
		wantErr   string
	}{
		{
			name:      "entry without a pull request link",
			changelog: "## [Unreleased]\n\n### Added\n\n- New directive.\n",
			version:   "1.0.0",
			wantErr:   "no link to its pull request",
		},
		{
			name:      "version with a v prefix",
			changelog: unreleased,
			version:   "v1.0.0",
			wantErr:   "not MAJOR.MINOR.PATCH",
		},
		{
			name:      "pre-release version",
			changelog: unreleased,
			version:   "1.0.0-rc.1",
			wantErr:   "not MAJOR.MINOR.PATCH",
		},
		{
			name:      "version of the last release",
			changelog: unreleased + "\n## [1.0.0] - 2026-10-24\n\n### Added\n\n- First release. [#1](https://github.com/kauricre/aegis/pull/1)\n",
			version:   "1.0.0",
			wantErr:   "not greater than the last release",
		},
		{
			name:      "version below the last release",
			changelog: unreleased + "\n## [1.10.0] - 2026-10-24\n\n### Added\n\n- First release. [#1](https://github.com/kauricre/aegis/pull/1)\n",
			version:   "1.9.0",
			wantErr:   "not greater than the last release",
		},
		{
			name:      "last release heading without a version",
			changelog: unreleased + "\n## 1.0.0\n\n### Added\n\n- First release. [#1](https://github.com/kauricre/aegis/pull/1)\n",
			version:   "1.1.0",
			wantErr:   "names no MAJOR.MINOR.PATCH release",
		},
		{
			name:      "unknown category",
			changelog: "## [Unreleased]\n\n### Removed\n\n- Old directive. [#5](https://github.com/kauricre/aegis/pull/5)\n",
			version:   "1.0.0",
			wantErr:   `unknown category "Removed"`,
		},
		{
			name:      "entry outside a category",
			changelog: "## [Unreleased]\n\n- New directive. [#3](https://github.com/kauricre/aegis/pull/3)\n\n### Added\n",
			version:   "1.0.0",
			wantErr:   "entry outside a category",
		},
		{
			name:      "no entries",
			changelog: "## [Unreleased]\n\n### Added\n\n### Changed\n\n### Deprecated\n\n### Fixed\n",
			version:   "1.0.0",
			wantErr:   "nothing to release",
		},
		{
			name:      "no Unreleased section",
			changelog: "# Changelog\n",
			version:   "1.0.0",
			wantErr:   "no ## [Unreleased] section",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := release(tc.changelog, tc.version, "2026-11-02")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("release() error = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}
