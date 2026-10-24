// Command changelog moves the entries under "## [Unreleased]" in CHANGELOG.md
// into a new section for a release. Run it from the repository root:
//
//	go run ./scripts/changelog 1.2.0
package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

// categories are the Unreleased subsections, in Keep a Changelog's order.
var categories = []string{"Added", "Changed", "Deprecated", "Fixed"}

// versionRE matches a release version. Pre-releases are not accepted, since
// ordering them needs the full precedence rules of Semantic Versioning.
var versionRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// entryRE matches an entry: one line that ends with a link to the pull
// request that made the change.
var entryRE = regexp.MustCompile(`^- .+ \[#[0-9]+\]\(https://github\.com/kauricre/aegis/pull/[0-9]+\)$`)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./scripts/changelog <version>")
		os.Exit(2)
	}
	b, err := os.ReadFile("CHANGELOG.md")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out, err := release(string(b), os.Args[1], time.Now().Format(time.DateOnly))
	if err != nil {
		fmt.Fprintln(os.Stderr, "changelog:", err)
		os.Exit(1)
	}
	if err := os.WriteFile("CHANGELOG.md", []byte(out), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// release returns changelog with its Unreleased entries moved into a new
// section for version, released on date.
func release(changelog, version, date string) (string, error) {
	if !versionRE.MatchString(version) {
		return "", fmt.Errorf("version %q is not MAJOR.MINOR.PATCH", version)
	}

	lines := strings.Split(strings.TrimSuffix(changelog, "\n"), "\n")
	start := slices.Index(lines, "## [Unreleased]")
	if start < 0 {
		return "", errors.New("no ## [Unreleased] section")
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "## ") {
			end = i
			break
		}
	}
	if end < len(lines) {
		last, _, _ := strings.Cut(strings.TrimPrefix(lines[end], "## ["), "]")
		if !versionRE.MatchString(last) {
			return "", fmt.Errorf("heading %q after Unreleased names no MAJOR.MINOR.PATCH release", lines[end])
		}
		if !greater(version, last) {
			return "", fmt.Errorf("version %s is not greater than the last release %s", version, last)
		}
	}

	entries := make(map[string][]string)
	var category string
	for _, line := range lines[start+1 : end] {
		switch {
		case line == "":
		case strings.HasPrefix(line, "### "):
			category = strings.TrimPrefix(line, "### ")
			if !slices.Contains(categories, category) {
				return "", fmt.Errorf("unknown category %q", category)
			}
		case category == "":
			return "", fmt.Errorf("entry outside a category: %s", line)
		case !entryRE.MatchString(line):
			return "", fmt.Errorf("entry has no link to its pull request: %s", line)
		default:
			entries[category] = append(entries[category], line)
		}
	}
	if len(entries) == 0 {
		return "", errors.New("nothing to release: Unreleased has no entries")
	}

	var b strings.Builder
	for _, line := range lines[:start] {
		b.WriteString(line + "\n")
	}
	b.WriteString("## [Unreleased]\n")
	for _, c := range categories {
		b.WriteString("\n### " + c + "\n")
	}
	b.WriteString("\n## [" + version + "] - " + date + "\n")
	for _, c := range categories {
		if len(entries[c]) == 0 {
			continue
		}
		b.WriteString("\n### " + c + "\n\n")
		for _, e := range entries[c] {
			b.WriteString(e + "\n")
		}
	}
	if end < len(lines) {
		b.WriteString("\n")
		for _, line := range lines[end:] {
			b.WriteString(line + "\n")
		}
	}
	return b.String(), nil
}

func greater(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := range as {
		if as[i] != bs[i] {
			// versionRE allows no leading zeros, so the longer number is the
			// larger one.
			return len(as[i]) > len(bs[i]) || len(as[i]) == len(bs[i]) && as[i] > bs[i]
		}
	}
	return false
}
