// Package allow loads the false-positive allowlist: findings it matches are
// left out of scan, redact and the MCP scan_report.
//
// File format (one entry per line, '#' starts a comment):
//
//	fp:3f9a1c0b7e21                             # one value, by the fingerprint scan prints
//	rule:jwt path:~/.claude/projects/*docs*/**  # one rule in some transcripts
//	path:~/.codex/sessions/2026/01/**           # every rule under a path
//	rule:generic-assign                         # a whole rule, everywhere
//	value:AKIAIOSFODNN7EXAMPLE                  # a literal, known-fake value
//
// Keys on one line must all match (AND). Lines are OR'ed.
package allow

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Blackman99/spillscan/detect"
)

// Keys lists the entry keys the file format accepts.
var Keys = []string{"fp", "rule", "path", "value"}

type entry struct {
	fp, rule, value string
	glob            *regexp.Regexp
	src             string // file:line, for messages
}

// List is a loaded allowlist. A nil *List allows nothing.
type List struct {
	entries []entry
	// Files are the allowlist files that were read, in load order.
	Files []string
}

// DefaultPath is $XDG_CONFIG_HOME/spillscan/allow.txt, falling back to
// ~/.config/spillscan/allow.txt on every OS.
func DefaultPath() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "spillscan", "allow.txt")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "spillscan", "allow.txt")
}

// Load reads the default allowlist (when useDefault and it exists) plus
// every file in extra, which must exist.
func Load(useDefault bool, extra []string) (*List, error) {
	l := &List{}
	if useDefault {
		if p := DefaultPath(); p != "" {
			if _, err := os.Stat(p); err == nil {
				if err := l.addFile(p); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, p := range extra {
		if slices.Contains(l.Files, p) {
			continue
		}
		if err := l.addFile(p); err != nil {
			return nil, err
		}
	}
	return l, nil
}

func (l *List) addFile(p string) error {
	f, err := os.Open(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("allowlist not found: %s", p)
		}
		return fmt.Errorf("allowlist: %w", err)
	}
	defer f.Close()
	es, err := parse(f, p)
	if err != nil {
		return err
	}
	l.entries = append(l.entries, es...)
	l.Files = append(l.Files, p)
	return nil
}

// parse reads allowlist entries; src names the input in error messages.
func parse(r io.Reader, src string) ([]entry, error) {
	var out []entry
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		e, ok, err := parseLine(sc.Text())
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", src, n, err)
		}
		if ok {
			e.src = fmt.Sprintf("%s:%d", src, n)
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

var hexRe = regexp.MustCompile(`^[0-9a-f]{8,64}$`)

func parseLine(line string) (entry, bool, error) {
	var e entry
	seen := map[string]bool{}
	for _, tok := range strings.Fields(line) {
		if strings.HasPrefix(tok, "#") {
			break
		}
		key, val, ok := strings.Cut(tok, ":")
		if !ok || !slices.Contains(Keys, key) {
			if hexRe.MatchString(strings.ToLower(tok)) {
				return e, false, fmt.Errorf("bare %q: write it as fp:%s", tok, strings.ToLower(tok))
			}
			if ok {
				return e, false, fmt.Errorf("unknown key %q (use %s)", key+":", strings.Join(keyList(), ", "))
			}
			return e, false, fmt.Errorf("%q is not key:value (use %s)", tok, strings.Join(keyList(), ", "))
		}
		if seen[key] {
			return e, false, fmt.Errorf("%s: given twice on one line; put alternatives on separate lines", key)
		}
		seen[key] = true
		if val == "" {
			return e, false, fmt.Errorf("%s: is empty", key)
		}
		switch key {
		case "fp":
			v := strings.ToLower(val)
			if !hexRe.MatchString(v) {
				return e, false, fmt.Errorf("fp:%s is not a fingerprint (8-64 hex chars, as printed by spillscan scan)", val)
			}
			e.fp = v
		case "rule":
			if !slices.Contains(detect.RuleIDs(), val) {
				msg := fmt.Sprintf("unknown rule %q", val)
				if s := closest(val, detect.RuleIDs()); s != "" {
					msg += fmt.Sprintf(" (did you mean rule:%s?)", s)
				}
				return e, false, errors.New(msg)
			}
			e.rule = val
		case "path":
			re, err := compileGlob(val)
			if err != nil {
				return e, false, err
			}
			e.glob = re
		case "value":
			e.value = val
		}
	}
	return e, len(seen) > 0, nil
}

func keyList() []string {
	out := make([]string, len(Keys))
	for i, k := range Keys {
		out[i] = k + ":"
	}
	return out
}

// Allowed reports whether a finding of rule with secret in path is
// allowlisted. path may be relative; it is made absolute before matching.
func (l *List) Allowed(rule, secret, path string) bool {
	if l == nil || len(l.entries) == 0 {
		return false
	}
	abs := path
	if a, err := filepath.Abs(path); err == nil {
		abs = a
	}
	abs = filepath.ToSlash(abs)
	fp := ""
	for _, e := range l.entries {
		if e.rule != "" && e.rule != rule {
			continue
		}
		if e.value != "" && e.value != secret {
			continue
		}
		if e.fp != "" {
			if fp == "" {
				fp = detect.Fingerprint(secret)
			}
			if !strings.HasPrefix(fp, e.fp) {
				continue
			}
		}
		if e.glob != nil && !e.glob.MatchString(abs) {
			continue
		}
		return true
	}
	return false
}

// For binds the list to one file, for redact's per-file scrub.
func (l *List) For(path string) func(rule, secret string) bool {
	if l == nil || len(l.entries) == 0 {
		return nil
	}
	return func(rule, secret string) bool { return l.Allowed(rule, secret, path) }
}

// Len is the number of entries loaded.
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.entries)
}

// compileGlob turns a path glob into an anchored regexp over slash paths.
//
//   - any run of characters except '/'
//     ** any run of characters, '/' included ("**/" may also match nothing)
//     ?  one character except '/'
//
// "~/" expands to $HOME. A pattern without '/' matches the file name; an
// absolute pattern matches the whole path; any other pattern matches a
// trailing run of path segments (like .gitignore).
func compileGlob(g string) (*regexp.Regexp, error) {
	pat := g
	if strings.HasPrefix(pat, "~/") || pat == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("path:%s: cannot expand ~: %w", g, err)
		}
		pat = filepath.ToSlash(home) + pat[1:]
	}
	pat = filepath.ToSlash(pat)
	var b strings.Builder
	switch {
	case !strings.Contains(pat, "/"):
		b.WriteString(`^(?:.*/)?`)
	case strings.HasPrefix(pat, "/") || filepath.IsAbs(pat) || (len(pat) > 1 && pat[1] == ':'):
		b.WriteString(`^`)
	default:
		b.WriteString(`^(?:.*/)?`)
	}
	for i := 0; i < len(pat); i++ {
		c := pat[i]
		switch {
		case c == '*' && i+1 < len(pat) && pat[i+1] == '*':
			i++
			if i+1 < len(pat) && pat[i+1] == '/' {
				i++
				b.WriteString(`(?:.*/)?`)
			} else {
				b.WriteString(`.*`)
			}
		case c == '*':
			b.WriteString(`[^/]*`)
		case c == '?':
			b.WriteString(`[^/]`)
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(`$`)
	return regexp.Compile(b.String())
}

func closest(word string, known []string) string {
	best, bestD := "", 3
	for _, k := range known {
		if d := lev(word, k); d < bestD {
			best, bestD = k, d
		}
	}
	return best
}

func lev(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			c := 1
			if a[i-1] == b[j-1] {
				c = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+c)
		}
		prev = cur
	}
	return prev[len(b)]
}
