package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Survey-meter palette as ANSI: amber for readouts, contam rust for hits,
// phosphor green for clean. Honors NO_COLOR and only paints real terminals.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiAmber  = "\x1b[38;5;178m"
	ansiContam = "\x1b[38;5;166m"
	ansiOK     = "\x1b[38;5;107m"
)

type painter struct{ on bool }

func newPainter(w io.Writer, force bool) painter {
	if force {
		return painter{}
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return painter{}
	}
	if os.Getenv("TERM") == "dumb" {
		return painter{}
	}
	f, ok := w.(*os.File)
	if !ok {
		return painter{}
	}
	st, err := f.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return painter{}
	}
	return painter{on: true}
}

func (p painter) wrap(code, s string) string {
	if !p.on || s == "" {
		return s
	}
	return code + s + ansiReset
}
func (p painter) bold(s string) string   { return p.wrap(ansiBold, s) }
func (p painter) dim(s string) string    { return p.wrap(ansiDim, s) }
func (p painter) amber(s string) string  { return p.wrap(ansiAmber, s) }
func (p painter) contam(s string) string { return p.wrap(ansiContam+ansiBold, s) }
func (p painter) ok(s string) string     { return p.wrap(ansiOK+ansiBold, s) }

// tildify shortens $HOME to ~ so tables stay readable and screenshots don't leak usernames.
func tildify(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	if path == home {
		return "~"
	}
	prefix := home + string(filepath.Separator)
	if strings.HasPrefix(path, prefix) {
		return "~" + string(filepath.Separator) + path[len(prefix):]
	}
	return path
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// suggest returns the closest known word within edit distance 2, or "".
func suggest(word string, known []string) string {
	best, bestD := "", 3
	for _, k := range known {
		if len(word) >= 3 && strings.HasPrefix(k, word) {
			return k
		}
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
