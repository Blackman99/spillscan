// Package scan walks transcript files and reports secret findings.
package scan

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Blackman99/spillscan/detect"
	"github.com/Blackman99/spillscan/paths"
)

// Finding is a secret hit located in a transcript.
type Finding struct {
	Rule    string    `json:"rule"`
	Preview string    `json:"preview"`
	Path    string    `json:"path"`
	Line    int       `json:"line"`
	Offset  int       `json:"offset"`
	Agent   string    `json:"agent"`
	Mtime   time.Time `json:"mtime"`
	Secret  string    `json:"-"`
}

// Result aggregates a scan.
type Result struct {
	Files     int          `json:"files"`
	Findings  []Finding    `json:"findings"`
	Skipped   []string     `json:"skipped,omitempty"` // files that could not be read
	Roots     []paths.Root `json:"roots,omitempty"`
	ScannedAt time.Time    `json:"scanned_at"`
}

// Options controls scan scope.
type Options struct {
	Home  string
	Agent string
	Paths []string // explicit files or dirs; empty = discover
}

// Run discovers (or uses Paths) and scans transcripts (see paths.IsTranscript).
func Run(opt Options) (*Result, error) {
	res := &Result{ScannedAt: time.Now().UTC(), Findings: []Finding{}}
	var files []string
	if len(opt.Paths) > 0 {
		for _, p := range opt.Paths {
			st, err := os.Stat(p)
			if err != nil {
				if os.IsNotExist(err) {
					return nil, fmt.Errorf("path not found: %s", p)
				}
				return nil, err
			}
			if st.IsDir() {
				files = append(files, paths.Walk(p)...)
			} else {
				files = append(files, p)
			}
		}
	} else {
		roots, err := paths.Discover(opt.Home)
		if err != nil {
			return nil, err
		}
		res.Roots = roots
		files, err = paths.ListFiles(opt.Home, opt.Agent)
		if err != nil {
			return nil, err
		}
	}
	res.Files = len(files)
	for _, f := range files {
		fs, err := scanFile(f)
		if err != nil {
			res.Skipped = append(res.Skipped, f)
		}
		res.Findings = append(res.Findings, fs...)
	}
	return res, nil
}

func scanFile(path string) ([]Finding, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if paths.IsBinary(path) {
		return nil, nil // e.g. an MCP image copy under tool-results/
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	agent := inferAgent(path)
	var out []Finding
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		for _, d := range detect.Scan(line) {
			out = append(out, Finding{
				Rule:    d.Rule,
				Preview: d.Preview,
				Path:    path,
				Line:    lineNo,
				Offset:  d.Start,
				Agent:   agent,
				Mtime:   st.ModTime().UTC(),
				Secret:  d.Secret,
			})
		}
	}
	return out, sc.Err()
}

func inferAgent(path string) string {
	p := filepath.ToSlash(path)
	switch {
	case strings.Contains(p, "/.claude/"):
		return "claude-code"
	case strings.Contains(p, "/.codex/"):
		return "codex"
	case strings.Contains(p, "/.cursor/"):
		return "cursor"
	case strings.Contains(p, "/.gemini/"):
		return "gemini-cli"
	case strings.Contains(p, "/opencode/"):
		return "opencode"
	default:
		return "unknown"
	}
}
