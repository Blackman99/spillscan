// Package redact rewrites secrets inside JSONL transcripts safely.
package redact

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Blackman99/spillscan/detect"
)

// Result describes a redaction pass.
type Result struct {
	Files    int            `json:"files"`
	Replaced int            `json:"replaced"`
	Backups  []string       `json:"backups,omitempty"`
	DryRun   bool           `json:"dry_run"`
	PerFile  map[string]int `json:"per_file,omitempty"`
}

// Options controls redaction.
type Options struct {
	Write bool // false = dry-run
}

// Run redacts secrets in the given files. Always writes .bak when Write.
func Run(files []string, opt Options) (*Result, error) {
	res := &Result{DryRun: !opt.Write, PerFile: map[string]int{}}
	for _, path := range files {
		n, bak, err := redactFile(path, opt.Write)
		if err != nil {
			return res, err
		}
		res.Files++
		res.Replaced += n
		res.PerFile[path] = n
		if bak != "" {
			res.Backups = append(res.Backups, bak)
		}
	}
	return res, nil
}

func redactFile(path string, write bool) (replaced int, backup string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, "", err
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var out bytes.Buffer
	for sc.Scan() {
		line := sc.Text()
		newLine, n := redactLine(line)
		replaced += n
		out.WriteString(newLine)
		out.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return 0, "", err
	}
	if !write || replaced == 0 {
		return replaced, "", nil
	}
	bak := path + ".bak"
	if err := os.WriteFile(bak, raw, 0o600); err != nil {
		return 0, "", fmt.Errorf("backup: %w", err)
	}
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		return 0, bak, err
	}
	return replaced, bak, nil
}

func redactLine(line string) (string, int) {
	findings := detect.Scan(line)
	if len(findings) == 0 {
		return line, 0
	}
	// Try JSON-aware rewrite.
	var v any
	if json.Unmarshal([]byte(line), &v) == nil {
		n := 0
		v2 := walkReplace(v, &n)
		b, err := json.Marshal(v2)
		if err == nil {
			return string(b), n
		}
	}
	// Fallback: replace from end so offsets stay valid.
	b := []byte(line)
	n := 0
	for i := len(findings) - 1; i >= 0; i-- {
		f := findings[i]
		repl := []byte("[REDACTED:" + f.Rule + "]")
		b = append(b[:f.Start], append(repl, b[f.End:]...)...)
		n++
	}
	return string(b), n
}

func walkReplace(v any, n *int) any {
	switch t := v.(type) {
	case string:
		fs := detect.Scan(t)
		if len(fs) == 0 {
			return t
		}
		b := []byte(t)
		for i := len(fs) - 1; i >= 0; i-- {
			f := fs[i]
			repl := []byte("[REDACTED:" + f.Rule + "]")
			b = append(b[:f.Start], append(repl, b[f.End:]...)...)
			*n++
		}
		return string(b)
	case map[string]any:
		for k, vv := range t {
			t[k] = walkReplace(vv, n)
		}
		return t
	case []any:
		for i, vv := range t {
			t[i] = walkReplace(vv, n)
		}
		return t
	default:
		return v
	}
}

// CollectJSONL expands paths to .jsonl files.
func CollectJSONL(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if st.IsDir() {
			err = filepath.Walk(p, func(fp string, info os.FileInfo, err error) error {
				if err == nil && info != nil && !info.IsDir() && strings.HasSuffix(info.Name(), ".jsonl") {
					out = append(out, fp)
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
		} else {
			out = append(out, p)
		}
	}
	return out, nil
}
