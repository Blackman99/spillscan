// Package redact rewrites secrets inside agent transcripts safely.
package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Blackman99/spillscan/detect"
	"github.com/Blackman99/spillscan/paths"
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
	if paths.IsBinary(path) {
		return 0, "", nil // e.g. an MCP image copy under tool-results/
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, "", err
	}
	out, replaced := Scrub(raw, paths.IsJSONL(path))
	if !write || replaced == 0 {
		return replaced, "", nil
	}
	bak := path + ".bak"
	orig, err := backupContent(path, bak, raw)
	if err != nil {
		return 0, "", err
	}
	if err := os.WriteFile(bak, orig, 0o600); err != nil {
		return 0, "", fmt.Errorf("backup: %w", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return 0, bak, err
	}
	return replaced, bak, nil
}

// backupContent returns what <file>.bak should hold before a scrub. On a
// first scrub that is simply the current bytes. When an earlier scrub left a
// .bak and the agent has since appended to the transcript, the old backup is
// extended with the new tail so it keeps holding every original byte — a
// second `redact --write` must never overwrite the first originals.
func backupContent(path, bak string, raw []byte) ([]byte, error) {
	old, err := os.ReadFile(bak)
	if os.IsNotExist(err) {
		return raw, nil
	}
	if err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}
	scrubbed, _ := Scrub(old, paths.IsJSONL(path))
	if !bytes.HasPrefix(raw, scrubbed) {
		return nil, fmt.Errorf("%s already exists and does not match %s; move it aside (it may hold originals) and retry", bak, path)
	}
	return append(old, raw[len(scrubbed):]...), nil
}

// Scrub returns raw with every detected secret replaced by
// [REDACTED:<rule>] and the number of replacements. jsonl selects the
// JSON-aware per-line rewrite; anything else (Claude Code tool-results/ spill
// files) is plain text. Untouched lines keep their exact bytes, including
// CRLF and a missing final newline.
func Scrub(raw []byte, jsonl bool) ([]byte, int) {
	var out bytes.Buffer
	out.Grow(len(raw))
	replaced := 0
	for _, chunk := range bytes.SplitAfter(raw, []byte("\n")) {
		if len(chunk) == 0 {
			continue
		}
		body := chunk
		var eol []byte
		if bytes.HasSuffix(body, []byte("\n")) {
			body, eol = body[:len(body)-1], []byte("\n")
			if bytes.HasSuffix(body, []byte("\r")) {
				body, eol = body[:len(body)-1], []byte("\r\n")
			}
		}
		var newLine string
		var n int
		if jsonl {
			newLine, n = redactLine(string(body))
		} else {
			newLine, n = redactText(string(body))
		}
		replaced += n
		if n == 0 {
			out.Write(chunk)
			continue
		}
		out.WriteString(newLine)
		out.Write(eol)
	}
	return out.Bytes(), replaced
}

// redactText replaces secrets in a plain-text line in place.
func redactText(line string) (string, int) {
	findings := detect.Scan(line)
	b := []byte(line)
	for i := len(findings) - 1; i >= 0; i-- {
		f := findings[i]
		b = append(b[:f.Start:f.Start], append([]byte("[REDACTED:"+f.Rule+"]"), b[f.End:]...)...)
	}
	return string(b), len(findings)
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

// CollectJSONL expands paths to transcript files: *.jsonl, Claude Code's
// *.jsonl.superseded-* set-asides and tool-results/ spill files
// (see paths.IsTranscript). Explicit file paths are kept as given.
func CollectJSONL(in []string) ([]string, error) {
	var out []string
	for _, p := range in {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if st.IsDir() {
			out = append(out, paths.Walk(p)...)
		} else {
			out = append(out, p)
		}
	}
	return out, nil
}
