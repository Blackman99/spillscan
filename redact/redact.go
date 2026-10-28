// Package redact rewrites secrets inside agent transcripts safely.
package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Blackman99/spillscan/allow"
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
	// Allowlisted counts detected values an allowlist entry kept in place.
	Allowlisted int `json:"allowlisted"`
}

// Options controls redaction.
type Options struct {
	Write bool        // false = dry-run
	Allow *allow.List // matching findings are left untouched
}

// Run redacts secrets in the given files. Always writes .bak when Write.
func Run(files []string, opt Options) (*Result, error) {
	res := &Result{DryRun: !opt.Write, PerFile: map[string]int{}}
	for _, path := range files {
		n, kept, bak, err := redactFile(path, opt.Write, opt.Allow.For(path))
		if err != nil {
			return res, err
		}
		res.Allowlisted += kept
		res.Files++
		res.Replaced += n
		res.PerFile[path] = n
		if bak != "" {
			res.Backups = append(res.Backups, bak)
		}
	}
	return res, nil
}

func redactFile(path string, write bool, skip Skip) (replaced, kept int, backup string, err error) {
	if paths.IsBinary(path) {
		return 0, 0, "", nil // e.g. an MCP image copy under tool-results/
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, "", err
	}
	out, replaced, kept := ScrubWith(raw, paths.IsJSONL(path), skip)
	if !write || replaced == 0 {
		return replaced, kept, "", nil
	}
	bak := path + ".bak"
	orig, err := backupContent(path, bak, raw, skip)
	if err != nil {
		return 0, 0, "", err
	}
	if err := os.WriteFile(bak, orig, 0o600); err != nil {
		return 0, 0, "", fmt.Errorf("backup: %w", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return 0, 0, bak, err
	}
	return replaced, kept, bak, nil
}

// scrubbedPrefix finds what an earlier scrub of orig produced inside cur.
// That scrub may have run with the allowlist in force now, or before the
// allowlist existed, so both are tried. ok is false if cur does not start
// with either (the file was edited some other way).
func scrubbedPrefix(orig, cur []byte, jsonl bool, skip Skip) (n int, ok bool) {
	cands := []Skip{skip}
	if skip != nil {
		cands = append(cands, nil)
	}
	for _, s := range cands {
		scrubbed, _, _ := ScrubWith(orig, jsonl, s)
		if bytes.HasPrefix(cur, scrubbed) {
			return len(scrubbed), true
		}
	}
	return 0, false
}

// backupContent returns what <file>.bak should hold before a scrub. On a
// first scrub that is simply the current bytes. When an earlier scrub left a
// .bak and the agent has since appended to the transcript, the old backup is
// extended with the new tail so it keeps holding every original byte — a
// second `redact --write` must never overwrite the first originals.
func backupContent(path, bak string, raw []byte, skip Skip) ([]byte, error) {
	old, err := os.ReadFile(bak)
	if os.IsNotExist(err) {
		return raw, nil
	}
	if err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}
	n, ok := scrubbedPrefix(old, raw, paths.IsJSONL(path), skip)
	if !ok {
		return nil, fmt.Errorf("%s already exists and does not match %s; move it aside (it may hold originals) and retry", bak, path)
	}
	return append(old, raw[n:]...), nil
}

// Skip reports whether a detected value must be left in place
// (allowlisted). A nil Skip keeps nothing.
type Skip func(rule, secret string) bool

// Scrub returns raw with every detected secret replaced by
// [REDACTED:<rule>] and the number of replacements. jsonl selects the
// JSON-aware per-line rewrite; anything else (Claude Code tool-results/ spill
// files) is plain text. Untouched lines keep their exact bytes, including
// CRLF and a missing final newline.
func Scrub(raw []byte, jsonl bool) ([]byte, int) {
	out, n, _ := ScrubWith(raw, jsonl, nil)
	return out, n
}

// ScrubWith is Scrub that leaves values skip accepts in place; kept counts
// them. A line whose every finding is kept is left byte-for-byte unchanged.
func ScrubWith(raw []byte, jsonl bool, skip Skip) (out []byte, replaced, kept int) {
	sc := &scrubber{skip: skip}
	var buf bytes.Buffer
	buf.Grow(len(raw))
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
			newLine, n = sc.line(string(body))
		} else {
			newLine, n = sc.text(string(body))
		}
		replaced += n
		if n == 0 {
			buf.Write(chunk)
			continue
		}
		buf.WriteString(newLine)
		buf.Write(eol)
	}
	return buf.Bytes(), replaced, sc.kept
}

type scrubber struct {
	skip Skip
	kept int
}

// filter drops kept findings, counting them when count is set. decoded marks
// text that came out of a JSON string: scan sees the escaped form (a PEM key
// has \n, not newlines), so both forms are checked against the allowlist.
func (sc *scrubber) filter(fs []detect.Finding, decoded, count bool) []detect.Finding {
	if sc.skip == nil {
		return fs
	}
	out := fs[:0:0]
	for _, f := range fs {
		if sc.skip(f.Rule, f.Secret) || (decoded && sc.skip(f.Rule, jsonEscape(f.Secret))) {
			if count {
				sc.kept++
			}
			continue
		}
		out = append(out, f)
	}
	return out
}

func jsonEscape(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(s) != nil {
		return s
	}
	out := bytes.TrimSuffix(b.Bytes(), []byte("\n"))
	return string(out[1 : len(out)-1])
}

func replaceSpans(s string, fs []detect.Finding) string {
	b := []byte(s)
	for i := len(fs) - 1; i >= 0; i-- {
		f := fs[i]
		b = append(b[:f.Start:f.Start], append([]byte("[REDACTED:"+f.Rule+"]"), b[f.End:]...)...)
	}
	return string(b)
}

// text replaces secrets in a plain-text line in place.
func (sc *scrubber) text(line string) (string, int) {
	fs := sc.filter(detect.Scan(line), false, true)
	if len(fs) == 0 {
		return line, 0
	}
	return replaceSpans(line, fs), len(fs)
}

func (sc *scrubber) line(line string) (string, int) {
	all := detect.Scan(line)
	if len(all) == 0 {
		return line, 0
	}
	// Leave the line byte-identical when everything on it is allowlisted.
	if live := sc.filter(all, false, false); len(live) == 0 {
		sc.kept += len(all)
		return line, 0
	}
	// Try JSON-aware rewrite.
	var v any
	if json.Unmarshal([]byte(line), &v) == nil {
		n := 0
		v2 := sc.walk(v, &n)
		if b, err := json.Marshal(v2); err == nil {
			return string(b), n
		}
	}
	// Fallback: replace raw spans from the end so offsets stay valid.
	fs := sc.filter(all, false, true)
	return replaceSpans(line, fs), len(fs)
}

func (sc *scrubber) walk(v any, n *int) any {
	switch t := v.(type) {
	case string:
		fs := sc.filter(detect.Scan(t), true, true)
		if len(fs) == 0 {
			return t
		}
		*n += len(fs)
		return replaceSpans(t, fs)
	case map[string]any:
		for k, vv := range t {
			t[k] = sc.walk(vv, n)
		}
		return t
	case []any:
		for i, vv := range t {
			t[i] = sc.walk(vv, n)
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
