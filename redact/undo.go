package redact

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/Blackman99/spillscan/paths"
)

// Undo states for one transcript.
const (
	UndoExact    = "intact"   // file unchanged since the scrub
	UndoAppended = "appended" // agent appended lines after the scrub; they are kept
	UndoDiverged = "diverged" // file no longer starts with the scrubbed backup; left alone
	UndoMissing  = "missing"  // only the .bak is left
)

// UndoItem reports one backup.
type UndoItem struct {
	Path      string `json:"path"`
	Backup    string `json:"backup"`
	State     string `json:"state"`
	TailLines int    `json:"tail_lines,omitempty"` // lines appended after the scrub, kept as-is
}

// UndoResult describes an undo pass.
type UndoResult struct {
	DryRun   bool       `json:"dry_run"`
	Restored int        `json:"restored"`
	Skipped  int        `json:"skipped"`
	Items    []UndoItem `json:"items"`
}

// FindBackups returns every spillscan .bak under the given files or
// directories whose original is (or was) a transcript.
func FindBackups(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(bak string) {
		if !seen[bak] {
			seen[bak] = true
			out = append(out, bak)
		}
	}
	for _, p := range in {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			if b, ok := strings.CutSuffix(p, ".bak"); ok && paths.IsTranscript(b) {
				add(p)
			} else if _, err := os.Stat(p + ".bak"); err == nil {
				add(p + ".bak")
			}
			continue
		}
		for _, b := range paths.WalkBackups(p) {
			add(b)
		}
	}
	return out, nil
}

// Undo restores transcripts from the .bak files written by `redact --write`.
// It only restores when the current file still begins with exactly what the
// scrub produced from that backup; lines the agent appended afterwards are
// kept. With Write it rewrites the file and removes the then-redundant .bak.
func Undo(backups []string, opt Options) (*UndoResult, error) {
	res := &UndoResult{DryRun: !opt.Write, Items: []UndoItem{}}
	for _, bak := range backups {
		path := bak[:len(bak)-len(".bak")]
		it := UndoItem{Path: path, Backup: bak}
		orig, err := os.ReadFile(bak)
		if err != nil {
			return res, err
		}
		cur, err := os.ReadFile(path)
		switch {
		case os.IsNotExist(err):
			it.State = UndoMissing
		case err != nil:
			return res, err
		default:
			scrubbed, _ := Scrub(orig, paths.IsJSONL(path))
			if !bytes.HasPrefix(cur, scrubbed) {
				it.State = UndoDiverged
				break
			}
			tail := cur[len(scrubbed):]
			it.State = UndoExact
			if len(tail) > 0 {
				it.State = UndoAppended
				it.TailLines = bytes.Count(tail, []byte("\n"))
				if tail[len(tail)-1] != '\n' {
					it.TailLines++
				}
			}
			if opt.Write {
				if err := restore(path, bak, append(orig, tail...)); err != nil {
					return res, err
				}
			}
		}
		if it.State == UndoExact || it.State == UndoAppended {
			res.Restored++
		} else {
			res.Skipped++
		}
		res.Items = append(res.Items, it)
	}
	return res, nil
}

// restore writes data to path via a temp file + rename, then drops the .bak.
func restore(path, bak string, data []byte) error {
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp := path + ".spillscan-undo.tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("undo: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("undo: %w", err)
	}
	return os.Remove(bak)
}
