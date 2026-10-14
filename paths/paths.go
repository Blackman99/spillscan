// Package paths discovers local AI coding-agent transcript roots.
package paths

import (
	"os"
	"path/filepath"
	"strings"
)

// Root is one discovered transcript root.
type Root struct {
	Agent string `json:"agent"`
	Path  string `json:"path"`
	Files int    `json:"files"`
}

// Discover walks known agent homes under home (or $HOME).
func Discover(home string) ([]Root, error) {
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return nil, err
		}
	}
	specs := []struct {
		agent string
		globs []string
	}{
		{"claude-code", []string{
			filepath.Join(home, ".claude", "projects", "**", "*.jsonl"),
		}},
		{"codex", []string{
			filepath.Join(home, ".codex", "sessions", "**", "*.jsonl"),
			filepath.Join(home, ".codex", "transcripts", "**", "*.jsonl"),
		}},
		{"cursor", []string{
			filepath.Join(home, ".cursor", "projects", "**", "agent-transcripts", "**", "*.jsonl"),
			filepath.Join(home, ".cursor", "ai-tracking", "**", "*.jsonl"),
			filepath.Join(home, ".cursor", "chats", "**", "*.jsonl"),
		}},
		{"gemini-cli", []string{
			filepath.Join(home, ".gemini", "tmp", "**", "*.jsonl"),
			filepath.Join(home, ".gemini", "sessions", "**", "*.jsonl"),
		}},
		{"opencode", []string{
			filepath.Join(home, ".opencode", "sessions", "**", "*.jsonl"),
			filepath.Join(home, ".local", "share", "opencode", "sessions", "**", "*.jsonl"),
		}},
	}
	var out []Root
	for _, s := range specs {
		seen := map[string]struct{}{}
		var files []string
		for _, g := range s.globs {
			matches, err := expandGlob(g)
			if err != nil {
				continue
			}
			for _, m := range matches {
				if _, ok := seen[m]; ok {
					continue
				}
				seen[m] = struct{}{}
				files = append(files, m)
			}
		}
		if len(files) == 0 {
			// Still report the primary root if the directory exists.
			primary := strings.TrimSuffix(s.globs[0], string(filepath.Separator)+"**"+string(filepath.Separator)+"*.jsonl")
			primary = strings.ReplaceAll(primary, "**"+string(filepath.Separator), "")
			if st, err := os.Stat(filepath.Dir(primary)); err == nil && st.IsDir() {
				out = append(out, Root{Agent: s.agent, Path: filepath.Dir(primary), Files: 0})
			}
			continue
		}
		root := commonRoot(files)
		out = append(out, Root{Agent: s.agent, Path: root, Files: len(files)})
	}
	return out, nil
}

// ListFiles returns all transcript files for an agent under home.
func ListFiles(home, agent string) ([]string, error) {
	roots, err := Discover(home)
	if err != nil {
		return nil, err
	}
	var all []string
	for _, r := range roots {
		if agent != "" && r.Agent != agent {
			continue
		}
		_ = filepath.Walk(r.Path, func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			if strings.HasSuffix(info.Name(), ".jsonl") {
				all = append(all, p)
			}
			return nil
		})
	}
	return all, nil
}

func expandGlob(pattern string) ([]string, error) {
	// filepath.Glob does not support **; walk manually.
	parts := strings.Split(pattern, "**")
	if len(parts) == 1 {
		return filepath.Glob(pattern)
	}
	base := strings.TrimSuffix(parts[0], string(filepath.Separator))
	suffix := strings.TrimPrefix(parts[len(parts)-1], string(filepath.Separator))
	if st, err := os.Stat(base); err != nil || !st.IsDir() {
		return nil, nil
	}
	var out []string
	_ = filepath.Walk(base, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		ok, _ := filepath.Match(suffix, info.Name())
		if suffix == "*.jsonl" {
			ok = strings.HasSuffix(info.Name(), ".jsonl")
		}
		if ok {
			out = append(out, p)
		}
		return nil
	})
	return out, nil
}

func commonRoot(files []string) string {
	if len(files) == 0 {
		return ""
	}
	root := filepath.Dir(files[0])
	for _, f := range files[1:] {
		d := filepath.Dir(f)
		for !strings.HasPrefix(d+string(filepath.Separator), root+string(filepath.Separator)) && root != "/" && root != "." {
			root = filepath.Dir(root)
		}
	}
	return root
}

// Agents lists the agent names Discover knows, in display order.
var Agents = []string{"claude-code", "codex", "cursor", "gemini-cli", "opencode"}
