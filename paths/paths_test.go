package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscover(t *testing.T) {
	home := t.TempDir()
	claude := filepath.Join(home, ".claude", "projects", "demo")
	codex := filepath.Join(home, ".codex", "sessions", "2026")
	_ = os.MkdirAll(claude, 0o755)
	_ = os.MkdirAll(codex, 0o755)
	_ = os.WriteFile(filepath.Join(claude, "a.jsonl"), []byte("{}\n"), 0o644)
	_ = os.WriteFile(filepath.Join(codex, "b.jsonl"), []byte("{}\n"), 0o644)

	roots, err := Discover(home)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Root{}
	for _, r := range roots {
		by[r.Agent] = r
	}
	if by["claude-code"].Files != 1 {
		t.Fatalf("claude files: %#v", by["claude-code"])
	}
	if by["codex"].Files != 1 {
		t.Fatalf("codex files: %#v", by["codex"])
	}
}
