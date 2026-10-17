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

func TestIsTranscript(t *testing.T) {
	sess := filepath.Join("home", ".claude", "projects", "-p", "abc")
	cases := map[string]bool{
		sess + ".jsonl":                                    true,
		sess + ".orphaned-1-2.jsonl":                       true,
		sess + ".jsonl.superseded-2026-10-17T03-00-00Z":    true,
		filepath.Join(sess, "subagents", "agent-1.jsonl"):  true,
		filepath.Join(sess, "tool-results", "toolu_1.txt"): true,
		filepath.Join(sess, "tool-results", "toolu_2"):     true,
		filepath.Join(sess, "tool-results", "t.json"):      true,
		filepath.Join(sess, "tool-results", "img.PNG"):     false,
		filepath.Join(sess, "tool-results", "t.txt.bak"):   false,
		sess + ".jsonl.bak":                                false,
		sess + ".jsonl.superseded-1.bak":                   false,
		filepath.Join(sess, "notes.txt"):                   false,
		filepath.Join("x", "my-tool-results", "a.txt"):     false,
	}
	for p, want := range cases {
		if got := IsTranscript(p); got != want {
			t.Errorf("IsTranscript(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestDiscoverClaudeSpillCopies(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, ".claude", "projects", "-p")
	tr := filepath.Join(proj, "abc", "tool-results")
	_ = os.MkdirAll(tr, 0o755)
	for name, body := range map[string]string{
		filepath.Join(proj, "abc.jsonl"):                                 "{}\n",
		filepath.Join(proj, "abc.jsonl.superseded-2026-10-17T03-00-00Z"): "{}\n",
		filepath.Join(tr, "toolu_1.txt"):                                 "plain\n",
		filepath.Join(tr, "shot.png"):                                    "\x89PNG\x00",
		filepath.Join(proj, "abc.jsonl.bak"):                             "{}\n",
	} {
		if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := ListFiles(home, "claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("want transcript + superseded + tool-results file, got %v", files)
	}
	roots, _ := Discover(home)
	if len(roots) != 1 || roots[0].Files != 3 {
		t.Fatalf("roots: %#v", roots)
	}
}
