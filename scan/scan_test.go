package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanFixture(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sess.jsonl")
	content := `{"type":"tool_result","content":"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nOPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz012345"}` + "\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(Options{Paths: []string{p}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) < 2 {
		t.Fatalf("want >=2 findings, got %#v", res.Findings)
	}
}

func TestScanDirIncludesClaudeSpillCopies(t *testing.T) {
	dir := t.TempDir()
	tr := filepath.Join(dir, "abc", "tool-results")
	if err := os.MkdirAll(tr, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(tr, "toolu_1.txt"), "line one\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
	write(filepath.Join(dir, "abc.jsonl.superseded-2026-10-17T03-00-00Z"), `{"content":"xoxp-TESTONLY00-spillscanfixture000001"}`+"\n")
	write(filepath.Join(tr, "blob.bin"), "AKIAIOSFODNN7EXAMPLE\x00\x01")
	res, err := Run(Options{Paths: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 3 {
		t.Fatalf("files=%d", res.Files)
	}
	got := map[string]int{}
	for _, f := range res.Findings {
		got[filepath.Base(f.Path)]++
		if filepath.Base(f.Path) == "toolu_1.txt" && f.Line != 2 {
			t.Fatalf("line=%d", f.Line)
		}
	}
	if got["toolu_1.txt"] == 0 || got["abc.jsonl.superseded-2026-10-17T03-00-00Z"] == 0 {
		t.Fatalf("missing findings: %v", got)
	}
	if got["blob.bin"] != 0 {
		t.Fatal("binary file should be skipped")
	}
}
