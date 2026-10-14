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
