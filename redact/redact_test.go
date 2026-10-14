package redact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactRoundTripJSONL(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.jsonl")
	line := `{"type":"tool_result","content":"key=AKIAIOSFODNN7EXAMPLE and sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD"}`
	if err := os.WriteFile(p, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run([]string{p}, Options{Write: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Replaced < 2 {
		t.Fatalf("replaced=%d", res.Replaced)
	}
	raw, _ := os.ReadFile(p)
	s := string(raw)
	if strings.Contains(s, "AKIA") || strings.Contains(s, "sk-ant-api03-abcdefgh") {
		t.Fatalf("secret still present: %s", s)
	}
	if !strings.Contains(s, "[REDACTED:") {
		t.Fatalf("missing redaction marker: %s", s)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &v); err != nil {
		t.Fatalf("invalid JSON after redact: %v\n%s", err, s)
	}
	bak := p + ".bak"
	if _, err := os.Stat(bak); err != nil {
		t.Fatalf("missing bak: %v", err)
	}
}

func TestDryRun(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.jsonl")
	_ = os.WriteFile(p, []byte(`{"x":"AKIAIOSFODNN7EXAMPLE"}\n`), 0o644)
	res, err := Run([]string{p}, Options{Write: false})
	if err != nil {
		t.Fatal(err)
	}
	if res.Replaced < 1 {
		t.Fatalf("dry-run should count: %#v", res)
	}
	if _, err := os.Stat(p + ".bak"); !os.IsNotExist(err) {
		t.Fatal("dry-run must not write bak")
	}
}
