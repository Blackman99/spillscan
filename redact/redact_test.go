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

func TestRedactToolResultsPlainText(t *testing.T) {
	dir := t.TempDir()
	tr := filepath.Join(dir, "abc", "tool-results")
	_ = os.MkdirAll(tr, 0o755)
	p := filepath.Join(tr, "toolu_1.txt")
	// Not JSON, CRLF endings, no final newline: all must survive untouched.
	orig := "$ env\r\n{\"half\": \"json\r\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\r\nHOME=/home/test"
	if err := os.WriteFile(p, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := CollectJSONL([]string{dir})
	if err != nil || len(files) != 1 {
		t.Fatalf("collect: %v %v", files, err)
	}
	res, err := Run(files, Options{Write: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Replaced != 1 {
		t.Fatalf("replaced=%d", res.Replaced)
	}
	got, _ := os.ReadFile(p)
	want := strings.Replace(orig, "AKIAIOSFODNN7EXAMPLE", "[REDACTED:aws-akia]", 1)
	if string(got) != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	bak, err := os.ReadFile(p + ".bak")
	if err != nil || string(bak) != orig {
		t.Fatalf("bak must hold the original: %v", err)
	}
	// The .bak must not be picked up on the next pass.
	files, _ = CollectJSONL([]string{dir})
	if len(files) != 1 {
		t.Fatalf("bak collected: %v", files)
	}
}

func TestRedactSupersededStaysValidJSONL(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "abc.jsonl.superseded-2026-10-17T03-00-00Z")
	body := `{"n":1,"content":"clean"}` + "\n" + `{"n":2,"content":"token xoxp-TESTONLY00-spillscanfixture000001"}` + "\n"
	_ = os.WriteFile(p, []byte(body), 0o644)
	files, _ := CollectJSONL([]string{dir})
	if len(files) != 1 {
		t.Fatalf("collect: %v", files)
	}
	if _, err := Run(files, Options{Write: true}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 2 || lines[0] != `{"n":1,"content":"clean"}` {
		t.Fatalf("lines: %q", lines)
	}
	for _, l := range lines {
		var v map[string]any
		if err := json.Unmarshal([]byte(l), &v); err != nil {
			t.Fatalf("invalid JSON %q: %v", l, err)
		}
	}
	if strings.Contains(string(raw), "xoxp-") {
		t.Fatalf("secret left: %s", raw)
	}
	if _, err := os.Stat(p + ".bak"); err != nil {
		t.Fatal("missing bak")
	}
}

func TestRedactSkipsBinary(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tool-results", "shot.dat")
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	orig := "AKIAIOSFODNN7EXAMPLE\x00\x01\x02"
	_ = os.WriteFile(p, []byte(orig), 0o644)
	res, err := Run([]string{p}, Options{Write: true})
	if err != nil || res.Replaced != 0 {
		t.Fatalf("res=%#v err=%v", res, err)
	}
	if got, _ := os.ReadFile(p); string(got) != orig {
		t.Fatal("binary file modified")
	}
}
