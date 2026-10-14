package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errw bytes.Buffer
	code := run(args, &out, &errw)
	return code, out.String(), errw.String()
}

func TestScanFindingsOutput(t *testing.T) {
	code, out, _ := runCLI(t, "scan", "../../testdata")
	if code != 2 {
		t.Fatalf("exit=%d want 2", code)
	}
	for _, want := range []string{"CONTAMINATED", "distinct=", "Rotate them at the provider first", "spillscan redact --write"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("ANSI color leaked into non-terminal output")
	}
	if strings.Contains(out, "unknown") {
		t.Error("explicit-path agent should render as '-', not 'unknown'")
	}
}

func TestScanCleanAndEmpty(t *testing.T) {
	dir := t.TempDir()
	code, out, _ := runCLI(t, "scan", dir)
	if code != 0 || !strings.Contains(out, "NO READING") {
		t.Fatalf("empty dir: exit=%d out=%s", code, out)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.jsonl"), []byte(`{"text":"hello"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runCLI(t, "scan", dir)
	if code != 0 || !strings.Contains(out, "CLEAN — 1 transcript surveyed") {
		t.Fatalf("clean dir: exit=%d out=%s", code, out)
	}
}

func TestErrorsAreHelpful(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"scna"}, "did you mean: spillscan scan"},
		{[]string{"scan", "--jsno"}, "did you mean: --json"},
		{[]string{"scan", "--agent", "claud"}, "did you mean: --agent claude-code"},
		{[]string{"scan", "--agent"}, "one of: claude-code"},
		{[]string{"scan", "definitely-missing"}, "path not found: definitely-missing"},
		{[]string{"redact", "definitely-missing"}, "path not found: definitely-missing"},
		{[]string{"redact", "--wrtie"}, "did you mean: --write"},
		{[]string{"paths", "--bogus"}, "unknown flag --bogus"},
	}
	for _, c := range cases {
		code, _, errOut := runCLI(t, c.args...)
		if code != 1 || !strings.Contains(errOut, c.want) {
			t.Errorf("%v: exit=%d stderr=%q want %q", c.args, code, errOut, c.want)
		}
	}
}

func TestRedactStates(t *testing.T) {
	dir := t.TempDir()
	src, _ := os.ReadFile("../../testdata/codex/session.jsonl")
	f := filepath.Join(dir, "s.jsonl")
	_ = os.WriteFile(f, src, 0o600)
	_, out, _ := runCLI(t, "redact", f)
	if !strings.Contains(out, "Nothing changed") || !strings.Contains(out, "redact --write "+f) {
		t.Fatalf("dry-run: %s", out)
	}
	_, out, _ = runCLI(t, "redact", "--write", f)
	if !strings.Contains(out, "SCRUBBED") || !strings.Contains(out, ".bak") {
		t.Fatalf("write: %s", out)
	}
	_, out, _ = runCLI(t, "redact", f)
	if !strings.Contains(out, "CLEAN — nothing to scrub") {
		t.Fatalf("after write: %s", out)
	}
}

func TestSuggestAndTildify(t *testing.T) {
	if s := suggest("redcat", commands); s != "redact" {
		t.Errorf("suggest=%q", s)
	}
	if s := suggest("zzzzzz", commands); s != "" {
		t.Errorf("suggest=%q want empty", s)
	}
	home, _ := os.UserHomeDir()
	if got := tildify(filepath.Join(home, "x", "y.jsonl")); !strings.HasPrefix(got, "~") {
		t.Errorf("tildify=%q", got)
	}
}
