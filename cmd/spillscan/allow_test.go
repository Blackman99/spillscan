package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Blackman99/spillscan/detect"
)

// TestMain points the default allowlist at an empty temp dir so a
// developer's own ~/.config/spillscan/allow.txt never changes test results.
func TestMain(m *testing.M) {
	cfg, err := os.MkdirTemp("", "spillscan-cfg-")
	if err != nil {
		panic(err)
	}
	os.Setenv("XDG_CONFIG_HOME", cfg)
	code := m.Run()
	os.RemoveAll(cfg)
	os.Exit(code)
}

const (
	fakeAKIA  = "AKIAIOSFODNN7EXAMPLE"
	fakeSlack = "xoxp-TESTONLY00-spillscanfixture000001"
)

func fixtureDir(t *testing.T) (dir, file string) {
	t.Helper()
	dir = t.TempDir()
	file = filepath.Join(dir, "s.jsonl")
	body := `{"content":"AWS_ACCESS_KEY_ID=` + fakeAKIA + `"}` + "\n" + `{"content":"slack ` + fakeSlack + `"}` + "\n"
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, file
}

func writeAllow(t *testing.T, path, body string) string {
	t.Helper()
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanShowsFingerprintNeverSecret(t *testing.T) {
	dir, _ := fixtureDir(t)
	code, out, _ := runCLI(t, "scan", dir)
	if code != 2 {
		t.Fatalf("exit=%d", code)
	}
	for _, want := range []string{"FP", detect.Fingerprint(fakeAKIA), detect.Fingerprint(fakeSlack), "Known-fake value? Add the line fp:<FP> to", "allow.txt"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, fakeAKIA) || strings.Contains(out, fakeSlack) {
		t.Fatalf("full secret printed:\n%s", out)
	}
	if strings.Contains(out, "allowlisted") {
		t.Errorf("no allowlist in use, yet output mentions it:\n%s", out)
	}
}

func TestScanAllowFlag(t *testing.T) {
	dir, _ := fixtureDir(t)
	al := writeAllow(t, filepath.Join(t.TempDir(), "team allow.txt"), "fp:"+detect.Fingerprint(fakeAKIA)+"  # AWS docs example key\n")
	code, out, _ := runCLI(t, "scan", "--allow", al, dir)
	if code != 2 {
		t.Fatalf("exit=%d", code)
	}
	for _, want := range []string{"findings=1", "allowlisted=1", "1 allowlisted finding hidden", "spillscan scan --no-allow", "redact --allow '" + al + "'"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "aws-akia") {
		t.Errorf("allowlisted rule still listed:\n%s", out)
	}
	// Everything allowlisted: CLEAN, exit 0, and still says what was hidden.
	both := writeAllow(t, filepath.Join(t.TempDir(), "a.txt"), "value:"+fakeAKIA+"\nrule:slack-token path:*.jsonl\n")
	code, out, _ = runCLI(t, "scan", "--allow="+both, dir)
	if code != 0 || !strings.Contains(out, "CLEAN") || !strings.Contains(out, "2 allowlisted findings hidden") {
		t.Fatalf("all hidden: exit=%d\n%s", code, out)
	}
	// --no-allow shows everything again, even with a default list present.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	writeAllow(t, filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "spillscan", "allow.txt"), "value:"+fakeAKIA+"\n")
	_, out, _ = runCLI(t, "scan", dir)
	if !strings.Contains(out, "allowlisted=1") {
		t.Fatalf("default allowlist not read:\n%s", out)
	}
	if strings.Contains(out, "--allow ") {
		t.Errorf("default list must not be repeated as --allow:\n%s", out)
	}
	code, out, _ = runCLI(t, "scan", "--no-allow", dir)
	if code != 2 || strings.Contains(out, "allowlisted") || !strings.Contains(out, "findings=2") {
		t.Fatalf("--no-allow: exit=%d\n%s", code, out)
	}
}

func TestScanJSONAllowlisted(t *testing.T) {
	dir, _ := fixtureDir(t)
	al := writeAllow(t, filepath.Join(t.TempDir(), "a.txt"), "value:"+fakeSlack+"\n")
	_, out, _ := runCLI(t, "scan", "--json", "--allow", al, dir)
	var res struct {
		Allowlisted int      `json:"allowlisted"`
		AllowFiles  []string `json:"allow_files"`
		Findings    []struct {
			Rule        string `json:"rule"`
			Fingerprint string `json:"fingerprint"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if res.Allowlisted != 1 || len(res.Findings) != 1 || res.Findings[0].Fingerprint != detect.Fingerprint(fakeAKIA) || len(res.AllowFiles) != 1 {
		t.Fatalf("%+v", res)
	}
	if strings.Contains(out, fakeAKIA) {
		t.Fatal("secret in JSON output")
	}
}

func TestRedactAndUndoHonorAllowlist(t *testing.T) {
	dir, f := fixtureDir(t)
	orig, _ := os.ReadFile(f)
	al := writeAllow(t, filepath.Join(t.TempDir(), "a.txt"), "value:"+fakeAKIA+"\n")
	_, out, _ := runCLI(t, "redact", "--allow", al, f)
	if !strings.Contains(out, "replaced=1 allowlisted=1") || !strings.Contains(out, "1 allowlisted value left as-is") || !strings.Contains(out, "redact --write --allow "+al) {
		t.Fatalf("dry-run:\n%s", out)
	}
	_, out, _ = runCLI(t, "redact", "--write", "--allow", al, f)
	if !strings.Contains(out, "SCRUBBED") {
		t.Fatalf("write:\n%s", out)
	}
	got, _ := os.ReadFile(f)
	if !strings.Contains(string(got), fakeAKIA) || strings.Contains(string(got), fakeSlack) {
		t.Fatalf("after write: %s", got)
	}
	code, out, _ := runCLI(t, "undo", "--write", "--allow", al, dir)
	if code != 0 || !strings.Contains(out, "RESTORED") {
		t.Fatalf("undo: %d\n%s", code, out)
	}
	if got, _ := os.ReadFile(f); string(got) != string(orig) {
		t.Fatal("undo did not restore original bytes")
	}
}

func TestAllowFlagErrors(t *testing.T) {
	bad := writeAllow(t, filepath.Join(t.TempDir(), "bad.txt"), "# ok\nrule:jtw\n")
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"scan", "--allow"}, "--allow needs a file"},
		{[]string{"scan", "--allow="}, "--allow needs a file"},
		{[]string{"scan", "--allow", "definitely-missing.txt"}, "allowlist not found: definitely-missing.txt"},
		{[]string{"scan", "--allow", bad}, "bad.txt:2: unknown rule \"jtw\" (did you mean rule:jwt?)"},
		{[]string{"redact", "--allow", bad}, "did you mean rule:jwt?"},
		{[]string{"undo", "--allow", bad}, "did you mean rule:jwt?"},
		{[]string{"scan", "--no-allow", "--allow", bad}, "drop --allow or --no-allow"},
		{[]string{"scan", "--alow", "x"}, "did you mean: --allow"},
		{[]string{"redact", "--no-alow"}, "did you mean: --no-allow"},
	}
	for _, c := range cases {
		code, _, errOut := runCLI(t, c.args...)
		if code != 1 || !strings.Contains(errOut, c.want) {
			t.Errorf("%v: exit=%d stderr=%q want %q", c.args, code, errOut, c.want)
		}
	}
}

func TestHelpDocumentsAllowlist(t *testing.T) {
	_, out, _ := runCLI(t, "scan", "--help")
	for _, want := range []string{"--allow FILE", "--no-allow", "fp:", "rule:", "path:", "value:", "allow.txt"} {
		if !strings.Contains(out, want) {
			t.Errorf("scan --help missing %q", want)
		}
	}
	_, out, _ = runCLI(t, "help")
	if !strings.Contains(out, "False positives") {
		t.Error("top-level help should point at the allowlist")
	}
}
