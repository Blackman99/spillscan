package allow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Blackman99/spillscan/detect"
)

// Obviously fake values only (AWS's documented example key, TESTONLY tokens).
const (
	fakeAKIA  = "AKIAIOSFODNN7EXAMPLE"
	fakeSlack = "xoxp-TESTONLY00-spillscanfixture000001"
)

func mustParse(t *testing.T, src string) *List {
	t.Helper()
	es, err := parse(strings.NewReader(src), "test.txt")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return &List{entries: es}
}

func TestParseEntriesAndComments(t *testing.T) {
	l := mustParse(t, `
# a comment line

fp:`+detect.Fingerprint(fakeAKIA)+`   # trailing comment
rule:jwt path:docs/**
value:`+fakeSlack+`
`)
	if l.Len() != 3 {
		t.Fatalf("entries=%d want 3", l.Len())
	}
}

func TestParseErrorsPointAtLine(t *testing.T) {
	cases := []struct{ src, want string }{
		{"\n\n3f9a1c0b7e21\n", "test.txt:3: bare \"3f9a1c0b7e21\": write it as fp:3f9a1c0b7e21"},
		{"rul:jwt", `unknown key "rul:" (use fp:, rule:, path:, value:)`},
		{"rule:jtw", `did you mean rule:jwt?`},
		{"rule:", "rule: is empty"},
		{"fp:zz12", "is not a fingerprint"},
		{"fp:abc", "is not a fingerprint"},
		{"rule:jwt rule:npm-token", "given twice"},
		{"just-words", `"just-words" is not key:value`},
	}
	for _, c := range cases {
		_, err := parse(strings.NewReader(c.src), "test.txt")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: err=%v want %q", c.src, err, c.want)
		}
	}
}

func TestAllowedKinds(t *testing.T) {
	home, _ := os.UserHomeDir()
	l := mustParse(t, strings.Join([]string{
		"fp:" + detect.Fingerprint(fakeAKIA)[:8], // a prefix is enough
		"value:" + fakeSlack,
		"rule:jwt path:~/fixtures/**",
		"path:*.superseded-*",
		"rule:npm-token path:/srv/agent/a/*.jsonl",
	}, "\n"))
	cases := []struct {
		rule, secret, path string
		want               bool
	}{
		{"aws-akia", fakeAKIA, "/any/x.jsonl", true},
		{"aws-akia", "AKIAIOSFODNN7EXAMPLF", "/any/x.jsonl", false},
		{"slack-token", fakeSlack, "/any/x.jsonl", true},
		{"jwt", "eyJ.fake", filepath.Join(home, "fixtures", "deep", "x.jsonl"), true},
		{"jwt", "eyJ.fake", "/elsewhere/fixtures/x.jsonl", false}, // ~ anchors to home
		{"github-pat", "ghp_fake", filepath.Join(home, "fixtures", "x.jsonl"), false},
		{"github-pat", "ghp_fake", "/a/b/s.jsonl.superseded-2026", true}, // basename glob
		{"npm-token", "npm_fake", "/srv/agent/a/s.jsonl", true},
		{"npm-token", "npm_fake", "/srv/agent/a/b/s.jsonl", false}, // * stays in one segment
	}
	for _, c := range cases {
		if got := l.Allowed(c.rule, c.secret, c.path); got != c.want {
			t.Errorf("Allowed(%s, %s) = %v want %v", c.rule, c.path, got, c.want)
		}
	}
}

func TestRelativeGlobMatchesTrailingSegments(t *testing.T) {
	l := mustParse(t, "path:proj/**/tool-results/*")
	if !l.Allowed("aws-akia", fakeAKIA, "/h/.claude/projects/proj/abc/tool-results/t.txt") {
		t.Error("relative glob should match at a segment boundary")
	}
	if !l.Allowed("aws-akia", fakeAKIA, "/h/proj/tool-results/t.txt") {
		t.Error("**/ should also match zero segments")
	}
	if l.Allowed("aws-akia", fakeAKIA, "/h/myproj/abc/tool-results/t.txt") {
		t.Error("relative glob must not match inside a segment name")
	}
}

func TestNilListAllowsNothing(t *testing.T) {
	var l *List
	if l.Allowed("aws-akia", fakeAKIA, "x") || l.For("x") != nil || l.Len() != 0 {
		t.Fatal("nil list must allow nothing")
	}
}

func TestLoadDefaultAndExtra(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	l, err := Load(true, nil)
	if err != nil || l.Len() != 0 || len(l.Files) != 0 {
		t.Fatalf("missing default must be fine: %v %+v", err, l)
	}
	def := filepath.Join(cfg, "spillscan", "allow.txt")
	if DefaultPath() != def {
		t.Fatalf("DefaultPath=%s", DefaultPath())
	}
	_ = os.MkdirAll(filepath.Dir(def), 0o755)
	_ = os.WriteFile(def, []byte("value:"+fakeAKIA+"\n"), 0o600)
	extra := filepath.Join(t.TempDir(), "team.txt")
	_ = os.WriteFile(extra, []byte("value:"+fakeSlack+"\n"), 0o600)
	l, err = Load(true, []string{extra, def})
	if err != nil {
		t.Fatal(err)
	}
	if l.Len() != 2 || len(l.Files) != 2 || l.Files[0] != def {
		t.Fatalf("files=%v len=%d (default first, no duplicates)", l.Files, l.Len())
	}
	l, _ = Load(false, nil)
	if l.Len() != 0 {
		t.Fatal("useDefault=false must not read the default file")
	}
	if _, err := Load(true, []string{filepath.Join(cfg, "nope.txt")}); err == nil || !strings.Contains(err.Error(), "allowlist not found") {
		t.Fatalf("missing --allow file: %v", err)
	}
}
