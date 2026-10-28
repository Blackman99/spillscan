package redact

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Blackman99/spillscan/allow"
	"github.com/Blackman99/spillscan/detect"
)

// Obviously fake fixture values (fakeAKIA lives in undo_test.go).
const (
	fakeSlack = "xoxp-TESTONLY00-spillscanfixture000001"
	fakePEM   = `-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCFAKEFAKEFAKEKEYMATERIAL\n-----END PRIVATE KEY-----`
)

func allowList(t *testing.T, lines ...string) *allow.List {
	t.Helper()
	f := filepath.Join(t.TempDir(), "allow.txt")
	if err := os.WriteFile(f, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := allow.Load(false, []string{f})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestRedactKeepsAllowlistedValues(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.jsonl")
	// Odd spacing on line 1 proves an all-allowlisted line keeps its bytes.
	line1 := `{ "content" : "fixture ` + fakeAKIA + `" }`
	line2 := `{"content":"aws ` + fakeAKIA + ` and slack ` + fakeSlack + `"}`
	orig := line1 + "\n" + line2 + "\n"
	_ = os.WriteFile(p, []byte(orig), 0o600)
	al := allowList(t, "value:"+fakeAKIA)
	res, err := Run([]string{p}, Options{Write: true, Allow: al})
	if err != nil {
		t.Fatal(err)
	}
	if res.Replaced != 1 || res.Allowlisted != 2 {
		t.Fatalf("replaced=%d allowlisted=%d want 1/2", res.Replaced, res.Allowlisted)
	}
	got, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSuffix(string(got), "\n"), "\n")
	if lines[0] != line1 {
		t.Fatalf("allowlisted-only line changed: %q", lines[0])
	}
	if strings.Contains(lines[1], fakeSlack) || !strings.Contains(lines[1], fakeAKIA) || !strings.Contains(lines[1], "[REDACTED:slack-token]") {
		t.Fatalf("line 2: %q", lines[1])
	}
	for _, l := range lines {
		var v any
		if err := json.Unmarshal([]byte(l), &v); err != nil {
			t.Fatalf("invalid JSON %q: %v", l, err)
		}
	}
	if bak, _ := os.ReadFile(p + ".bak"); string(bak) != orig {
		t.Fatal(".bak must hold the original")
	}
	// undo with the same allowlist puts the original back.
	ures, err := Undo([]string{p + ".bak"}, Options{Write: true, Allow: al})
	if err != nil || ures.Restored != 1 {
		t.Fatalf("undo: %v %+v", err, ures)
	}
	if got, _ := os.ReadFile(p); string(got) != orig {
		t.Fatal("undo did not restore")
	}
}

// scan sees a JSON-escaped PEM (literal \n); the JSON-aware scrub sees real
// newlines. An fp: copied from scan output must still protect it.
func TestRedactAllowlistedPEMByFingerprint(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.jsonl")
	line := `{"text":"` + fakePEM + `"}`
	_ = os.WriteFile(p, []byte(line+"\n"), 0o600)
	fs := detect.Scan(line)
	if len(fs) != 1 || fs[0].Rule != "pem-private" {
		t.Fatalf("fixture: %+v", fs)
	}
	al := allowList(t, "fp:"+detect.Fingerprint(fs[0].Secret))
	res, err := Run([]string{p}, Options{Write: true, Allow: al})
	if err != nil || res.Replaced != 0 || res.Allowlisted != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if got, _ := os.ReadFile(p); string(got) != line+"\n" {
		t.Fatal("allowlisted PEM was rewritten")
	}
	// Mixed line: the PEM is kept inside a re-encoded JSON value.
	mixed := `{"text":"` + fakePEM + `","tok":"` + fakeSlack + `"}`
	out, n, kept := ScrubWith([]byte(mixed+"\n"), true, al.For(p))
	if n != 1 || kept != 1 || bytes.Contains(out, []byte(fakeSlack)) || !bytes.Contains(out, []byte("BEGIN PRIVATE KEY")) {
		t.Fatalf("mixed: n=%d kept=%d %s", n, kept, out)
	}
}

// Scrub first without an allowlist, add one, scrub again after the agent
// appended: the .bak must still be extended, not refused.
func TestRescrubAfterAllowlistAdded(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.jsonl")
	first := `{"c":"` + fakeAKIA + `"}` + "\n"
	_ = os.WriteFile(p, []byte(first), 0o600)
	if _, err := Run([]string{p}, Options{Write: true}); err != nil {
		t.Fatal(err)
	}
	cur, _ := os.ReadFile(p)
	appended := `{"c":"later ` + fakeSlack + `"}` + "\n"
	_ = os.WriteFile(p, append(cur, appended...), 0o600)
	al := allowList(t, "value:"+fakeAKIA)
	res, err := Run([]string{p}, Options{Write: true, Allow: al})
	if err != nil || res.Replaced != 1 {
		t.Fatalf("rescrub: %v %+v", err, res)
	}
	if bak, _ := os.ReadFile(p + ".bak"); string(bak) != first+appended {
		t.Fatalf("bak=%q", bak)
	}
	ures, err := Undo([]string{p + ".bak"}, Options{Write: true, Allow: al})
	if err != nil || ures.Restored != 1 {
		t.Fatalf("undo: %v %+v", err, ures)
	}
	if got, _ := os.ReadFile(p); string(got) != first+appended {
		t.Fatalf("restored=%q", got)
	}
}

func TestPlainTextAllowlist(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tool-results", "t.txt")
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	orig := "KEY=" + fakeAKIA + "\r\nslack " + fakeSlack
	_ = os.WriteFile(p, []byte(orig), 0o600)
	res, err := Run([]string{p}, Options{Write: true, Allow: allowList(t, "rule:aws-akia path:**/tool-results/*")})
	if err != nil || res.Replaced != 1 || res.Allowlisted != 1 {
		t.Fatalf("%v %+v", err, res)
	}
	want := "KEY=" + fakeAKIA + "\r\nslack [REDACTED:slack-token]"
	if got, _ := os.ReadFile(p); string(got) != want {
		t.Fatalf("got %q", got)
	}
}
