package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Blackman99/spillscan/allow"
	"github.com/Blackman99/spillscan/detect"
)

func loadAllow(t *testing.T, body string) *allow.List {
	t.Helper()
	f := filepath.Join(t.TempDir(), "allow.txt")
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := allow.Load(false, []string{f})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestScanAllowlistSuppressesAndCounts(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sess.jsonl")
	content := `{"content":"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE slack=xoxp-TESTONLY00-spillscanfixture000001"}` + "\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Run(Options{Paths: []string{p}})
	if err != nil || len(res.Findings) != 2 || res.Allowlisted != 0 {
		t.Fatalf("baseline: %v %+v", err, res)
	}
	for _, f := range res.Findings {
		if f.Fingerprint != detect.Fingerprint(f.Secret) {
			t.Fatalf("fingerprint not set: %+v", f)
		}
	}
	al := loadAllow(t, "fp:"+detect.Fingerprint("AKIAIOSFODNN7EXAMPLE")+"\n")
	res, err = Run(Options{Paths: []string{p}, Allow: al})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Rule != "slack-token" || res.Allowlisted != 1 {
		t.Fatalf("want slack only, 1 allowlisted: %+v", res)
	}
	if len(res.AllowFiles) != 1 || !strings.HasSuffix(res.AllowFiles[0], "allow.txt") {
		t.Fatalf("allow files: %v", res.AllowFiles)
	}
	// A relative path argument still matches an absolute-looking glob.
	al = loadAllow(t, "rule:slack-token path:"+filepath.ToSlash(dir)+"/*.jsonl\n")
	wd, _ := os.Getwd()
	rel, _ := filepath.Rel(wd, p)
	res, _ = Run(Options{Paths: []string{rel}, Allow: al})
	if len(res.Findings) != 1 || res.Findings[0].Rule != "aws-akia" || res.Allowlisted != 1 {
		t.Fatalf("rule+path: %+v", res)
	}
}
