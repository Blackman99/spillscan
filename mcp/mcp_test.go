package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Blackman99/spillscan/detect"
)

const (
	fakeAKIA  = "AKIAIOSFODNN7EXAMPLE"
	fakeSlack = "xoxp-TESTONLY00-spillscanfixture000001"
)

func call(t *testing.T, req string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := Run(strings.NewReader(req+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	return resp
}

func TestScanReportHonorsAllowlistAndStaysReadOnly(t *testing.T) {
	home := t.TempDir()
	Home = home
	t.Cleanup(func() { Home = "" })
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	tr := filepath.Join(home, ".claude", "projects", "p", "s.jsonl")
	_ = os.MkdirAll(filepath.Dir(tr), 0o755)
	body := `{"content":"` + fakeAKIA + ` ` + fakeSlack + `"}` + "\n"
	_ = os.WriteFile(tr, []byte(body), 0o600)
	_ = os.MkdirAll(filepath.Join(cfg, "spillscan"), 0o755)
	_ = os.WriteFile(filepath.Join(cfg, "spillscan", "allow.txt"), []byte("value:"+fakeAKIA+"\n"), 0o600)

	resp := call(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan_report","arguments":{}}}`)
	text := resp["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	var rep struct {
		Count       int `json:"count"`
		Allowlisted int `json:"allowlisted"`
		Findings    []struct {
			Rule        string `json:"rule"`
			Fingerprint string `json:"fingerprint"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(text), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Count != 1 || rep.Allowlisted != 1 || rep.Findings[0].Rule != "slack-token" || rep.Findings[0].Fingerprint != detect.Fingerprint(fakeSlack) {
		t.Fatalf("report: %s", text)
	}
	if strings.Contains(text, fakeAKIA) || strings.Contains(text, fakeSlack) {
		t.Fatal("raw secret in MCP output")
	}
	if got, _ := os.ReadFile(tr); string(got) != body {
		t.Fatal("scan_report modified a transcript")
	}

	// A broken allowlist is a tool error, not a silent full report.
	_ = os.WriteFile(filepath.Join(cfg, "spillscan", "allow.txt"), []byte("rule:nope\n"), 0o600)
	resp = call(t, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_report","arguments":{}}}`)
	if e, ok := resp["error"].(map[string]any); !ok || !strings.Contains(e["message"].(string), "unknown rule") {
		t.Fatalf("want allowlist error, got %v", resp)
	}
}
