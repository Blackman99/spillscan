package guard

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestMatchDumpCompound(t *testing.T) {
	cases := []struct {
		cmd  string
		deny bool
	}{
		{`echo "searching..."; env 2>/dev/null; npm search foo`, true},
		{`printenv | grep TOKEN`, true},
		{`cat .env`, true},
		{`cat .env.local`, true},
		{`cat /proc/1/environ`, true},
		{`bash -c 'env'`, true},
		{`sh -c "printenv"`, true},
		{`npm test && go test`, false},
		{`echo hello`, false},
		{`kubectl get secret -o yaml`, true},
		{`ls && env && pwd`, true},
		{`true || env`, true},
	}
	for _, c := range cases {
		_, deny := MatchDump(c.cmd)
		if deny != c.deny {
			t.Fatalf("%q: deny=%v want %v", c.cmd, deny, c.deny)
		}
	}
}

func TestEvaluateBashDeny(t *testing.T) {
	in := `{"tool_name":"Bash","tool_input":{"command":"echo x; env"}}`
	var out bytes.Buffer
	if err := Evaluate(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	var d Decision
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.PermissionDecision != "deny" && (d.HookSpecificOutput == nil || d.HookSpecificOutput.PermissionDecision != "deny") {
		t.Fatalf("want deny, got %s", out.String())
	}
}

func TestEvaluateAllowNonBash(t *testing.T) {
	in := `{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"}}`
	var out bytes.Buffer
	if err := Evaluate(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "allow") {
		t.Fatalf("want allow: %s", out.String())
	}
}
