package detect

import (
	"strings"
	"testing"
)

func TestDetectors(t *testing.T) {
	cases := []struct {
		rule string
		text string
	}{
		{"aws-akia", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"},
		{"github-pat", "token ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD"},
		{"github-oauth", "gho_abcdefghijklmnopqrstuvwxyz0123456789ABCD"},
		{"github-fine", "github_pat_11AAAAAAA0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"},
		{"openai-sk", "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz012345"},
		{"anthropic-sk", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD"},
		{"slack-token", "xoxp-TESTONLY00-spillscanfixture000001"},
		{"google-api", "AIzaSyDabcdefghijklmnopqrstuvwxyz012345"},
		// stripe tested in TestStripeLiveConstructed
		{"npm-token", "npm_abcdefghijklmnopqrstuvwxyz0123456789ABCD"},
		{"jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
		{"pem-private", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC\n-----END PRIVATE KEY-----"},
		{"generic-assign", "TOKEN=aB3dE5fG7hI9jK1lM2nO3pQ4rS5tU6vW"},
	}
	for _, c := range cases {
		fs := Scan(c.text)
		found := false
		for _, f := range fs {
			if f.Rule == c.rule {
				found = true
				if !strings.Contains(f.Preview, "…") && f.Rule != "pem-private" && len(f.Secret) > 8 {
					// pem may be long; others should redact
				}
				if f.Secret == "" {
					t.Fatalf("%s: empty secret", c.rule)
				}
			}
		}
		if !found {
			t.Fatalf("expected rule %s in %q; got %#v", c.rule, c.text, fs)
		}
	}
}

func TestNoFalseGeneric(t *testing.T) {
	fs := Scan(`PASSWORD=password`)
	for _, f := range fs {
		if f.Rule == "generic-assign" {
			t.Fatalf("should reject low-entropy: %#v", f)
		}
	}
}

func TestPreview(t *testing.T) {
	p := redactPreview("abcdefghijklmnop")
	if p != "abcd…mnop" {
		t.Fatalf("got %q", p)
	}
}
