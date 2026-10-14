// Package guard implements Claude Code PreToolUse stdin/stdout hook.
package guard

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"
)

// Envelope is the PreToolUse JSON from Claude Code (tolerant fields).
type Envelope struct {
	ToolName  string         `json:"tool_name"`
	Tool      string         `json:"tool"`
	Name      string         `json:"name"`
	Input     map[string]any `json:"tool_input"`
	ToolInput map[string]any `json:"input"`
}

// Decision is written to stdout for Claude Code.
type Decision struct {
	HookSpecificOutput *HookOut `json:"hookSpecificOutput,omitempty"`
	PermissionDecision string   `json:"permissionDecision,omitempty"`
	Reason             string   `json:"reason,omitempty"`
}

type HookOut struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

var dumpPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(^|[\s;&|])(env|printenv|export\s+-p|declare\s+-p|set)\b`),
	regexp.MustCompile(`(?i)\bcat\s+[^\n;|&]*\.env\b`),
	regexp.MustCompile(`(?i)\bcat\s+[^\n;|&]*\.env\.[A-Za-z0-9_.-]+`),
	regexp.MustCompile(`(?i)/proc/[^/\s]+/environ`),
	regexp.MustCompile(`(?i)\bkubectl\s+get\s+secret\b`),
}

var shellC = regexp.MustCompile(`(?i)\b(?:bash|sh|zsh|dash)\s+(?:-c)\s+['"]([^'"]+)['"]`)
var shellCRest = regexp.MustCompile(`(?i)\b(?:bash|sh|zsh|dash)\s+-c\s+(.+)$`)

// Evaluate reads one JSON envelope from r and writes a decision to w.
func Evaluate(r io.Reader, w io.Writer) error {
	var env Envelope
	dec := json.NewDecoder(r)
	if err := dec.Decode(&env); err != nil {
		// Non-JSON: allow (don't break the agent).
		return writeAllow(w, "unparseable envelope")
	}
	tool := firstNonEmpty(env.ToolName, env.Tool, env.Name)
	if !strings.EqualFold(tool, "Bash") && !strings.EqualFold(tool, "bash") {
		return writeAllow(w, "not bash")
	}
	cmd := extractCommand(env)
	if cmd == "" {
		return writeAllow(w, "empty command")
	}
	if reason, deny := MatchDump(cmd); deny {
		return writeDeny(w, reason)
	}
	return writeAllow(w, "ok")
}

// MatchDump returns (reason, true) if command looks like an env dump.
func MatchDump(cmd string) (string, bool) {
	for _, seg := range SplitSegments(cmd) {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		// Unwrap bash -c / sh -c bodies and re-scan.
		bodies := unwrapShellC(seg)
		check := append([]string{seg}, bodies...)
		for _, c := range check {
			for _, re := range dumpPatterns {
				if re.MatchString(c) {
					return "spillscan guard: blocked env-dump / secret-print pattern (" + summarize(c) + ")", true
				}
			}
		}
	}
	return "", false
}

// SplitSegments splits on && || ; | while respecting simple quotes.
func SplitSegments(cmd string) []string {
	var parts []string
	var b strings.Builder
	var quote rune
	runes := []rune(cmd)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if quote != 0 {
			b.WriteRune(r)
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			b.WriteRune(r)
			continue
		}
		// && or ||
		if (r == '&' || r == '|') && i+1 < len(runes) && runes[i+1] == r {
			parts = append(parts, b.String())
			b.Reset()
			i++
			continue
		}
		if r == ';' || r == '|' {
			parts = append(parts, b.String())
			b.Reset()
			continue
		}
		b.WriteRune(r)
	}
	parts = append(parts, b.String())
	return parts
}

func unwrapShellC(seg string) []string {
	var out []string
	if m := shellC.FindStringSubmatch(seg); len(m) > 1 {
		out = append(out, m[1])
		out = append(out, SplitSegments(m[1])...)
	}
	if m := shellCRest.FindStringSubmatch(seg); len(m) > 1 {
		body := strings.TrimSpace(m[1])
		body = strings.Trim(body, `"'`)
		out = append(out, body)
		out = append(out, SplitSegments(body)...)
	}
	return out
}

func extractCommand(env Envelope) string {
	for _, m := range []map[string]any{env.Input, env.ToolInput} {
		if m == nil {
			continue
		}
		for _, k := range []string{"command", "cmd", "bash_command"} {
			if v, ok := m[k].(string); ok {
				return v
			}
		}
	}
	return ""
}

func writeAllow(w io.Writer, reason string) error {
	d := Decision{
		PermissionDecision: "allow",
		HookSpecificOutput: &HookOut{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "allow",
			PermissionDecisionReason: reason,
		},
	}
	return json.NewEncoder(w).Encode(d)
}

func writeDeny(w io.Writer, reason string) error {
	d := Decision{
		PermissionDecision: "deny",
		Reason:             reason,
		HookSpecificOutput: &HookOut{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: reason,
		},
	}
	return json.NewEncoder(w).Encode(d)
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func summarize(c string) string {
	c = strings.TrimSpace(c)
	if len(c) > 60 {
		return c[:57] + "..."
	}
	return c
}
