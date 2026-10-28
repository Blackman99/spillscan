// Package detect finds secret-shaped substrings in text (no network).
package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"unicode"
)

// Finding is one matched secret span.
type Finding struct {
	Rule    string `json:"rule"`
	Preview string `json:"preview"` // first/last 4 kept
	Start   int    `json:"start"`
	End     int    `json:"end"`
	Secret  string `json:"-"` // full match, never serialized
}

type rule struct {
	id  string
	re  *regexp.Regexp
	min int // minimum length for generic rules
}

var rules = []rule{
	{id: "aws-akia", re: regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`)},
	{id: "github-pat", re: regexp.MustCompile(`\b(ghp_[A-Za-z0-9_]{36,})\b`)},
	{id: "github-oauth", re: regexp.MustCompile(`\b(gho_[A-Za-z0-9_]{36,})\b`)},
	{id: "github-fine", re: regexp.MustCompile(`\b(github_pat_[A-Za-z0-9_]{20,})\b`)},
	{id: "openai-sk", re: regexp.MustCompile(`\b(sk-[A-Za-z0-9\-]{20,}(?:T3BlbkFJ[A-Za-z0-9]{20,})?)\b`)},
	{id: "anthropic-sk", re: regexp.MustCompile(`\b(sk-ant-api03-[A-Za-z0-9\-_]{20,})\b`)},
	{id: "slack-token", re: regexp.MustCompile(`\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b`)},
	{id: "google-api", re: regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{35})\b`)},
	{id: "stripe-live", re: regexp.MustCompile("\\b(sk_" + "live_[A-Za-z0-9]{20,})\\b")},
	{id: "npm-token", re: regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36,})\b`)},
	{id: "pem-private", re: regexp.MustCompile(`(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)`)},
	{id: "jwt", re: regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b`)},
	{id: "generic-assign", re: regexp.MustCompile(`(?i)\b(?:KEY|TOKEN|PASSWORD|SECRET|API_KEY|ACCESS_KEY|AUTH_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9_\-./+=]{16,})['"]?`), min: 16},
}

// RuleIDs lists every detector rule id, in priority order.
func RuleIDs() []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.id
	}
	return out
}

// Fingerprint is a short, stable id for a secret value: the first 12 hex
// chars of a domain-separated SHA-256. It lets you allowlist one value
// without the value ever being printed. Detectors only fire on long,
// high-entropy strings, so the prefix does not make guessing practical.
func Fingerprint(secret string) string {
	sum := sha256.Sum256([]byte("spillscan-fp-v1\x00" + secret))
	return hex.EncodeToString(sum[:])[:12]
}

// Scan returns non-overlapping findings, highest-specificity rules first.
func Scan(text string) []Finding {
	type hit struct {
		f   Finding
		pri int
	}
	var hits []hit
	for i, r := range rules {
		ms := r.re.FindAllStringSubmatchIndex(text, -1)
		for _, m := range ms {
			// Prefer capture group 1 when present.
			gs, ge := m[0], m[1]
			if len(m) >= 4 && m[2] >= 0 {
				gs, ge = m[2], m[3]
			}
			sec := text[gs:ge]
			if r.min > 0 && len(sec) < r.min {
				continue
			}
			if r.id == "generic-assign" && !highEntropy(sec) {
				continue
			}
			if r.id == "openai-sk" && (len(sec) < 20 || hasPrefix(sec, "sk-ant-")) {
				continue
			}
			hits = append(hits, hit{
				f: Finding{
					Rule:    r.id,
					Preview: redactPreview(sec),
					Start:   gs,
					End:     ge,
					Secret:  sec,
				},
				pri: i,
			})
		}
	}
	// Greedy non-overlap: sort by start, then priority.
	for i := 0; i < len(hits); i++ {
		for j := i + 1; j < len(hits); j++ {
			if hits[j].f.Start < hits[i].f.Start ||
				(hits[j].f.Start == hits[i].f.Start && hits[j].pri < hits[i].pri) {
				hits[i], hits[j] = hits[j], hits[i]
			}
		}
	}
	var out []Finding
	lastEnd := -1
	for _, h := range hits {
		if h.f.Start < lastEnd {
			continue
		}
		out = append(out, h.f)
		lastEnd = h.f.End
	}
	return out
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

func redactPreview(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "…" + s[len(s)-4:]
}

func highEntropy(s string) bool {
	if len(s) < 16 {
		return false
	}
	// Reject obvious placeholders.
	low := toLower(s)
	for _, bad := range []string{"example", "changeme", "placeholder", "your_", "xxx", "testtest", "password", "secret"} {
		if contains(low, bad) {
			return false
		}
	}
	var classes int
	var hasUpper, hasLower, hasDigit, hasOther bool
	seen := map[rune]struct{}{}
	for _, r := range s {
		seen[r] = struct{}{}
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasOther = true
		}
	}
	if hasUpper {
		classes++
	}
	if hasLower {
		classes++
	}
	if hasDigit {
		classes++
	}
	if hasOther {
		classes++
	}
	uniq := len(seen)
	return classes >= 2 && uniq >= 10
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
