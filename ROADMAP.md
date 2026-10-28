# Roadmap

## v0.1.0 (shipped)
- `spillscan scan` / `redact` / `paths` / `guard` / `version` / `mcp`
- Detectors: AWS AKIA, GitHub pats, OpenAI/Anthropic sk, Slack, Google API, PEM, JWT-shaped, generic KEY/TOKEN/PASSWORD/SECRET, Stripe sk_live, NPM
- Claude Code PreToolUse guard for env-dump / cat-.env / printenv / /proc/*/environ (compound commands)
- GoReleaser binaries; GitHub Pages landing with Geiger meter demo (redesigned 2026-10-15 as a hazmat absorbent pad)

## v0.2.0 (shipped)
- `spillscan undo`: restore `.bak` originals, keeping lines appended after the scrub; repeat `redact --write` never overwrites the first backup
- scan/redact cover Claude Code `tool-results/` spill files and `*.jsonl.superseded-*` transcripts

## Unreleased on main
- False-positive allowlist file: `~/.config/spillscan/allow.txt` plus `--allow FILE` / `--no-allow` on scan, redact and undo; entries by `fp:` (value fingerprint), `rule:`, `path:` glob or `value:`; findings now carry a 12-hex fingerprint; scan reports `allowlisted=N`; MCP `scan_report` honors the default list

## v0.3 candidates
- More agent roots as paths stabilize (Copilot CLI, Desktop variants)
- Entropy tuning for `generic-assign` (wait for real false-positive reports; the allowlist covers the known ones)
- Provider "rotate here" links in report
- Optional PostToolUse companion (when vendors stop ignoring Bash output hooks)

## v1.0
- Stable rule IDs + SARIF output; brew formula
