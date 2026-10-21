# Roadmap

## v0.1.0 (shipped)
- `spillscan scan` / `redact` / `paths` / `guard` / `version` / `mcp`
- Detectors: AWS AKIA, GitHub pats, OpenAI/Anthropic sk, Slack, Google API, PEM, JWT-shaped, generic KEY/TOKEN/PASSWORD/SECRET, Stripe sk_live, NPM
- Claude Code PreToolUse guard for env-dump / cat-.env / printenv / /proc/*/environ (compound commands)
- GoReleaser binaries; GitHub Pages landing with Geiger meter demo (redesigned 2026-10-15 as a hazmat absorbent pad)

## v0.2
- `spillscan undo`: restore `.bak` originals, keeping lines appended after the scrub; repeat `redact --write` never overwrites the first backup (done on main, unreleased)
- More agent roots as paths stabilize (Copilot CLI, Desktop variants)
- Entropy tuning / false-positive allowlist file

## v0.3
- Provider "rotate here" links in report
- Optional PostToolUse companion (when vendors stop ignoring Bash output hooks)

## v1.0
- Stable rule IDs + SARIF output; brew formula
