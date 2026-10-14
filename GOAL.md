# Goal

**Tell you, in one command, which secrets already spilled into your local AI coding-agent session transcripts — and scrub them in place with a backup.**

In scope: discover Claude Code / Codex / Cursor (and documented Gemini CLI / opencode) transcript roots; pattern+entropy detectors for common cloud/API tokens; human + JSON report; in-place JSONL-safe redaction with `.bak`; Claude Code PreToolUse `guard` for env-dump class Bash; optional read-only MCP (`scan_report`, `list_paths`).

Out of scope: preventing secrets from leaving the machine (egress firewall), matching only known local credential values (that is Stroq), rotating credentials at providers, scanning git history / CI logs (gitleaks), rewriting agent prompts.
