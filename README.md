# spillscan

**Tell you, in one command, which secrets already spilled into your local AI coding-agent session transcripts — and scrub them in place with a backup.**

One `env` / `printenv` / `cat .env` inside an agent Bash call writes live credentials into plaintext session JSONL (`~/.claude/projects/**/*.jsonl`, `~/.codex/sessions/**/*.jsonl`, Cursor, …). spillscan finds them and redacts them — including the copies Claude Code keeps beside the transcript: large tool outputs spilled to `<session>/tool-results/` and set-aside `*.jsonl.superseded-<timestamp>` transcripts ([docs](https://code.claude.com/docs/en/claude-directory)).

![demo](site/demo.gif)

## 30-second path

```bash
go install github.com/Blackman99/spillscan/cmd/spillscan@latest
spillscan scan              # survey every agent transcript under $HOME — exit 2 if anything spilled
spillscan redact            # dry-run: shows what would be scrubbed, changes nothing
spillscan redact --write    # scrub in place; each file is copied to <file>.bak first
spillscan undo              # changed your mind? dry-run of putting the originals back (then --write)
```

Rotate any key it finds at the provider **before** scrubbing — redacting a transcript does not revoke a credential.

## Install

**Go 1.24+:** `go install github.com/Blackman99/spillscan/cmd/spillscan@latest`

**No Go (macOS / Linux, static binary):**

```bash
V=0.2.0; OS=$(uname -s | tr A-Z a-z); ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -fsSL "https://github.com/Blackman99/spillscan/releases/download/v$V/spillscan_${V}_${OS}_${ARCH}.tar.gz" | tar xz spillscan
sudo mv spillscan /usr/local/bin/ && spillscan version
```

**Windows:** download `spillscan_<version>_windows_amd64.zip` from [Releases](https://github.com/Blackman99/spillscan/releases), verify against `checksums.txt`.

## What a sweep looks like

```text
$ spillscan scan
SPILLSCAN  files=41 findings=3 distinct=3  2026-10-14 10:04 CST
RULE        PREVIEW    FP            AGENT        FILE:LINE
aws-akia    AKIA…MPLE  8cc03843ecd0  claude-code  ~/.claude/projects/…/x.jsonl:128
github-pat  ghp_…a91F  1d6e40b2c9f7  claude-code  ~/.claude/projects/…/x.jsonl:128
openai-sk   sk-p…9Qx2  a40f3be1d258  codex        ~/.codex/sessions/…/y.jsonl:44

CONTAMINATED — 3 distinct secrets in 2 files.
  1. Rotate them at the provider first — scrubbing a transcript does not revoke a key.
  2. Preview the scrub:  spillscan redact
  3. Apply it (.bak kept): spillscan redact --write
  Known-fake value? Add the line fp:<FP> to ~/.config/spillscan/allow.txt; scan and redact then skip it.
```

`FP` is a short fingerprint of the value (never the value itself), used by the allowlist below.

| Command | What it does |
|---|---|
| `spillscan scan [--agent NAME] [--allow FILE] [--no-allow] [paths…]` | Survey. Exit `0` clean · `2` findings · `1` error. `--json` for scripts. Allowlisted findings are hidden, counted in the header (`allowlisted=N`) and don't affect the exit code. |
| `spillscan redact [--write] [paths…]` | Dry-run by default; `--write` backs up to `.bak`, then replaces with `[REDACTED:<rule>]`. JSONL stays valid JSON; `tool-results/` spill files are scrubbed as plain text. Scrubbing again later extends the existing `.bak` with the new lines instead of overwriting the first originals. Allowlisted values are left as they are. |
| `spillscan undo [--write] [paths…]` | Put the `.bak` originals back. Dry-run by default. Lines the agent appended after the scrub are kept; a file edited any other way is reported `diverged` and left alone. Exit `1` if any backup could not be restored. Pass the same `--allow` files you scrubbed with. |
| `spillscan paths` | Which transcript roots were discovered, and how many files each holds. |
| `spillscan guard` / `spillscan mcp` | Claude Code hook (below) / read-only MCP server (`scan_report`, `list_paths`). |

Agents: `claude-code`, `codex`, `cursor`, `gemini-cli`, `opencode`. Paths are shown as `~/…` so screenshots don't leak your username. Output is colored only on a terminal; `NO_COLOR=1` or `--no-color` turns it off.

### Allowlist known fakes *(on `main`, ships in the next release)*

Docs example keys, test fixtures and tutorial JWTs are real-looking but harmless. List them once in `~/.config/spillscan/allow.txt` (or `$XDG_CONFIG_HOME/spillscan/allow.txt`) and `scan`, `redact` and the MCP `scan_report` skip them. Add more lists with `--allow FILE` (repeatable); `--no-allow` ignores them all.

```text
# one entry per line; keys on one line must all match
fp:8cc03843ecd0                             # one value, by the FP scan printed
rule:jwt path:~/.claude/projects/*docs*/**  # a rule, only under some transcripts
path:~/.codex/sessions/2026/01/**           # everything under a path
rule:generic-assign                         # a whole detector
value:AKIAIOSFODNN7EXAMPLE                  # a literal (only for values that are fake by design)
```

`fp:` takes 8–64 hex characters of the fingerprint (a domain-separated SHA-256 of the value), so you never have to write a real value down. `path:` globs match the absolute transcript path: `*` stays in one segment, `**` crosses them, `~/` is your home, and a glob without `/` matches the file name. A typo is an error with the file and line (`allow.txt:3: unknown rule "jtw" (did you mean rule:jwt?)`), not a silent miss. Nothing is hidden quietly: scan reports the count and how to see everything.

### Guard (Claude Code PreToolUse)

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "spillscan guard" }]
      }
    ]
  }
}
```

Install into `.claude/settings.json` (project or user). Denies `env` / `printenv` / `cat .env*` / `/proc/*/environ` even inside `cmd1; env; cmd2` and `bash -c '…'`.

## Why not Stroq / gitleaks?

| | spillscan | Stroq | gitleaks |
|---|---|---|---|
| Unknown secrets (pattern+entropy) | yes | no (local known values) | yes |
| In-place JSONL redact + `.bak` | yes | no (past records unchanged) | no |
| Agent transcript roots | yes | yes | you point it |
| Static binary, ms hook start | yes (Go) | Node ≥22 | yes |

## Docs

https://blackman99.github.io/spillscan/

Pain source: [anthropics/claude-code#80153](https://github.com/anthropics/claude-code/issues/80153) (reporter [@aaronlippold](https://github.com/aaronlippold), Jul 2026). Current Claude Code [permissions docs](https://code.claude.com/docs/en/permissions) say deny/ask rules split on `;`/`&&`/… and fire if any subcommand matches — so `Bash(env *)` should catch a middle `env` on current builds. spillscan remains the cleanup for already-spilled transcript secrets (+ PreToolUse guard); PostToolUse Bash rewrite was historically ignored ([#68951](https://github.com/anthropics/claude-code/issues/68951)).

## License

MIT
