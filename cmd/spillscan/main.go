// spillscan finds and scrubs secrets spilled into local AI agent transcripts.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/Blackman99/spillscan/guard"
	"github.com/Blackman99/spillscan/mcp"
	"github.com/Blackman99/spillscan/paths"
	"github.com/Blackman99/spillscan/redact"
	"github.com/Blackman99/spillscan/scan"
)

var version = "dev"

const usage = `spillscan — contamination survey for AI agent transcripts

Tell you, in one command, which secrets already spilled into your local AI
coding-agent session transcripts — and scrub them in place with a backup.

Usage:
  spillscan scan [--json] [--agent NAME] [--no-color] [paths...]
  spillscan redact [--write] [--json] [paths...]
  spillscan paths [--json]
  spillscan guard          # Claude Code PreToolUse hook (stdin → stdout)
  spillscan mcp            # read-only MCP stdio (scan_report, list_paths)
  spillscan version

Agents: claude-code, codex, cursor, gemini-cli, opencode
Colors follow the terminal; set NO_COLOR=1 or pass --no-color to disable.
Exit codes: 0 clean/ok · 2 findings (scan) · 1 error
`

var commands = []string{"scan", "redact", "paths", "guard", "mcp", "version", "help"}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errw io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(errw, usage)
		return 1
	}
	switch args[0] {
	case "scan":
		return cmdScan(args[1:], out, errw)
	case "redact":
		return cmdRedact(args[1:], out, errw)
	case "paths":
		return cmdPaths(args[1:], out, errw)
	case "guard":
		if err := guard.Evaluate(os.Stdin, out); err != nil {
			fmt.Fprintln(errw, "spillscan guard:", err)
			return 1
		}
		return 0
	case "mcp":
		if err := mcp.Run(os.Stdin, out); err != nil {
			fmt.Fprintln(errw, "spillscan mcp:", err)
			return 1
		}
		return 0
	case "version", "-version", "--version":
		fmt.Fprintln(out, "spillscan", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(out, usage)
		return 0
	default:
		fmt.Fprintf(errw, "spillscan: unknown command %q\n", args[0])
		if s := suggest(args[0], commands); s != "" {
			fmt.Fprintf(errw, "  did you mean: spillscan %s\n", s)
		}
		fmt.Fprintln(errw, "  run 'spillscan help' for usage")
		return 1
	}
}

// badFlag reports an unrecognised flag instead of treating it as a path.
func badFlag(errw io.Writer, cmd, flag string, known []string) int {
	fmt.Fprintf(errw, "spillscan %s: unknown flag %s\n", cmd, flag)
	if s := suggest(flag, known); s != "" {
		fmt.Fprintf(errw, "  did you mean: %s\n", s)
	}
	fmt.Fprintf(errw, "  run 'spillscan %s --help' for usage\n", cmd)
	return 1
}

func isFlag(a string) bool { return len(a) > 1 && strings.HasPrefix(a, "-") }

func cmdScan(args []string, out, errw io.Writer) int {
	asJSON, noColor, agent, rest := false, false, "", []string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if v, ok := strings.CutPrefix(a, "--agent="); ok {
			agent = v
			continue
		}
		switch a {
		case "--json", "-json":
			asJSON = true
		case "--no-color", "-no-color":
			noColor = true
		case "--agent", "-agent":
			i++
			if i >= len(args) || isFlag(args[i]) {
				fmt.Fprintf(errw, "spillscan scan: --agent needs a value (one of: %s)\n", strings.Join(paths.Agents, ", "))
				return 1
			}
			agent = args[i]
		case "-h", "--help":
			fmt.Fprintln(out, "spillscan scan [--json] [--agent NAME] [--no-color] [paths...]")
			fmt.Fprintln(out, "  No paths: survey every known agent transcript root under $HOME.")
			fmt.Fprintf(out, "  --agent: limit discovery to one of %s\n", strings.Join(paths.Agents, ", "))
			fmt.Fprintln(out, "  Exit 2 when anything is found, so it gates CI and pre-commit hooks.")
			return 0
		case "--":
			rest = append(rest, args[i+1:]...)
			i = len(args)
		default:
			if isFlag(a) {
				return badFlag(errw, "scan", a, []string{"--json", "--agent", "--no-color", "--help"})
			}
			rest = append(rest, a)
		}
	}
	if agent != "" && !slices.Contains(paths.Agents, agent) {
		fmt.Fprintf(errw, "spillscan scan: unknown agent %q (one of: %s)\n", agent, strings.Join(paths.Agents, ", "))
		if s := suggest(agent, paths.Agents); s != "" {
			fmt.Fprintf(errw, "  did you mean: --agent %s\n", s)
		}
		return 1
	}
	if agent != "" && len(rest) > 0 {
		fmt.Fprintln(errw, "spillscan scan: --agent filters discovery; drop it when passing explicit paths")
		return 1
	}
	res, err := scan.Run(scan.Options{Agent: agent, Paths: rest})
	if err != nil {
		fmt.Fprintln(errw, "spillscan scan:", err)
		return 1
	}
	for _, f := range res.Skipped {
		fmt.Fprintf(errw, "spillscan: warning: could not read %s (skipped)\n", tildify(f))
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		printScan(out, res, newPainter(out, noColor), len(rest) > 0)
	}
	if len(res.Findings) > 0 {
		return 2
	}
	return 0
}

func printScan(out io.Writer, res *scan.Result, p painter, explicit bool) {
	n := len(res.Findings)
	distinct := map[string]struct{}{}
	files := map[string]struct{}{}
	for _, f := range res.Findings {
		distinct[f.Rule+"\x00"+f.Secret] = struct{}{}
		files[f.Path] = struct{}{}
	}
	head := fmt.Sprintf("files=%d findings=%d", res.Files, n)
	if n > 0 {
		head = fmt.Sprintf("files=%d findings=%s distinct=%d", res.Files, p.contam(fmt.Sprint(n)), len(distinct))
	}
	fmt.Fprintf(out, "%s  %s  %s\n", p.amber(p.bold("SPILLSCAN")), head, p.dim(res.ScannedAt.Local().Format("2006-01-02 15:04 MST")))
	if res.Files == 0 {
		if explicit {
			fmt.Fprintln(out, p.amber("NO READING")+" — no transcripts (*.jsonl, *.jsonl.superseded-*, tool-results/) under the given paths.")
		} else {
			fmt.Fprintln(out, p.amber("NO READING")+" — no agent transcripts found under $HOME.")
			fmt.Fprintln(out, p.dim("  Looked for: "+strings.Join(paths.Agents, ", ")+". Point at a directory: spillscan scan <dir>"))
		}
		return
	}
	if n == 0 {
		fmt.Fprintln(out, p.ok("CLEAN")+fmt.Sprintf(" — %d %s surveyed, no secret-shaped contamination.", res.Files, plural(res.Files, "transcript", "transcripts")))
		return
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, p.dim("RULE\tPREVIEW\tAGENT\tFILE:LINE"))
	for _, f := range res.Findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s:%d\n", p.contam(f.Rule), f.Preview, agentLabel(f.Agent), tildify(f.Path), f.Line)
	}
	_ = tw.Flush()
	fmt.Fprintf(out, "\n%s — %d distinct %s in %d %s.\n", p.contam("CONTAMINATED"), len(distinct), plural(len(distinct), "secret", "secrets"), len(files), plural(len(files), "file", "files"))
	fmt.Fprintln(out, "  1. Rotate them at the provider first — scrubbing a transcript does not revoke a key.")
	fmt.Fprintln(out, "  2. Preview the scrub:  "+p.amber("spillscan redact"+scopeHint(res, explicit)))
	fmt.Fprintln(out, "  3. Apply it (.bak kept): "+p.amber("spillscan redact --write"+scopeHint(res, explicit)))
}

// scopeHint repeats explicit file paths in the follow-up commands (up to 3).
func scopeHint(res *scan.Result, explicit bool) string {
	if !explicit {
		return ""
	}
	var uniq []string
	for _, f := range res.Findings {
		if !slices.Contains(uniq, f.Path) {
			uniq = append(uniq, f.Path)
		}
	}
	if len(uniq) > 3 {
		return " <paths>"
	}
	for i, u := range uniq {
		uniq[i] = shellQuote(tildify(u))
	}
	return " " + strings.Join(uniq, " ")
}

func shellQuote(s string) string {
	if strings.ContainsAny(s, " '\"$`\\") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

func cmdRedact(args []string, out, errw io.Writer) int {
	write, asJSON, noColor := false, false, false
	var rest []string
	for _, a := range args {
		switch a {
		case "--write", "-write":
			write = true
		case "--json", "-json":
			asJSON = true
		case "--no-color", "-no-color":
			noColor = true
		case "-h", "--help":
			fmt.Fprintln(out, "spillscan redact [--write] [--json] [paths...]")
			fmt.Fprintln(out, "  Without --write: dry-run, nothing is changed.")
			fmt.Fprintln(out, "  With --write: copy each file to <file>.bak, then replace secrets with [REDACTED:<rule>].")
			fmt.Fprintln(out, "  JSONL lines stay valid JSON; tool-results/ spill files are treated as plain text.")
			fmt.Fprintln(out, "  Rotate keys at the provider first.")
			return 0
		default:
			if isFlag(a) {
				return badFlag(errw, "redact", a, []string{"--write", "--json", "--no-color", "--help"})
			}
			rest = append(rest, a)
		}
	}
	p := newPainter(out, noColor)
	scope := ""
	if len(rest) > 0 && len(rest) <= 3 {
		q := make([]string, len(rest))
		for i, r := range rest {
			q[i] = shellQuote(r)
		}
		scope = " " + strings.Join(q, " ")
	} else if len(rest) > 3 {
		scope = " <paths>"
	}
	if len(rest) == 0 {
		files, err := paths.ListFiles("", "")
		if err != nil {
			fmt.Fprintln(errw, "spillscan redact:", err)
			return 1
		}
		rest = files
	} else {
		for _, r := range rest {
			if _, err := os.Stat(r); err != nil {
				fmt.Fprintf(errw, "spillscan redact: path not found: %s\n", r)
				return 1
			}
		}
	}
	files, err := redact.CollectJSONL(rest)
	if err != nil {
		fmt.Fprintln(errw, "spillscan redact:", err)
		return 1
	}
	res, err := redact.Run(files, redact.Options{Write: write})
	if err != nil {
		fmt.Fprintln(errw, "spillscan redact:", err)
		return 1
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return 0
	}
	mode := p.amber("dry-run")
	if write {
		mode = p.contam("write")
	}
	fmt.Fprintf(out, "%s (%s)  files=%d replaced=%d\n", p.amber(p.bold("REDACT")), mode, res.Files, res.Replaced)
	switch {
	case res.Files == 0:
		fmt.Fprintln(out, p.amber("NO READING")+" — no transcripts to scrub.")
	case res.Replaced == 0:
		fmt.Fprintln(out, p.ok("CLEAN")+" — nothing to scrub; no files were touched.")
	case write:
		for _, b := range res.Backups {
			fmt.Fprintf(out, "  %s %s\n", p.dim("bak"), tildify(b))
		}
		fmt.Fprintf(out, "%s — %d %s replaced with [REDACTED:<rule>]. Verify: %s\n", p.ok("SCRUBBED"), res.Replaced, plural(res.Replaced, "secret", "secrets"), p.amber("spillscan scan"))
		fmt.Fprintln(out, p.dim("  Delete the .bak files once you're satisfied — they still hold the originals."))
	default:
		fmt.Fprintf(out, "Would replace %d %s. Nothing changed. Apply with: %s\n", res.Replaced, plural(res.Replaced, "secret", "secrets"), p.amber("spillscan redact --write"+scope))
	}
	return 0
}

func cmdPaths(args []string, out, errw io.Writer) int {
	asJSON := false
	for _, a := range args {
		switch a {
		case "--json", "-json":
			asJSON = true
		case "-h", "--help":
			fmt.Fprintln(out, "spillscan paths [--json]")
			fmt.Fprintln(out, "  List the transcript roots spillscan would survey.")
			return 0
		default:
			return badFlag(errw, "paths", a, []string{"--json", "--help"})
		}
	}
	roots, err := paths.Discover("")
	if err != nil {
		fmt.Fprintln(errw, "spillscan paths:", err)
		return 1
	}
	if asJSON {
		if roots == nil {
			roots = []paths.Root{}
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(roots)
		return 0
	}
	if len(roots) == 0 {
		fmt.Fprintln(out, "No transcript roots found under $HOME.")
		fmt.Fprintln(out, "  Looked for: ~/.claude/projects, ~/.codex/sessions, ~/.cursor, ~/.gemini, opencode sessions.")
		fmt.Fprintln(out, "  Elsewhere? spillscan scan <dir>")
		return 0
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "AGENT\tFILES\tPATH")
	for _, r := range roots {
		fmt.Fprintf(tw, "%s\t%d\t%s\n", r.Agent, r.Files, tildify(r.Path))
	}
	_ = tw.Flush()
	return 0
}

func agentLabel(a string) string {
	if a == "unknown" {
		return "-"
	}
	return a
}
