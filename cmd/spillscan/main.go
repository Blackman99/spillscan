// spillscan finds and scrubs secrets spilled into local AI agent transcripts.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

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
  spillscan scan [--json] [--agent NAME] [paths...]
  spillscan redact [--write] [--json] [paths...]
  spillscan paths [--json]
  spillscan guard          # Claude Code PreToolUse hook (stdin → stdout)
  spillscan mcp            # read-only MCP stdio (scan_report, list_paths)
  spillscan version

Exit codes: 0 clean/ok · 2 findings (scan) · 1 error
`

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
		fmt.Fprint(errw, usage)
		return 1
	}
}

func cmdScan(args []string, out, errw io.Writer) int {
	asJSON, agent, rest := false, "", []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json", "-json":
			asJSON = true
		case "--agent", "-agent":
			i++
			if i >= len(args) {
				fmt.Fprintln(errw, "spillscan scan: --agent needs a value")
				return 1
			}
			agent = args[i]
		case "-h", "--help":
			fmt.Fprintln(out, "spillscan scan [--json] [--agent NAME] [paths...]")
			return 0
		default:
			rest = append(rest, args[i])
		}
	}
	res, err := scan.Run(scan.Options{Agent: agent, Paths: rest})
	if err != nil {
		fmt.Fprintln(errw, "spillscan:", err)
		return 1
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		printScan(out, res)
	}
	if len(res.Findings) > 0 {
		return 2
	}
	return 0
}

func printScan(out io.Writer, res *scan.Result) {
	fmt.Fprintf(out, "SPILLSCAN  files=%d findings=%d  %s\n", res.Files, len(res.Findings), res.ScannedAt.Format(time.RFC3339))
	if len(res.Findings) == 0 {
		fmt.Fprintln(out, "CLEAN — no secret-shaped contamination detected.")
		return
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tPREVIEW\tAGENT\tFILE:LINE")
	for _, f := range res.Findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s:%d\n", f.Rule, f.Preview, f.Agent, f.Path, f.Line)
	}
	_ = tw.Flush()
	fmt.Fprintln(out, "\nRotate these credentials, then: spillscan redact --write <paths>")
}

func cmdRedact(args []string, out, errw io.Writer) int {
	write, asJSON := false, false
	var rest []string
	for _, a := range args {
		switch a {
		case "--write", "-write":
			write = true
		case "--json", "-json":
			asJSON = true
		case "-h", "--help":
			fmt.Fprintln(out, "spillscan redact [--write] [--json] [paths...]")
			fmt.Fprintln(out, "  Without --write: dry-run. With --write: backup to .bak then mutate.")
			return 0
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) == 0 {
		files, err := paths.ListFiles("", "")
		if err != nil {
			fmt.Fprintln(errw, "spillscan:", err)
			return 1
		}
		rest = files
	}
	files, err := redact.CollectJSONL(rest)
	if err != nil {
		fmt.Fprintln(errw, "spillscan:", err)
		return 1
	}
	res, err := redact.Run(files, redact.Options{Write: write})
	if err != nil {
		fmt.Fprintln(errw, "spillscan:", err)
		return 1
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return 0
	}
	mode := "dry-run"
	if write {
		mode = "write"
	}
	fmt.Fprintf(out, "REDACT (%s)  files=%d replaced=%d\n", mode, res.Files, res.Replaced)
	if write {
		for _, b := range res.Backups {
			fmt.Fprintf(out, "  bak %s\n", b)
		}
	} else if res.Replaced > 0 {
		fmt.Fprintln(out, "Re-run with --write to scrub (creates .bak first).")
	}
	return 0
}

func cmdPaths(args []string, out, errw io.Writer) int {
	asJSON := false
	for _, a := range args {
		if a == "--json" || a == "-json" {
			asJSON = true
		}
	}
	roots, err := paths.Discover("")
	if err != nil {
		fmt.Fprintln(errw, "spillscan:", err)
		return 1
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(roots)
		return 0
	}
	if len(roots) == 0 {
		fmt.Fprintln(out, "No transcript roots found under $HOME.")
		return 0
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "AGENT\tFILES\tPATH")
	for _, r := range roots {
		fmt.Fprintf(tw, "%s\t%d\t%s\n", r.Agent, r.Files, r.Path)
	}
	_ = tw.Flush()
	return 0
}
