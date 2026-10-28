// Package mcp provides a minimal read-only MCP stdio server.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Blackman99/spillscan/allow"
	"github.com/Blackman99/spillscan/paths"
	"github.com/Blackman99/spillscan/scan"
)

// Run starts the JSON-RPC MCP loop on stdin/stdout.
// Version is reported in serverInfo; set by main from the build version.
var Version = "dev"

// Home overrides $HOME for transcript discovery (tests); empty = $HOME.
var Home = ""

func Run(in io.Reader, out io.Writer) error {
	br := bufio.NewReader(in)
	for {
		line, err := br.ReadBytes('\n')
		if err == io.EOF {
			if len(line) == 0 {
				return nil
			}
		} else if err != nil {
			return err
		}
		line = trimNL(line)
		if len(line) == 0 {
			continue
		}
		var req map[string]any
		if err := json.Unmarshal(line, &req); err != nil {
			_ = writeErr(out, nil, -32700, "parse error")
			continue
		}
		id := req["id"]
		method, _ := req["method"].(string)
		params, _ := req["params"].(map[string]any)
		switch method {
		case "initialize":
			_ = writeResult(out, id, map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "spillscan", "version": Version},
			})
		case "notifications/initialized", "initialized":
			// no response
		case "tools/list":
			_ = writeResult(out, id, map[string]any{
				"tools": []map[string]any{
					{
						"name":        "scan_report",
						"description": "Scan local AI agent transcripts for spilled secrets. Returns rule, redacted preview, fingerprint, path, line, agent, plus how many findings the user's allowlist (~/.config/spillscan/allow.txt) hid. Never returns raw secret values. Read-only: never redacts.",
						"inputSchema": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"agent": map[string]any{"type": "string", "description": "Optional agent filter: claude-code, codex, cursor, …"},
							},
						},
					},
					{
						"name":        "list_paths",
						"description": "List discovered transcript roots and file counts.",
						"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
					},
				},
			})
		case "tools/call":
			name, _ := params["name"].(string)
			args, _ := params["arguments"].(map[string]any)
			switch name {
			case "scan_report":
				agent, _ := args["agent"].(string)
				al, err := allow.Load(true, nil)
				if err != nil {
					_ = writeErr(out, id, -32000, err.Error())
					continue
				}
				res, err := scan.Run(scan.Options{Agent: agent, Home: Home, Allow: al})
				if err != nil {
					_ = writeErr(out, id, -32000, err.Error())
					continue
				}
				safe := make([]map[string]any, 0, len(res.Findings))
				for _, f := range res.Findings {
					safe = append(safe, map[string]any{
						"rule": f.Rule, "preview": f.Preview, "fingerprint": f.Fingerprint, "path": f.Path,
						"line": f.Line, "agent": f.Agent, "mtime": f.Mtime,
					})
				}
				body, _ := json.Marshal(map[string]any{"files": res.Files, "findings": safe, "count": len(safe), "allowlisted": res.Allowlisted})
				_ = writeResult(out, id, map[string]any{
					"content": []map[string]any{{"type": "text", "text": string(body)}},
				})
			case "list_paths":
				roots, err := paths.Discover(Home)
				if err != nil {
					_ = writeErr(out, id, -32000, err.Error())
					continue
				}
				body, _ := json.Marshal(roots)
				_ = writeResult(out, id, map[string]any{
					"content": []map[string]any{{"type": "text", "text": string(body)}},
				})
			default:
				_ = writeErr(out, id, -32601, "unknown tool: "+name)
			}
		case "ping":
			_ = writeResult(out, id, map[string]any{})
		default:
			if id != nil {
				_ = writeErr(out, id, -32601, "method not found: "+method)
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func writeResult(w io.Writer, id any, result any) error {
	return writeMsg(w, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeErr(w io.Writer, id any, code int, msg string) error {
	return writeMsg(w, map[string]any{
		"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": code, "message": msg},
	})
}

func writeMsg(w io.Writer, m map[string]any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	if f, ok := w.(*os.File); ok {
		_ = f.Sync()
	}
	return err
}
