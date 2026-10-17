package paths

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// imageExts are skipped under tool-results/: Claude Code stores full-size
// copies of MCP-returned images there, and they are not text.
var imageExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".bmp": true, ".tif": true, ".tiff": true, ".ico": true, ".heic": true,
}

// IsTranscript reports whether path is a file spillscan should survey:
//   - session transcripts: *.jsonl
//   - transcripts Claude Code set aside: *.jsonl.superseded-<timestamp>
//   - large tool outputs Claude Code spilled to a tool-results/ directory
//     (any name, plain text or JSON; images skipped)
//
// spillscan's own .bak backups are never matched.
// See https://code.claude.com/docs/en/claude-directory (Application data).
func IsTranscript(path string) bool {
	name := filepath.Base(path)
	if strings.HasSuffix(name, ".bak") {
		return false
	}
	if strings.HasSuffix(name, ".jsonl") || strings.Contains(name, ".jsonl.superseded-") {
		return true
	}
	if inToolResults(path) {
		return !imageExts[strings.ToLower(filepath.Ext(name))]
	}
	return false
}

func inToolResults(path string) bool {
	dir := filepath.ToSlash(filepath.Dir(path))
	for _, part := range strings.Split(dir, "/") {
		if part == "tool-results" {
			return true
		}
	}
	return false
}

// IsJSONL reports whether lines of path are expected to be JSON objects.
func IsJSONL(path string) bool {
	name := filepath.Base(path)
	return strings.HasSuffix(name, ".jsonl") || strings.Contains(name, ".jsonl.superseded-")
}

// IsBinary sniffs the first 8 KiB of path for a NUL byte.
func IsBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 8192)
	n, _ := io.ReadFull(f, buf)
	return bytes.IndexByte(buf[:n], 0) >= 0
}

// Walk returns every transcript file under dir (see IsTranscript).
func Walk(dir string) []string {
	var out []string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() && IsTranscript(p) {
			out = append(out, p)
		}
		return nil
	})
	return out
}
