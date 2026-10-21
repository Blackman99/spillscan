package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Obviously fake values only.
const (
	fakeAKIA = "AKIAIOSFODNN7EXAMPLE"
	fakeGHP  = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE00"
)

func writeT(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readT(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUndoExactRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.jsonl")
	orig := `{"a":"x"}` + "\n" + `{"out":"AWS_KEY ` + fakeAKIA + `"}` + "\r\n" + `{"z":1}`
	writeT(t, p, orig)
	if _, err := Run([]string{p}, Options{Write: true}); err != nil {
		t.Fatal(err)
	}
	baks, err := FindBackups([]string{dir})
	if err != nil || len(baks) != 1 {
		t.Fatalf("baks=%v err=%v", baks, err)
	}
	dry, err := Undo(baks, Options{})
	if err != nil || dry.Restored != 1 || dry.Items[0].State != UndoExact {
		t.Fatalf("dry=%+v err=%v", dry, err)
	}
	if strings.Contains(readT(t, p), fakeAKIA) {
		t.Fatal("dry-run must not touch the file")
	}
	res, err := Undo(baks, Options{Write: true})
	if err != nil || res.Restored != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if got := readT(t, p); got != orig {
		t.Fatalf("not byte-identical:\n%q\n%q", got, orig)
	}
	if _, err := os.Stat(p + ".bak"); !os.IsNotExist(err) {
		t.Fatal(".bak should be removed after restore")
	}
}

func TestUndoKeepsAppendedTail(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tool-results", "out.txt")
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	writeT(t, p, "token "+fakeGHP+"\n")
	if _, err := Run([]string{p}, Options{Write: true}); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("later line one\nlater line two")
	_ = f.Close()
	res, err := Undo([]string{p + ".bak"}, Options{Write: true})
	if err != nil || res.Items[0].State != UndoAppended || res.Items[0].TailLines != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	want := "token " + fakeGHP + "\nlater line one\nlater line two"
	if got := readT(t, p); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestUndoDivergedAndMissingAreLeftAlone(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.jsonl")
	writeT(t, p, `{"k":"`+fakeAKIA+`"}`+"\n")
	if _, err := Run([]string{p}, Options{Write: true}); err != nil {
		t.Fatal(err)
	}
	writeT(t, p, `{"rewritten":true}`+"\n")
	gone := filepath.Join(dir, "gone.jsonl")
	writeT(t, gone+".bak", `{"k":"`+fakeAKIA+`"}`+"\n")
	baks, _ := FindBackups([]string{dir})
	res, err := Undo(baks, Options{Write: true})
	if err != nil || res.Restored != 0 || res.Skipped != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	states := map[string]string{}
	for _, it := range res.Items {
		states[filepath.Base(it.Path)] = it.State
	}
	if states["s.jsonl"] != UndoDiverged || states["gone.jsonl"] != UndoMissing {
		t.Fatalf("states=%v", states)
	}
	if readT(t, p) != `{"rewritten":true}`+"\n" {
		t.Fatal("diverged file must be left alone")
	}
	if _, err := os.Stat(p + ".bak"); err != nil {
		t.Fatal("diverged .bak must be kept")
	}
}

// A second `redact --write` after the agent appended a new secret must not
// overwrite the first backup; undo then restores every original.
func TestSecondScrubExtendsBackup(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.jsonl")
	first := `{"k":"` + fakeAKIA + `"}` + "\n"
	writeT(t, p, first)
	if _, err := Run([]string{p}, Options{Write: true}); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	second := `{"t":"` + fakeGHP + `"}` + "\n"
	_, _ = f.WriteString(second)
	_ = f.Close()
	if _, err := Run([]string{p}, Options{Write: true}); err != nil {
		t.Fatal(err)
	}
	if got := readT(t, p+".bak"); got != first+second {
		t.Fatalf("bak=%q", got)
	}
	cur := readT(t, p)
	if strings.Contains(cur, fakeAKIA) || strings.Contains(cur, fakeGHP) {
		t.Fatalf("secrets left: %s", cur)
	}
	if _, err := Undo([]string{p + ".bak"}, Options{Write: true}); err != nil {
		t.Fatal(err)
	}
	if got := readT(t, p); got != first+second {
		t.Fatalf("after undo %q", got)
	}
}

func TestScrubRefusesForeignBackup(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.jsonl")
	writeT(t, p, `{"k":"`+fakeAKIA+`"}`+"\n")
	writeT(t, p+".bak", "someone else's backup\n")
	_, err := Run([]string{p}, Options{Write: true})
	if err == nil || !strings.Contains(err.Error(), "move it aside") {
		t.Fatalf("err=%v", err)
	}
	if readT(t, p+".bak") != "someone else's backup\n" {
		t.Fatal("foreign .bak must not be overwritten")
	}
}
