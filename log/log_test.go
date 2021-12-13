package log

import (
	"testing"

	"github.com/markdingo/autoreverse/mock"
)

func TestLevels(t *testing.T) {
	var w mock.IOWriter
	SetOut(&w)
	if Out() != &w {
		t.Fatal("SetOut or Out failed")
	}

	SetLevel(SilentLevel)
	if Level() != SilentLevel {
		t.Error("Set Silent failed")
	}
	if IfMajor() {
		t.Error("Silent should not be major")
	}
	if IfMinor() {
		t.Error("Silent should not be minor")
	}
	if IfDebug() {
		t.Error("Silent should not be debug")
	}
	if MajorLevel.String() != "Major" {
		t.Error("Wrong Major string", MajorLevel.String())
	}
	if MinorLevel.String() != "Minor" {
		t.Error("Wrong Minor string", MinorLevel.String())
	}
	if DebugLevel.String() != "Debug" {
		t.Error("Wrong Debug string", DebugLevel.String())
	}
	if SilentLevel.String() != "Silent" {
		t.Error("Wrong Silent string", SilentLevel.String())
	}

	Major("Should not log")
	Minor("Should not log")
	Debug("Should not log")
	Majorf("Should not log")
	Minorf("Should not log")
	Debugf("Should not log")
	if w.Len() > 0 {
		t.Error("Silent still logged", w.String())
	}

	w.Reset()
	SetLevel(MajorLevel) // Should accept minor + major but not debug
	Major("a")
	Minor("b")
	Debug("c")

	Majorf("d")
	Minorf("e")
	Debugf("f")

	exp := "a\nd\n"
	if w.String() != exp {
		t.Error("Major Levels not working. Got:", w.String(), "Exp:", exp, "<<")
	}

	w.Reset()
	SetLevel(MinorLevel) // Should accept minor + major but not debug
	Major("a")
	Minor("b")
	Debug("c")
	Majorf("d")
	Minorf("e")
	Debugf("f")
	exp = "a\n" + minorPrefix + "b\n" + "d\n" + minorPrefix + "e\n"
	if w.String() != exp {
		t.Error("Minor Levels not working. Got:", w.String(), "Exp:", exp)
	}
}

func TestFormat(t *testing.T) {
	var w mock.IOWriter
	SetOut(&w)
	SetLevel(MinorLevel)
	// Need to trick the complier so it doesn't warn about %d
	f := "%"
	f += "d a "
	Major(f, 5)       // Should not format
	Majorf("%d b", 5) // Should format
	exp := "%d a 5\n5 b\n"
	if exp != w.String() {
		t.Error("F and non-F not working", len(w.String()), len(exp), w.String(), exp)
	}
}

func TestMultiLine(t *testing.T) {
	var w mock.IOWriter
	SetOut(&w)
	SetLevel(MinorLevel)

	w.Reset()
	Major("a")
	exp := "a\n"
	if exp != w.String() {
		t.Error("Multiline with no trailing NL failed", exp, w.String())
	}
	w.Reset()
	Major("a\n") // Should produce the same result
	if exp != w.String() {
		t.Error("Multiline with no trailing NL failed", exp, w.String())
	}

	w.Reset()
	Major("a\nb")
	exp = "a\nb\n"
	if exp != w.String() {
		t.Error("Multiline with no trailing NL failed", exp, w.String())
	}

	w.Reset()
	Major("a\nb\n\n\n") // Should produce the same results
	if exp != w.String() {
		t.Error("Multiline with many trailing NLs failed", exp, w.String())
	}

	// Check that prefix gets added correctly
	w.Reset()
	SetLevel(DebugLevel)
	Debug("a\nb")
	exp = debugPrefix + "a\n" + debugPrefix + "b\n"
	if exp != w.String() {
		t.Error("Multiline with no trailing NL failed", exp, w.String())
	}

	w.Reset()
	Debug("a\nb\n\n\n") // Should produce the same results
	if exp != w.String() {
		t.Error("Multiline with many trailing NLs failed", exp, w.String())
	}
}
