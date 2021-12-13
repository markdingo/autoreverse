package log

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type logLevel int

const (
	SilentLevel logLevel = iota
	MajorLevel
	MinorLevel
	DebugLevel
)

var (
	majorPrefix = ""        // Prepended to each output. These values may be configurable
	minorPrefix = "  "      // at some point in the future, but there is no current need
	debugPrefix = "   Dbg:" // for that yet.

	out   io.Writer
	level logLevel
)

func init() {
	out = os.Stdout
}

func (t logLevel) String() string {
	switch t {
	case MajorLevel:
		return "Major"
	case MinorLevel:
		return "Minor"
	case DebugLevel:
		return "Debug"
	}

	return "Silent"
}

// SetOut changes the output of logging to the supplied io.Writer. The default is
// os.Stdout. The supplied io.Writer must never be nil.
func SetOut(w io.Writer) {
	if w == nil {
		panic("log.SetOut() called with a nil io.Writer")
	}
	out = w
}

// Out returns the current io.Writer for specialist logger functions which are not
// controlled by log levels. The return value will never be nil.
func Out() io.Writer {
	return out
}

// SetLevel sets the current logging level. Ignored if previously set by ENV variable.
func SetLevel(l logLevel) {
	level = l
}

// Level returns current level

func Level() logLevel {
	return level
}

// IfMajor returns true if Major logging is written to the output stream. Applications
// have access to these If* functions in cases where evaluation of the log arguments is
// expensive and the caller wishes to minimize that cost.
func IfMajor() bool {
	return level >= MajorLevel
}

func IfMinor() bool {
	return level >= MinorLevel
}

func IfDebug() bool {
	return level >= DebugLevel
}

// Majorf provides an approximate fmt.Printf equivalent interface to logging. Output is
// only generated if the level is >= Major. A newline is always added to the end of the
// output so the caller should not have that in there string. All output is prefixed with
// the current major prefix which may be an empty string.
func Majorf(format string, a ...interface{}) (n int, err error) {
	if level >= MajorLevel {
		s := fmt.Sprintf(format, a...)
		return prefixAndPrintLines(s, majorPrefix)
	}

	return 0, nil
}

// Major provides a fmt.Print like interface to logging. Output is only generated if the
// level is >= Major. Major uses fmt.Sprint to generate the output line thus it inherits
// the feature whereby spaces are added between operands when neither is a string.
func Major(a ...interface{}) (n int, err error) {
	if level >= MajorLevel {
		s := fmt.Sprint(a...)
		return prefixAndPrintLines(s, majorPrefix)
	}

	return 0, nil
}

// Minorf provides a fmt.Printf equivalent interface to logging. Output is only generated
// if the level is >= Minor.
func Minorf(format string, a ...interface{}) (n int, err error) {
	if level >= MinorLevel {
		s := fmt.Sprintf(format, a...)
		return prefixAndPrintLines(s, minorPrefix)
	}

	return 0, nil
}

// Minor provides a fmt.Print like interface to logging. Output is only generated if the
// level is >= Minor. Minor uses fmt.Sprint to generate the output line thus it inherits
// the feature whereby spaces are added between operands when neither is a string.
func Minor(a ...interface{}) (n int, err error) {
	if level >= MinorLevel {
		s := fmt.Sprint(a...)
		return prefixAndPrintLines(s, minorPrefix)
	}

	return 0, nil
}

// Debugf provides a fmt.Printf equivalent interface to logging. Output is only generated
// if the level is >= Debug.
func Debugf(format string, a ...interface{}) (n int, err error) {
	if level >= DebugLevel {
		s := fmt.Sprintf(format, a...)
		return prefixAndPrintLines(s, debugPrefix)
	}

	return 0, nil
}

// Debug provides a fmt.Print like interface to logging. Output is only generated if the
// level is >= Debug. Debug uses fmt.Sprint to generate the output line thus it inherits
// the feature whereby spaces are added between operands when neither is a string.
func Debug(a ...interface{}) (n int, err error) {
	if level >= DebugLevel {
		s := fmt.Sprint(a...)
		return prefixAndPrintLines(s, debugPrefix)
	}

	return 0, nil
}

// prefixAndPrintLines is the common handler which takes potentially multiple lines and
// sends them to the out stream prefixed with the supplied prefix.
func prefixAndPrintLines(lines, prefix string) (int, error) {
	if strings.Index(lines, "\n") == 0 { // Expect this to be the common case
		return fmt.Fprint(out, prefix, lines, "\n")
	}

	ar := strings.Split(lines, "\n")

	for len(ar) > 0 && len(ar[len(ar)-1]) == 0 { // Chomp trailing empty lines
		ar = ar[:len(ar)-1]
	}

	s := strings.Join(ar, "\n"+prefix) // Line1 \nprefix Line2 \nprefix Line3

	return fmt.Fprint(out, prefix, s, "\n")
}
