package main

import (
	"strings"
	"testing"

	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
)

// Why not?
func TestVersion(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	cfg := newConfig()
	cfg.printVersion()
	got := out.String()
	if !strings.Contains(got, "Program:") ||
		!strings.Contains(got, "Project:") ||
		!strings.Contains(got, "Inspiration:") ||
		!strings.Contains(got, programName) ||
		!strings.Contains(got, cfg.projectURL) {
		t.Error("Unexpected version output", got)
	}
}
