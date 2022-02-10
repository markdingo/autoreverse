package main

import (
	"strings"
	"testing"

	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
)

func TestUsage(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	cfg := newConfig()
	ar := newAutoReverse(cfg, nil)

	testCases := []struct {
		options string
		expect  string
		result  parseResult
	}{
		{"", "", parseContinue},
		{"-h", "SYNOPSIS", parseStop},
		{"--help", "SYNOPSIS", parseStop},
		{"-v", "Program:", parseStop},
		{"--version", "Program:", parseStop},
		{"--manpage", ".Sh NAME", parseStop},
		{"goop", "goop", parseFailed},
		{"-X", "unknown shorthand flag", parseFailed},
		{"--forward o.example.net --forward t.example.net", "Duplicate option", parseFailed},
		{"--listen 127.0.0.1 --listen ::1", "", parseContinue}, // This duplicate is ok
		{"--forward a.v --reverse 127.0.0.1/24" +
			" --listen ::1 --listen 127.0.0.1" +
			" --PTR-deduce http://url --PTR-deduce axfr://url" +
			" --passthru a-server --synthesize=true --CHAOS=true" +
			" --NSID myname --TTL 45m" +
			" --user u --group g --chroot /root" +
			" --log-major --log-minor --log-debug=true" +
			" --log-queries=false --report 4h", "", parseContinue}, // Every legit option
	}

	for ix, tc := range testCases {
		var opts []string
		if len(tc.options) > 0 {
			opts = strings.Split(tc.options, " ")
		}
		args := []string{programName}
		args = append(args, opts...)
		out.Reset()
		res := ar.parseOptions(args)
		if res != tc.result {
			t.Error(ix, "Results mismatch. Want", tc.result, "got", res)
		}
		got := out.String()
		if len(tc.expect) == 0 && len(got) != 0 {
			t.Error(ix, "Did not expect any output, but got", len(got), got)
		}
		if len(tc.expect) > 0 {
			if !strings.Contains(got, tc.expect) {
				t.Error(ix, "Output does not contain", tc.expect, "got", got)
			}
		}
	}
}
