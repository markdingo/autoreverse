package delegation

import (
	"math/rand"
	"net"
	"strings"
	"testing"

	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
	"github.com/markdingo/autoreverse/mock/resolver"
)

// A complete bogus domain that should elicit an error return
func TestFindBogus(t *testing.T) {
	res := resolver.NewResolver("./testdata/find") // Mock resolver
	finder := NewFinder(res)
	pr := NewForwardProbe("autoreverse.doesnot.exist.")
	_, err := finder.FindAndProbe(pr)
	if err == nil {
		t.Error("Expected an error return with non-existent TLD")
	}
}

type tfapCase struct {
	reverse                string
	name, parent, contains string
	target, success        bool
}

// Run various probes thru finder.FindAndProbe and check all responses. The lookup data
// for the mock resolver has been crafted to trigger each of these errors. The
// FindAndProbe function is careful to generate a unique error message for each different
// condition so there can be no ambiguity (tho we also use the go coverage tool to confirm
// which conditions have been exercised).
func TestFindAndProbe(t *testing.T) {
	testCases := []tfapCase{
		{"", "autoreverse.example.net.", "example.net.", "",
			true, true},
		{"", "autoreverse.a.b.c.example.net.", "example.net.", "",
			true, true}, // Label gaps
		{"", "noprobe.example.net.", "example.net.", "No Probe response",
			true, false},
		{"", "wrongprobe.example.net.", "example.net.", "Wrong Probe response",
			true, false},
		{"", "lame.example.net.", "example.net.", "100% lame",
			true, false},
		{"", "noautoreverse.example.net.", "example.net.", "no delegation",
			false, false},
		{"", "lameparents.example.org.", "example.org.", "not resolve parent",
			false, false},
		{"", "nxdomain.example.net.", "example.net.", "NXDomain from parent",
			false, false},
		{"", "odd.example.net.", "example.net.", "Odd",
			false, false},
		{"", "baddelegation.example.net.", "example.net.", "Invalid Delegation",
			false, false},
		{"", "reserr.example.net.", "example.net.", "Resolver error from parent",
			false, false},
		{"", "wrongdelegation.example.net.", "example.net.", "Alert:Wrong delegation",
			false, false},

		{"192.0.2.0/24", "2.0.192.in-addr.arpa.", "192.in-addr.arpa.", "",
			true, true},
		{"2001:db8::/64", "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			"8.b.d.0.1.0.0.2.ip6.arpa.", "", true, true},
	}

	for ix, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testFindOne(t, ix, tc)
		})
	}
}

func testFindOne(t *testing.T, ix int, tc tfapCase) {
	rand.Seed(0)
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.DebugLevel)
	res := resolver.NewResolver("./testdata/find") // Mock resolver
	finder := NewFinder(res)

	var pr Probe
	if len(tc.reverse) > 0 {
		_, ipNet, err := net.ParseCIDR(tc.reverse)
		if err != nil {
			t.Fatal("Setup", err)
		}
		pr = NewReverseProbe("example.org.", ipNet)
	} else {
		pr = NewForwardProbe(tc.name)
	}
	R, err := finder.FindAndProbe(pr)
	if err != nil {
		t.Error(ix, tc.name, "Unexpected error from FindAndProbe:", err)
		t.Log(out.String())
		return
	}

	if R.ProbeSuccess != tc.success {
		t.Error(ix, tc.name, "Probe success mismatch. Want",
			tc.success, "got", R.ProbeSuccess)
		t.Log(out.String())
		out.Reset()
	}

	if len(tc.parent) > 0 { // Is parent expected?
		if R.Parent == nil {
			t.Error(ix, tc.name, "Expected parent", tc.parent)
			t.Log(out.String())
			out.Reset()
		} else if tc.parent != R.Parent.Domain {
			t.Error(ix, tc.name, "Parent mis-match. Want",
				tc.parent, "got", R.Parent.Domain)
			t.Log(out.String())
			out.Reset()
		}
	} else if R.Parent != nil {
		t.Error(ix, tc.name, "Did not expect a parent response", R.Parent.Domain)
		t.Log(out.String())
		out.Reset()
	}

	if tc.target {
		if R.Target == nil {
			t.Error(ix, tc.name, "Expected Target return")
			t.Log(out.String())
			out.Reset()
		} else if R.Target.Domain != tc.name {
			t.Error(ix, tc.name, "Target Domain mismatch. Want",
				tc.name, "got", R.Target.Domain)
			t.Log(out.String())
			out.Reset()
		}
	} else {
		if R.Target != nil {
			t.Error(ix, tc.name, "Did not expect target", R.Target.Domain)
		}
	}

	if len(tc.contains) > 0 {
		got := out.String()
		if !strings.Contains(got, tc.contains) {
			t.Error(ix, tc.name, "Got error, but wrong one. Want", tc.contains,
				"got", got)
			out.Reset()
		}
	}
}
