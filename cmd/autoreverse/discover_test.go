package main

import (
	"math/rand"
	"net"
	"strings"
	"testing"

	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
	"github.com/markdingo/autoreverse/mock/resolver"
)

type tdCase struct {
	forward  string
	reverses string
}

// Remember, these tests are intended to exercise the code inside this
// directory. Exercising the delegation logic happens on over in its directory.
func TestDiscoverForward(t *testing.T) {
	rand.Seed(0) // Make PRNG predictable for probe generation
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MajorLevel)
	res := resolver.NewResolver("./testdata/discover")
	ar := newAutoReverse(&config{TTLAsSecs: 61}, res)       // Needed by zone parser
	ar.cfg.listen = append(ar.cfg.listen, "127.0.0.1:6366") // Exercise mutables setting
	ar.startServers()
	srv := ar.servers[0]
	mutsBefore := srv.getMutables()
	defer ar.stopServers()

	// Start off with a nice easy one that works. The delegation is
	// ns.autoreverse.example.net which is returned in the NS query to the parent.
	ar.cfg.delegatedForward = "autoreverse.example.net."
	ar.forward = ar.cfg.delegatedForward
	err := ar.discover()
	if err != nil {
		t.Error(err)
	}

	// Each successful discover should sets mutables afresh, so check that it did
	mutsAfter := srv.getMutables()
	if mutsBefore.ptrSuffix == mutsAfter.ptrSuffix {
		t.Log("Mutables didn't change", mutsBefore.ptrSuffix, mutsAfter.ptrSuffix)
	}
	if mutsBefore.authorities.len() == mutsAfter.authorities.len() {
		t.Log("Mutables didn't change",
			mutsBefore.authorities.len(), mutsAfter.authorities.len())
	}

	// Forward Error paths

	// Have parent, but not delegation
	ar.cfg.delegatedForward = "noautoreverse.example.net."
	err = ar.discover()
	if err == nil {
		t.Error("Expected discover to fail")
	} else if !strings.Contains(err.Error(), "no delegation") {
		t.Error("Wrong error returned", err)
	}

	// No probe response
	ar.cfg.delegatedForward = "noprobe.example.net."
	err = ar.discover()
	if err == nil {
		t.Error("Expected discover to fail")
	} else if !strings.Contains(err.Error(), "failed to self-identify") {
		t.Error("Wrong error returned", err)
	}

	// No delegation
	ar.cfg.delegatedForward = "lameparents.example.org."
	err = ar.discover()
	if err == nil {
		t.Error("Expected discover to fail")
	} else if !strings.Contains(err.Error(), "no delegation") {
		t.Error("Wrong error returned", err)
	}

	// No Parent
	ar.cfg.delegatedForward = "does.not.exist."
	err = ar.discover()
	if err == nil {
		t.Error("Expected discover to fail")
	} else if !strings.Contains(err.Error(), "No Delegation") {
		t.Error("Wrong error returned", err)
	}
}

// A nice easy test with no error cases. A forward and two reverses. Very typical.
func TestDiscoverReverseGood(t *testing.T) {
	rand.Seed(0) // Make PRNG predictable for probe generation
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.DebugLevel)
	res := resolver.NewResolver("./testdata/discover")
	ar := newAutoReverse(&config{TTLAsSecs: 61}, res) // Needed by zone parser

	ar.cfg.delegatedForward = "autoreverse.example.net."
	ar.forward = ar.cfg.delegatedForward

	ar.cfg.listen = append(ar.cfg.listen, "127.0.0.1:6366") // Exercise mutables setting
	ar.startServers()
	srv := ar.servers[0]
	mutsBefore := srv.getMutables()
	defer ar.stopServers()

	_, v4Net, e4 := net.ParseCIDR("192.0.2.0/24")
	if e4 != nil {
		t.Fatal("Setup", e4)
	}
	_, v6Net, e6 := net.ParseCIDR("2001:db8::/64")
	if e6 != nil {
		t.Fatal("Setup", e6)
	}
	ar.delegatedReverses = append(ar.delegatedReverses, v4Net)
	ar.delegatedReverses = append(ar.delegatedReverses, v6Net)
	err := ar.discover()
	if err != nil {
		t.Error(err)
	}

	mutsAfter := srv.getMutables()
	if mutsBefore.ptrSuffix == mutsAfter.ptrSuffix {
		t.Log("Mutables didn't change", mutsBefore.ptrSuffix, mutsAfter.ptrSuffix)
	}
	if mutsBefore.authorities.len() == mutsAfter.authorities.len() {
		t.Log("Mutables didn't change",
			mutsBefore.authorities.len(), mutsAfter.authorities.len())
	}

	if ar.authorities.len() != 3 {
		t.Error("Authority count wrong. Want 3, got", ar.authorities.len())
		t.Log(out.String())
	}
}

type tdreCase struct {
	reverse        string
	name, contains string
	success        bool
}

func TestDiscoverReverseErrors(t *testing.T) {
	testCases := []tdreCase{
		{"10.0.0.0/8", "10.in-addr.arpa.", "No Delegation", false},
		{"192.0.3.0/24", "192.in-addr.arpa.", "has no delegation for", false},
		{"192.0.4.0/24", "192.in-addr.arpa.", "Probe failed", false},
	}

	for ix, tc := range testCases {
		t.Run(tc.reverse, func(t *testing.T) {
			testDREOne(t, ix, tc)
		})
	}
}

func testDREOne(t *testing.T, ix int, tc tdreCase) {
	rand.Seed(0) // Make PRNG predictable for probe generation
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.DebugLevel)
	res := resolver.NewResolver("./testdata/discover")
	ar := newAutoReverse(&config{TTLAsSecs: 61}, res) // Needed by zone parser

	ar.cfg.localForward = "example.org." // set forward to a known
	ar.forward = ar.cfg.localForward     // good value

	_, ipNet, err := net.ParseCIDR(tc.reverse)
	if err != nil {
		t.Fatal("Setup", err)
	}
	ar.delegatedReverses = append(ar.delegatedReverses, ipNet)
	err = ar.discover()
	if err != nil {
		if len(tc.contains) > 0 {
			if !strings.Contains(err.Error(), tc.contains) {
				t.Error(ix, tc.reverse, "Got wrong error. Wanted",
					tc.contains, "got", err.Error())
				t.Log(out.String())
				out.Reset()
			}
		} else {
			t.Error(ix, tc.reverse, "Unexpected error", err.Error())
			t.Log(out.String())
			out.Reset()
		}
		return
	}
	if len(tc.contains) > 0 {
		t.Error(ix, tc.reverse, "Did not get error with: ", tc.contains)
		t.Log(out.String())
		out.Reset()
		return
	}
}

func TestDiscoverReverseDupes(t *testing.T) {
	rand.Seed(0) // Make PRNG predictable for probe generation
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.DebugLevel)
	res := resolver.NewResolver("./testdata/discover")
	ar := newAutoReverse(&config{TTLAsSecs: 61}, res) // Needed by zone parser

	ar.cfg.localForward = "example.org." // set forward to a known
	ar.forward = ar.cfg.localForward     // good value

	_, ipNet, err := net.ParseCIDR("2001:db8::/64")
	if err != nil {
		t.Fatal("Setup", err)
	}
	ar.delegatedReverses = append(ar.delegatedReverses, ipNet)
	ar.delegatedReverses = append(ar.delegatedReverses, ipNet)
	err = ar.discover()
	if err == nil {
		t.Error("Expected Error from duplicate reverses")
		t.Log(out.String())
	} else if !strings.Contains(err.Error(), "is duplicate") {
		t.Error("Got wrong error. Want 'is duplicate', got", err.Error())
		t.Log(out.String())
	}
}
