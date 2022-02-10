package main

import (
	"net"
	"testing"

	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
)

func TestGenerateLocalForward(t *testing.T) {
	ar := newAutoReverse(nil, nil)
	ar.generateLocalForward("example.net.")
	if ar.authorities.len() != 1 {
		t.Error("GLF should have added authority", ar.authorities.len())
	}

	auth := ar.authorities.slice[0]
	if auth.Domain != "example.net." {
		t.Error("Auth was net set", auth)
	}
}

func TestGenerateLocalReverse(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MajorLevel)

	ar := newAutoReverse(nil, nil)

	// Set up a forward as locals assumes there's already one present.  Include an NS
	// to ensure it's copied to the locals
	ar.generateLocalForward("example.net.")
	ar.forwardAuthority.NS = append(ar.forwardAuthority.NS,
		newRR("example.net. IN NS a.ns.example.net."))

	_, ipNet, err := net.ParseCIDR("2001:db8::/20")
	if err != nil {
		t.Fatal("Setup error", err)
	}
	ar.localReverses = append(ar.localReverses, ipNet)
	_, ipNet, err = net.ParseCIDR("192.0.2.0/16")
	if err != nil {
		t.Fatal("Setup error", err)
	}
	ar.localReverses = append(ar.localReverses, ipNet)
	err = ar.generateLocalReverses()
	if err != nil {
		t.Error("Unexpected v4 error", ipNet, err)
	}

	if ar.authorities.len() != 3 { // Forward + two reverses
		t.Error("GLR should have added authority", ar.authorities.len())
	}

	auth := ar.authorities.slice[1]
	exp := "0.1.0.0.2.ip6.arpa."
	if auth.Domain != exp {
		t.Error("Wrong v6 reverse. Exp", exp, "Got", auth.Domain)
	}
	if len(auth.NS) != 1 {
		t.Error("Forward NS was not copied across")
	} else if auth.NS[0].Header().Name != exp {
		t.Error("Reverse NS was not transmogrified", auth.NS[0].Header().Name)
	}

	auth = ar.authorities.slice[2]
	exp = "0.192.in-addr.arpa."
	if auth.Domain != exp {
		t.Error("Wrong v4 reverse. Exp", exp, "Got", auth.Domain)
	}
	if len(auth.NS) != 1 {
		t.Error("Forward NS was not copied across")
	} else if auth.NS[0].Header().Name != exp {
		t.Error("Reverse NS was not transmogrified", auth.NS[0].Header().Name)
	}

	// Calling a second time exercises the duplicate tests code - in a lazy way
	err = ar.generateLocalReverses()
	if err == nil {
		t.Error("Expected a 'duplicates' error")
	}
}
