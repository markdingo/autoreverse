package main

import (
	"net"
	"testing"
)

func TestAuthoritiesSort(t *testing.T) {
	input := []string{
		"0.192.in-addr.arpa.",
		"0.8.b.d.0.1.0.0.2.ip6.arpa.",
		"192.in-addr.arpa.",
		"191.in-addr.arpa.",
		"193.in-addr.arpa.",
		"2.0.192.in-addr.arpa.",
		"8.b.d.0.1.0.0.2.ip6.arpa.",
		"example.com.",
		"f.0.8.b.d.0.1.0.0.2.ip6.arpa.",
		"aspecific.example.com.",
		"a.b.c.d.e.f.labels.",  // More labels should come earlier
		"aabbccddeeff.labels.", // than merely long labels
		"a.bbbbbbb.c.",         // Same number of labels
		"bbbbbb.aa.c.",         // means a string compare
	}

	expected := []string{
		"f.0.8.b.d.0.1.0.0.2.ip6.arpa.", // This is most labels first
		"0.8.b.d.0.1.0.0.2.ip6.arpa.",   // followed by string comparison
		"8.b.d.0.1.0.0.2.ip6.arpa.",     // for same label count
		"a.b.c.d.e.f.labels.",
		"2.0.192.in-addr.arpa.",
		"0.192.in-addr.arpa.",
		"bbbbbb.aa.c.",
		"aspecific.example.com.",
		"a.bbbbbbb.c.",
		"193.in-addr.arpa.",
		"192.in-addr.arpa.",
		"191.in-addr.arpa.",
		"example.com.",
		"aabbccddeeff.labels.",
	}

	var auths authorities
	for _, d := range input {
		a := &authority{}
		a.Domain = d
		_, a.cidr, _ = net.ParseCIDR("192.0.2.0/24") // Just to make append() happy
		auths.append(a)
	}
	b4 := auths.len()
	auths.sort()
	af := auths.len()
	if b4 != af {
		t.Fatal("Slice lengths differ", b4, af)
	}

	for ix := 0; ix < auths.len(); ix++ {
		if auths.slice[ix].Domain != expected[ix] {
			t.Error(ix, "Mismatch", auths.slice[ix].Domain, expected[ix])
		}
	}
}

func TestAuthoritiesFindInDomain(t *testing.T) {
	var auths authorities
	for _, d := range []string{"a.example.net.", "b.a.example.net.", "c.b.a.example.net."} {
		a := &authority{forward: true}
		a.Domain = d
		auths.append(a)
	}

	for _, d := range []string{"0.8.b.d.0.1.0.0.2.ip6.arpa.", "1.0.0.2.ip6.arpa."} {
		a := &authority{}
		a.Domain = d
		a.cidr = &net.IPNet{} // Filler to make append() happy
		auths.append(a)
	}

	auths.sort()

	type testCase struct {
		qName  string
		expect string
	}

	testCases := []testCase{
		{"8.b.d.0.2.0.0.2.ip6.arpa.", ""},
		{"0.8.b.d.0.1.0.0.2.ip6.arpa.", "0.8.b.d.0.1.0.0.2.ip6.arpa."},
		{"1.2.3.0.8.b.d.0.1.0.0.2.ip6.arpa.", "0.8.b.d.0.1.0.0.2.ip6.arpa."},
		{"1.2.3.40.8.b.d.0.1.0.0.2.ip6.arpa.", "1.0.0.2.ip6.arpa."},
		{"1.0.0.2.ip6.arpa.", "1.0.0.2.ip6.arpa."},
		{"a.example.net.", "a.example.net."},
		{"b.a.example.net.", "b.a.example.net."},
		{"c.b.a.example.net.", "c.b.a.example.net."},
		{"d.c.b.a.example.net.", "c.b.a.example.net."},
	}

	for ix, tc := range testCases {
		a := auths.findInDomain(tc.qName)
		if a == nil {
			if len(tc.expect) > 0 {
				t.Error(ix, "No auth returned for", tc.qName)
			}
			continue
		}
		if a.Domain != tc.expect {
			t.Error(ix, "Wrong Domain returned", a.Domain)
		}
	}
}
