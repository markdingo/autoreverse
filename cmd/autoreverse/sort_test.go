package main

import (
	"testing"

	"github.com/markdingo/autoreverse/delegation"
)

func TestSortAuthorities(t *testing.T) {
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

	var slice []*delegation.Authority
	for _, d := range input {
		slice = append(slice, &delegation.Authority{Domain: d})
	}

	results := sortAuthorities(slice)
	if len(results) != len(expected) {
		t.Fatal("Slice lengths differ", len(results), len(expected))
	}

	for ix := 0; ix < len(results); ix++ {
		if results[ix].Domain != expected[ix] {
			t.Error(ix, "Mismatch", results[ix].Domain, expected[ix])
		}
	}
}
