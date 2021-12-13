package dnsutil

import (
	"testing"
)

func TestChompCanonicalName(t *testing.T) {
	r := ChompCanonicalName("a.b.c")
	if r != "a.b.c" {
		t.Error("Chomp is modifying when it shouldn't", r)
	}
	r = ChompCanonicalName("a.b.c.")
	if r != "a.b.c" {
		t.Error("Chomp is not chomping", r)
	}
	r = ChompCanonicalName("a.b.c..") // Only chomps one dot
	if r != "a.b.c." {
		t.Error("Chomp is not chomping", r)
	}
}
