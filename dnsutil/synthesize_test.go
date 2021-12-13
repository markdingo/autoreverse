package dnsutil

import (
	"net"
	"testing"
)

func TestSynthesize(t *testing.T) {
	ip4 := net.ParseIP("192.0.2.199")
	ip6 := net.ParseIP("2001:db8::27")
	ptr4 := SynthesizePTR("4.example.net.", "autoreverse.example.net", ip4)
	ptr6 := SynthesizePTR("6.example.net.", "autoreverse.example.net", ip6)
	exp := "192-0-2-199.autoreverse.example.net"
	got := ptr4.Ptr
	if exp != got {
		t.Error("Synth PTR4 not", exp, got)
	}

	exp = "2001-db8--27.autoreverse.example.net"
	got = ptr6.Ptr
	if exp != got {
		t.Error("Synth PTR6 not", exp, got)
	}
}
