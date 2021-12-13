package dnsutil_test

import (
	"net"
	"testing"

	"github.com/markdingo/autoreverse/dnsutil"
)

func TestIPToReverse(t *testing.T) {
	testCases := []struct{ ipStr, expect string }{
		{"1.2.3.4", "4.3.2.1.in-addr.arpa."},
		{"2001:db8:a:b:c::1", "1.0.0.0.0.0.0.0.0.0.0.0.c.0.0.0.b.0.0.0.a.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."},
		{"x", ""},
		{"", ""}, // Empty string
		{"0.0.0.0", "0.0.0.0.in-addr.arpa."},
		{"::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."},
	}

	for ix, tc := range testCases {
		var ip net.IP
		if len(tc.ipStr) > 0 {
			ip = net.ParseIP(tc.ipStr)
		}
		got := dnsutil.IPToReverseQName(ip)
		if got != tc.expect {
			t.Error(ix, "Input:", tc.ipStr, "Got", got, "Expected", tc.expect)
		}
	}
}

func TestIPToReverseBogus(t *testing.T) {
	ip := net.IP(make([]byte, 0))
	if ip == nil {
		t.Fatal("Setup error")
	}
	got := dnsutil.IPToReverseQName(ip)
	if got != "" {
		t.Error("Expected '' from bogus IP, not", got)
	}
}
