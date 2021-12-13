package dnsutil

import (
	"testing"

	"github.com/miekg/dns"
)

func TestIsEqual(t *testing.T) {
	testCases := []struct{ rr1, rr2, reason string }{
		{"a.example.Net. 91 IN A 192.0.2.123",
			"a.example.Net. 91 IN A 192.0.2.123",
			""},

		{"a.example.Net. 9991 IN A 192.0.2.123",
			"a.example.Net. 91 IN A 192.0.2.123",
			""},

		{"b.example.Net. 9991 IN A 192.0.2.123",
			"a.example.Net. 91 IN A 192.0.2.123",
			"qName"},

		{"a.example.Net. 9991 IN A 192.0.2.123",
			"a.example.Net. 91 IN A 192.0.2.124",
			"trailing byte"},

		{"a.example.Net. 9991 IN AAAA ::1",
			"a.example.Net. 91 IN A 192.0.2.124",
			"Type"},
		{"a.example.Net. 9991 IN AAAA ::1",
			"a.example.Net. 91 IN AAAA ::1",
			""},
		{"a.example.Net. 9991 IN AAAA 2001:db8::1",
			"a.example.Net. 91 IN AAAA 2001:db8::2",
			"trailing byte"},
		{"a.example.Net. 9991 IN AAAA 2001:db8::1",
			"a.example.Net. 91 IN AAAA 1001:db8::1",
			"leading byte"},

		{"a.example.Org. 9991 IN PTR This.Is.A.ptr",
			"a.example.Org. 9991 IN PTR This.is.a.PTR",
			""},
		{"a.example.Org. 9991 IN PTR This.Is.A.Ptr",
			"A.EXAMPLE.Org. 9991 IN PTR This.Is.b.Ptr",
			"Ptr text"},
	}

	for ix, tc := range testCases {
		rr1, err := dns.NewRR(tc.rr1)
		if err != nil {
			t.Fatal(ix, "Setup failed", err)
		}
		rr2, err := dns.NewRR(tc.rr2)
		if err != nil {
			t.Fatal(ix, "Setup failed", err)
		}

		if RRIsEqual(rr1, rr2) {
			if len(tc.reason) > 0 {
				t.Error(ix, "Expected difference", tc.reason, rr1, rr2)
			}
		} else {
			if len(tc.reason) == 0 {
				t.Error(ix, "Expected Equal", rr1, rr2)
			}
		}
	}
}
