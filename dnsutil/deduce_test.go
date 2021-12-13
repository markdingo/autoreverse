package dnsutil_test

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
)

func TestDeducePtr(t *testing.T) {

	testCases := []struct {
		input     string
		expectPtr string // If len() == 0 then don't expect a ptr back
		expectKey string
	}{
		{"a1. 123 IN A 192.0.2.250", "250.2.0.192.in-addr.arpa.	123\tIN\tPTR\ta1.", "192.0.2.250"},
		{
			"a224. 60 IN AAAA ::1",
			"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.\t60\tIN\tPTR\ta224.",
			"::1",
		},
		{
			"a3. 124 IN AAAA 2001:db8::1",
			"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.\t124\tIN\tPTR\ta3.",
			"2001:db8::1",
		},
		{
			"a4. 125 NS a.ns.a4.", // Should not return a PTR
			"",
			"",
		},

		{
			"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.dodgy 73 IN PTR v100.example.net.",
			"",
			"",
		},
		{
			"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.\t124\tIN\tPTR\ta3.",
			"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.\t124\tIN\tPTR\ta3.",
			"2001:db8::1",
		},
		{
			"11.2.0.192.in-addr.arpa.\t124\tIN\tPTR\ta3.",
			"11.2.0.192.in-addr.arpa.\t124\tIN\tPTR\ta3.",
			"192.0.2.11",
		},
	}

	for ix, tc := range testCases {
		addRR, err := dns.NewRR(tc.input)
		if err != nil {
			t.Fatal(ix, "Setup failed", err)
		}
		ptr, key := dnsutil.DeducePtr(addRR)
		if ptr == nil {
			if len(tc.expectPtr) > 0 {
				t.Error(ix, "PTR not return when expected from", tc.input, addRR)
			}
			continue // Expected
		}

		got := ptr.String()
		if got != tc.expectPtr {
			t.Error(ix, "PTR mismatch: Input", tc.input, "Got", got, "Expected", tc.expectPtr)
		}
		if key != tc.expectKey {
			t.Error(ix, "Key mismatch: Input", tc.input, "Got", key, "Expected", tc.expectKey)
		}
	}
}
