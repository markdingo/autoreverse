package dnsutil

import (
	"testing"
)

func TestInvertToIPv4(t *testing.T) {
	testCases := []struct {
		input, expect string
		truncated     bool
	}{
		{"1.2.3.4", "4.3.2.1", false},
		{"255.255.255.255", "255.255.255.255", false},

		{"1.168.192", "192.168.1.0", true},
		{"168.192", "192.168.0.0", true},
		{"192", "192.0.0.0", true},
		{"", "", false},

		{"255.255.255.255.255", "", false},
		{"255.255.255", "255.255.255.0", true},
		{"001.2.3.4", "", false},
		{"a.b.c.d.e", "", false},
		{"11.120.0.205", "205.0.120.11", false},
		{"11.120.0.300", "", false},
		{"11.120..200", "", false},
	}

	for ix, tc := range testCases {
		ip, truncated, err := InvertPtrToIPv4(tc.input)
		if err != nil {
			if len(tc.expect) == 0 {
				continue
			}
			t.Error(ix, "Unexpected error with", tc.input, err)
			continue
		}
		if truncated != tc.truncated {
			t.Error(ix, "Truncated flag is not", tc.truncated)
		}
		if len(tc.expect) == 0 { // Expect error?
			t.Error(ix, "Expected error, got none with", tc.input, "and", ip.String())
			continue
		}
		if ip.String() != tc.expect {
			t.Error(ix, "Mismatch. Expected:", tc.expect, "got", ip.String())
		}
	}
}

func TestInvertToIPv6(t *testing.T) {
	testCases := []struct {
		input, expect string
		truncated     bool
	}{
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0", "::1", false},
		{"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.8.0.a.0.0.0.3.0.3.0.4.2",
			"2403:300:a08:f000::3", false},
		{"7.d.0.5.2.d.a.c.5.c.b.7.1.8.8.0.0.3.e.f.e.d.5.9.3.6.3.e.d.2.d.f",
			"fd2d:e363:95de:fe30:881:7bc5:cad2:50d7", false},
		// 3. Mixed case hex
		{"7.D.0.5.2.d.a.C.5.c.B.7.1.8.8.0.0.3.e.f.e.d.5.9.3.6.3.e.d.2.d.f",
			"fd2d:e363:95de:fe30:881:7bc5:cad2:50d7", false},
		// 4. Empty nibble '..'
		{"7.d.0.5.2.d.a.c.5..b.7.1.8.8.0.0.3.e.f.e.d.5.9.3.6.3.e.d.2.d.f", "", false},
		// 5. Invalid hex 'g'
		{"7.d.0.5.2.d.a.c.5.g.b.7.1.8.8.0.0.3.e.f.e.d.5.9.3.6.3.e.d.2.d.f", "", false},
		// 6. Truncated
		{"1.7.d.0.5.2.d.a.c.5.7.1.8.8.0.0.3.e.f.e.d.5.9.3.6.3.e.d.2.d.f",
			"fd2d:e363:95de:fe30:881:75ca:d250:d710", true},
		{"7.d.0.5.2.d.a.c.5.7.1.8.8.0.0.3.e.f.e.d.5.9.3.6.3.e.d.2.d.f",
			"fd2d:e363:95de:fe30:881:75ca:d250:d700", true},
		{"d.0.5.2.d.a.c.5.7.1.8.8.0.0.3.e.f.e.d.5.9.3.6.3.e.d.2.d.f",
			"fd2d:e363:95de:fe30:881:75ca:d250:d000", true},
		{"d.0.5.2.d.a.c.5.7.1.8.8.0.0.3.e.f.e.d.5.9.3.6.3.e.d.2.d.f",
			"fd2d:e363:95de:fe30:881:75ca:d250:d000", true},
		{"0.5.2.d.a.c.5.7.1.8.8.0.0.3.e.f.e.d.5.9.3.6.3.e.d.2.d.f",
			"fd2d:e363:95de:fe30:881:75ca:d250:0", true},
		// 11.  Empty nibble
		{".5.2.d.a.c.5.7.1.8.8.0.0.3.e.f.e.d.5.9.3.6.3.e.d.2.d.f", "", false},
		// 12. nibble greater than 1 byte
		{"001.2.3.4", "", false},
		{"11.120.0.205", "", false},
	}

	for ix, tc := range testCases {
		ip, truncated, err := InvertPtrToIPv6(tc.input)
		if err != nil {
			if len(tc.expect) == 0 {
				continue
			}
			t.Error(ix, "Unexpected error with", tc.input, err)
			continue
		}
		if truncated != tc.truncated {
			t.Error(ix, "Truncated flag is not", tc.truncated)
		}
		if len(tc.expect) == 0 { // Expect error?
			t.Error(ix, "Expected error, got none with", tc.input, "and", ip.String())
			continue
		}
		if ip.String() != tc.expect {
			t.Error(ix, "Mismatch. Input:", tc.input, "got", ip.String())
		}
	}
}

func TestConvertDecimalOctet(t *testing.T) {
	testCases := []struct {
		input  string
		expect int
	}{
		{"", -1},
		{"z", -1},
		{".255.", -1},
		{"zabc", -1},
		{"123", 123},
		{"0", 0},
		{"255", 255},
		{"256", -1},
		{"25x", -1},
		{"a25", -1},
		{"2a5", -1},
		{"001", -1},
	}

	for ix, tc := range testCases {
		ret := convertDecimalOctet(tc.input)
		if ret != tc.expect {
			t.Error(ix, "Input:", tc.input, "Expected:", tc.expect, "Got:", ret)
		}
	}
}
