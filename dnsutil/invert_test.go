package dnsutil

import (
	"testing"
)

func TestInvertToIPv4(t *testing.T) {
	testCases := []struct{ input, expect string }{
		{"1.2.3.4", "4.3.2.1"},
		{"255.255.255.255", "255.255.255.255"},
		{"255.255.255", ""},
		{"255.255.255.255.255", ""},
		{"255.255.255", ""},
		{"001.2.3.4", ""},
		{"a.b.c.d.e", ""},
		{"11.120.0.205", "205.0.120.11"},
	}

	for ix, tc := range testCases {
		ip, err := InvertPtrToIPv4(tc.input)
		if err != nil {
			if len(tc.expect) == 0 {
				continue
			}
			t.Error(ix, "Unexpected error with", tc.input, err)
			continue
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

func TestInvertToIPv6(t *testing.T) {
	testCases := []struct{ input, expect string }{
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0", "::1"},
		{"3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.8.0.a.0.0.0.3.0.3.0.4.2",
			"2403:300:a08:f000::3"},
		{"7.d.0.5.2.d.a.c.5.c.b.7.1.8.8.0.0.3.e.f.e.d.5.9.3.6.3.e.d.2.d.f",
			"fd2d:e363:95de:fe30:881:7bc5:cad2:50d7"},
		{"7.D.0.5.2.d.a.c.5.c.b.7.1.8.8.0.0.3.e.f.e.d.5.9.3.6.3.e.d.2.d.f", ""},
		{"7.d.0.5.2.d.a.c.5..b.7.1.8.8.0.0.3.e.f.e.d.5.9.3.6.3.e.d.2.d.f", ""},
		{"7.d.0.5.2.d.a.c.5.g.b.7.1.8.8.0.0.3.e.f.e.d.5.9.3.6.3.e.d.2.d.f", ""},
		{"7.d.0.5.2.d.a.c.5.7.1.8.8.0.0.3.e.f.e.d.5.9.3.6.3.e.d.2.d.f", ""},
		{"001.2.3.4", ""},
		{"a.b.c.d.e", ""},
		{"11.120.0.205", ""},
		{"X.d.0.5.2.d.a.c.5.c.b.7.1.8.8.0.0.3.e.f.e.d.5.9.3.6.3.e.d.2.d.X", ""},
	}

	for ix, tc := range testCases {
		ip, err := InvertPtrToIPv6(tc.input)
		if err != nil {
			if len(tc.expect) == 0 {
				continue
			}
			t.Error(ix, "Unexpected error with", tc.input, err)
			continue
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
