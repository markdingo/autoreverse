package dnsutil

import (
	"testing"
)

func TestInBailiwick(t *testing.T) {
	testCases := []struct {
		sub, parent string
		expect      bool
	}{
		{"a.example.net", "example.net", true},
		{"example.net", "example.net", true},
		{"example.net", ".example.net", true},
		{"a.example.net", ".example.net.", true},
		{"a.example.org", ".example.net.", false},
		{"short.example.org", "notshort.example.org.", false},
		{"short.example.org", "ort.example.org.", false},
		{"root", ".", true},
	}

	for ix, tc := range testCases {
		if InBailiwick(tc.sub, tc.parent) != tc.expect {
			t.Error(ix, "Wrong", tc.sub, tc.parent, tc.expect)
		}
	}
}
