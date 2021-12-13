package dnsutil

import (
	"fmt"
	"testing"
)

func TestShorten(t *testing.T) {
	testCases := []struct{ in, out string }{
		{"", ""},
		{"This should remain unchanged", ""},
		{"An embedded i/o timeout is a", "Timeout"},
		{"An embedded connection refused is a", "Connection refused"},
	}

	e := ShortenLookupError(nil)
	if e != nil {
		t.Error("shorten created an error out of thin air!", e)
	}

	for ix, tc := range testCases {
		e = fmt.Errorf(tc.in)
		e = ShortenLookupError(e)
		exp := tc.out
		if len(exp) == 0 {
			exp = tc.in
		}
		got := e.Error()
		if exp != got {
			t.Error(ix, "Expected", exp, "Got", got)
		}
	}
}
