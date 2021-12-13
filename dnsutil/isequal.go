package dnsutil

import (
	"strings"

	"github.com/miekg/dns"
)

// RRIsEqual returns true if the RRs are "effectively" identical. That means they are
// identical excepting for TTL. Miekg does not offer an IsEqual() public function that
// compares the non-header part of an RR so we use the Stringer function and compare them
// as a string. A bit of a hack as we have to remove the header part of the string to
// eliminate the TTL, but it works, albeit slowly.
func RRIsEqual(a, b dns.RR) bool {
	ah := a.Header()
	bh := b.Header()

	// Do the easy stuff first
	if ah.Class != bh.Class ||
		ah.Rrtype != bh.Rrtype ||
		dns.CanonicalName(ah.Name) != dns.CanonicalName(bh.Name) {
		return false
	}

	// Looking equal so far, how about the payload part?

	ahl := len(ah.String())
	bhl := len(bh.String())
	as := a.String()[ahl:]
	bs := b.String()[bhl:]

	return strings.ToLower(as) == strings.ToLower(bs)
}
