package dnsutil

import (
	"github.com/miekg/dns"
)

// Make name canonical but lose trailing dot. For logging and mock processing where zones
// names are often converted to file names, the trailing dot is more of a hinderance than
// a help.
func ChompCanonicalName(n string) string {
	n = dns.CanonicalName(n)
	if len(n) > 0 && n[len(n)-1] == '.' {
		n = n[:len(n)-1]
	}

	return n
}
