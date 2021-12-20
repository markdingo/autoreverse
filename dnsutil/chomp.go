package dnsutil

import (
	"github.com/miekg/dns"
)

// ChompCanonicalName makes a name canonical but loses the trailing dot. For logging and
// mock processing, where zones names are often converted to file names, the trailing dot
// is more of a hindrance than a help, so this helps.
func ChompCanonicalName(n string) string {
	n = dns.CanonicalName(n)
	if len(n) > 0 && n[len(n)-1] == '.' {
		n = n[:len(n)-1]
	}

	return n
}
