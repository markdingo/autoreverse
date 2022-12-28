package dnsutil

import (
	"strings"

	"github.com/miekg/dns"
)

// InDomain returns true if the purported sub-domain is in-domain of the parent
// domain. This function assumes two relatively well-formed domain names but makes sure
// they are both Canonical before comparisons are made. In the interest of being "helpful"
// the parent domain may or may not have a leading "." as that is common for a lot of
// domain storage in this program.
func InDomain(sub, parent string) bool {
	if len(parent) == 0 || parent == "." { // Root?
		return true
	}

	parent = dns.CanonicalName(parent)
	if parent[0] == '.' {
		parent = parent[1:]
	}
	sub = dns.CanonicalName(sub)
	if len(sub) < len(parent) {
		return false
	}
	if sub == parent {
		return true
	}

	return strings.HasSuffix(sub, "."+parent)
}
