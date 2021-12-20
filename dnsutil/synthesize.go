package dnsutil

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

const (
	obeyRFC = true
)

// SynthesizePTR converts an IP address into a synthetic PTR. Mainly it just string
// substitutes ":" and "." in ip addresses to "-" which is an acceptable <domain-name>
// character.
//
// According to rfc1035 Ptr has to hold a <domain-name> which is constrainted to
// "let-dig-hyp", but I'll bet if the Ptr data contained "." and ":" (which would allow an
// *exact* representation of the query address) that almost nothing would care. If you
// want to toy with that idea, set obeyRFC to false.
//
// The suffix parameter is assumeded to be canonical.
func SynthesizePTR(qname, suffix string, ip net.IP) *dns.PTR {
	ptr := new(dns.PTR)
	ptr.Hdr.Name = qname
	ptr.Hdr.Class = dns.ClassINET
	ptr.Hdr.Rrtype = dns.TypePTR
	// ptr.Hdr.Ttl = 60 // Set by caller

	s := ip.String()
	if obeyRFC {
		s = strings.ReplaceAll(s, ":", "-")
		s = strings.ReplaceAll(s, ".", "-")
	}

	if len(suffix) > 0 { // The normal use-case
		s += "." + suffix
	}

	ptr.Ptr = s

	return ptr
}
