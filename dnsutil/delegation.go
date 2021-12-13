package dnsutil

import (
	"github.com/miekg/dns"
)

// ValidDelegation returns true if the message contains a standard-conforming delegation
// response.
//
// Strictly, a valid delegation is one which is !Authoritative, has zero Answer RRs, has
//at least one Ns RR and optional contains glue in Extra.
func ValidDelegation(response *dns.Msg) bool {
	if response.MsgHdr.Rcode != dns.RcodeSuccess {
		return false
	}

	if len(response.Answer) > 0 {
		return false
	}

	if len(response.Ns) == 0 {
		return false
	}

	for _, rr := range response.Ns {
		if rr.Header().Rrtype != dns.TypeNS || rr.Header().Class != dns.ClassINET {
			return false
		}
		if _, ok := rr.(*dns.NS); !ok { // Belts and braces
			return false
		}
	}

	return true
}
