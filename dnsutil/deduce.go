package dnsutil

import (
	"github.com/miekg/dns"
)

// DeducePtr converts a dns.A/AAAA RR into a dns.PTR and returns the RR if it's already a
// recognizable/convertable PTR. If the wrong type of RR is supplied a nil value is
// returned. The "key" value is effectively the IP address expressed as a string
// regardless of the RR type. It can be used by callers who want to reference the PTR via
// the original or extracted IP address.
func DeducePtr(rr dns.RR) (ptr *dns.PTR, key string) {
	switch rrt := rr.(type) {
	case *dns.A:
		ptr = &dns.PTR{}
		ptr.Hdr.Name = IPToReverseQName(rrt.A)
		ptr.Hdr.Rrtype = dns.TypePTR
		ptr.Hdr.Class = rrt.Hdr.Class
		ptr.Hdr.Ttl = rrt.Hdr.Ttl
		ptr.Ptr = rrt.Hdr.Name
		key = rrt.A.String()

	case *dns.AAAA:
		ptr = &dns.PTR{}
		ptr.Hdr.Name = IPToReverseQName(rrt.AAAA)
		ptr.Hdr.Rrtype = dns.TypePTR
		ptr.Hdr.Class = rrt.Hdr.Class
		ptr.Hdr.Ttl = rrt.Hdr.Ttl
		ptr.Ptr = rrt.Hdr.Name
		key = rrt.AAAA.String()

	case *dns.PTR:
		ip, err := InvertPtrToIP(rrt.Hdr.Name) // See if it's well-formed first
		if err == nil {
			ptr = rrt
			key = ip.String()
		}
	}

	return
}
