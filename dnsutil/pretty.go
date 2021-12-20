package dnsutil

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// All Pretty* functions returns a compact "pretty" version of various dns structures. The
// standard String() is more designed to be consistent with traditional dig-type output,
// which IMO is too verbose and pretty ugly. Maybe "Compact" would have been better than
// "Pretty"?

// PrettyMsg1 returns a compact string representing the complete message.
func PrettyMsg1(m *dns.Msg) string {
	h := m.MsgHdr
	flags := []string{}
	if h.Response {
		flags = append(flags, "qr")
	}
	if h.Authoritative {
		flags = append(flags, "aa")
	}
	if h.Truncated {
		flags = append(flags, "tc")
	}

	qTypes := make([]string, 0)
	aTypes := make([]string, 0)
	nTypes := make([]string, 0)
	eTypes := make([]string, 0)
	for _, q := range m.Question {
		qTypes = append(qTypes, TypeToString(q.Qtype))
	}
	for _, rr := range m.Answer {
		aTypes = append(aTypes, TypeToString(rr.Header().Rrtype))
	}
	for _, rr := range m.Ns {
		nTypes = append(nTypes, TypeToString(rr.Header().Rrtype))
	}
	for _, rr := range m.Extra {
		eTypes = append(eTypes, TypeToString(rr.Header().Rrtype))
	}
	return fmt.Sprintf("%d f=%s %s Q=%d-%s Ans=%d-%s Ns=%d-%s Extra=%d-%s",
		h.Id, strings.Join(flags, "+"), RcodeToString(h.Rcode),
		len(m.Question), strings.Join(qTypes, ","),
		len(m.Answer), strings.Join(aTypes, ","),
		len(m.Ns), strings.Join(nTypes, ","),
		len(m.Extra), strings.Join(eTypes, ","))
}

// PrettyQuestion returns a compact representation of the dns.Question
func PrettyQuestion(q dns.Question) string {
	return fmt.Sprintf("%s/%s %s",
		ClassToString(dns.Class(q.Qclass)),
		TypeToString(q.Qtype),
		q.Name)
}

// PrettyNS returns a compact representation of a single NS RR
func PrettyNS(rr *dns.NS, includeName bool) (s string) {
	if includeName {
		s = rr.Hdr.Name + " "
	}
	s += fmt.Sprintf("%s/%s %d %s",
		ClassToString(dns.Class(rr.Hdr.Class)),
		TypeToString(rr.Hdr.Rrtype),
		rr.Hdr.Ttl, rr.Ns)
	return
}

// PrettyShortNSSet returns just the name server names (RHS) separated by ", "
func PrettyShortNSSet(rrs []dns.RR) string {
	ar := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		if rrt, ok := rr.(*dns.NS); ok {
			ar = append(ar, rrt.Ns)
		}
	}

	return strings.Join(ar, ", ")
}

// PrettySOA returns a compact representation of a single SOA RR
func PrettySOA(rr *dns.SOA, includeName bool) (s string) {
	if includeName {
		s = rr.Hdr.Name + " "
	}
	s += fmt.Sprintf("%s/%s %d %s %s %d %d %d %d %d",
		ClassToString(dns.Class(rr.Hdr.Class)),
		TypeToString(rr.Hdr.Rrtype), rr.Hdr.Ttl, rr.Ns,
		rr.Mbox, rr.Serial, rr.Refresh, rr.Retry, rr.Expire,
		rr.Minttl)
	return
}

// PrettyAAAA returns a compact representation of a single AAAA RR
func PrettyAAAA(rr *dns.AAAA, includeName bool) (s string) {
	if includeName {
		s = rr.Hdr.Name + " "
	}
	s += fmt.Sprintf("%s/%s %d %s",
		ClassToString(dns.Class(rr.Hdr.Class)),
		TypeToString(rr.Hdr.Rrtype),
		rr.Hdr.Ttl, rr.AAAA.String())
	return
}

// PrettyA returns a compact representation of a single A RR
func PrettyA(rr *dns.A, includeName bool) (s string) {
	if includeName {
		s = rr.Hdr.Name + " "
	}
	s += fmt.Sprintf("%s/%s %d %s",
		ClassToString(dns.Class(rr.Hdr.Class)),
		TypeToString(rr.Hdr.Rrtype),
		rr.Hdr.Ttl, rr.A.String())
	return
}

// PrettyPTR returns a compact representation of a single PTR RR
func PrettyPTR(rr *dns.PTR, includeName bool) (s string) {
	if includeName {
		s = rr.Hdr.Name + " "
	}
	s += fmt.Sprintf("%s/%s %d %s",
		ClassToString(dns.Class(rr.Hdr.Class)),
		TypeToString(rr.Hdr.Rrtype),
		rr.Hdr.Ttl, rr.Ptr)
	return
}

// PrettyRRSet returns a compact representation of the slice of RRs. Each RR is separated
// a comma.
func PrettyRRSet(rrs []dns.RR, includeName bool) (s string) {
	ar := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		ar = append(ar, PrettyRR(rr, includeName))
	}

	return strings.Join(ar, ", ")
}

// PrettyRR returns a compact representation of the single RR. Known RR-types use the
// other pretty functions while unknown RRs use the general rendering offered by miekg.
func PrettyRR(rr dns.RR, includeName bool) string {
	switch rrt := rr.(type) {
	case *dns.NS:
		return PrettyNS(rrt, includeName)
	case *dns.A:
		return PrettyA(rrt, includeName)
	case *dns.AAAA:
		return PrettyAAAA(rrt, includeName)
	case *dns.PTR:
		return PrettyPTR(rrt, includeName)
	case *dns.SOA:
		return PrettySOA(rrt, includeName)
	}

	return rr.String()
}

// PrettyAddr returns a compact representation of the single address RR. It can be either
// an A or an AAAA RR.
func PrettyAddr(rr dns.RR, includeName bool) (s string) {
	if includeName {
		s = ChompCanonicalName(rr.Header().Name) + "/"
	}
	switch rrt := rr.(type) {
	case *dns.A:
		s += rrt.A.String()
	case *dns.AAAA:
		s += rrt.AAAA.String()
	default:
		s += "?PrettyAddr?"
	}

	return
}
