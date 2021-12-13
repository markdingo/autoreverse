package dnsutil

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Pretty* returns a compact "pretty" version of various dns structures. The standard
// String() is more designed to be consistent with traditional dig-type output, which IMO
// is too verbose and pretty ugly. Maybe "Compact" would have been better than "Pretty"?

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
		qTypes = append(qTypes, dns.TypeToString[q.Qtype])
	}
	for _, rr := range m.Answer {
		aTypes = append(aTypes, dns.TypeToString[rr.Header().Rrtype])
	}
	for _, rr := range m.Ns {
		nTypes = append(nTypes, dns.TypeToString[rr.Header().Rrtype])
	}
	for _, rr := range m.Extra {
		eTypes = append(eTypes, dns.TypeToString[rr.Header().Rrtype])
	}
	return fmt.Sprintf("%d f=%s %s Q=%d-%s Ans=%d-%s Ns=%d-%s Extra=%d-%s",
		h.Id, strings.Join(flags, "+"), dns.RcodeToString[h.Rcode],
		len(m.Question), strings.Join(qTypes, ","),
		len(m.Answer), strings.Join(aTypes, ","),
		len(m.Ns), strings.Join(nTypes, ","),
		len(m.Extra), strings.Join(eTypes, ","))
}

func PrettyQuestion(q dns.Question) string {
	return fmt.Sprintf("%s/%s %s",
		dns.ClassToString[q.Qclass],
		dns.TypeToString[q.Qtype],
		q.Name)
}

func PrettyNS(rr *dns.NS, includeName bool) (s string) {
	if includeName {
		s = rr.Hdr.Name + " "
	}
	s += fmt.Sprintf("%s/%s %d %s",
		dns.ClassToString[rr.Hdr.Class],
		dns.TypeToString[rr.Hdr.Rrtype],
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

func PrettySOA(rr *dns.SOA, includeName bool) (s string) {
	if includeName {
		s = rr.Hdr.Name + " "
	}
	s += fmt.Sprintf("%s/%s %d %s %s %d %d %d %d %d",
		dns.ClassToString[rr.Hdr.Class],
		dns.TypeToString[rr.Hdr.Rrtype], rr.Hdr.Ttl, rr.Ns,
		rr.Mbox, rr.Serial, rr.Refresh, rr.Retry, rr.Expire,
		rr.Minttl)
	return
}

func PrettyAAAA(rr *dns.AAAA, includeName bool) (s string) {
	if includeName {
		s = rr.Hdr.Name + " "
	}
	s += fmt.Sprintf("%s/%s %d %s",
		dns.ClassToString[rr.Hdr.Class],
		dns.TypeToString[rr.Hdr.Rrtype],
		rr.Hdr.Ttl, rr.AAAA.String())
	return
}

func PrettyA(rr *dns.A, includeName bool) (s string) {
	if includeName {
		s = rr.Hdr.Name + " "
	}
	s += fmt.Sprintf("%s/%s %d %s",
		dns.ClassToString[rr.Hdr.Class],
		dns.TypeToString[rr.Hdr.Rrtype],
		rr.Hdr.Ttl, rr.A.String())
	return
}

func PrettyPTR(rr *dns.PTR, includeName bool) (s string) {
	if includeName {
		s = rr.Hdr.Name + " "
	}
	s += fmt.Sprintf("%s/%s %d %s",
		dns.ClassToString[rr.Hdr.Class],
		dns.TypeToString[rr.Hdr.Rrtype],
		rr.Hdr.Ttl, rr.Ptr)
	return
}

// Separated by spaces here rather than commas because
func PrettyRRSet(rrs []dns.RR, includeName bool) (s string) {
	ar := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		ar = append(ar, PrettyRR(rr, includeName))
	}

	return strings.Join(ar, ", ")
}

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
