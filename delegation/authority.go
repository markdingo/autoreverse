package delegation

import (
	"context"
	"net"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/resolver"
)

// Authority contains the delegated and synthetic SOA details so our auth server can
// respond to SOA DNS requests. An Authority is considered valid if there is at least one
// resolved address for the name servers. If some name servers happen to be "lame", that
// doesn't invalidate the authority - tho of course it reduces their availability and
// effectiveness.
type Authority struct {
	Source string // Printable and possibly unique identifier
	Domain string // AKA Zone of authority - matched by DNS serving
	SOA    dns.SOA
	NS     []dns.RR
	AAAA   []dns.RR
	A      []dns.RR
}

// Transfer the delegation material from the parent name server response into the
// Authority; this includes the domain name extracted from the qName of the NS entry.
// This is important to note as it may well be a different domain from that targeted, if,
// e.g., the parent has given a different answer than what we were expecting. It's the
// responsibility of the caller to make a final check that this domain name suits their
// needs. Having said that, typically the Domain should match in the forward case or is
// reasonable in the reverse case.
//
// Another important note is that the message should be a delegation message which means
// that the NS addresses are in Extra, not Answer.
func (t *Authority) populateFromDelegation(m *dns.Msg) {
	t.NS = m.Ns

	// If we have at least one NS RR, make its qName the authority domain
	if len(t.NS) > 0 {
		if ns, ok := t.NS[0].(*dns.NS); ok {
			t.Domain = ns.Hdr.Name
		}
	}

	// Copy relevant glue
	for _, addr := range m.Extra {
		if AAAA, ok := addr.(*dns.AAAA); ok {
			t.AAAA = append(t.AAAA, AAAA)
		}
		if A, ok := addr.(*dns.A); ok {
			t.A = append(t.A, A)
		}
	}
}

// Find addresses of all name servers which do not already have at least one address in
// the Authority. This is typically non-glue names tho it can also occur for in-domain
// names which happen to be CNAMEs! In any event, rather than try and discriminate between
// names which should have come back as glue, we simply query for all outstanding names
// and let a real resolver work it out for us.
func (t *Authority) resolveMissingNSAddresses(res resolver.Resolver) {
	aMap := make(map[string]struct{}) // Track already-resolved names
	for _, rr := range t.AAAA {
		aMap[rr.Header().Name] = struct{}{}
	}
	for _, rr := range t.A {
		aMap[rr.Header().Name] = struct{}{}
	}

	for _, rr := range t.NS {
		if rrt, ok := rr.(*dns.NS); ok {
			name := rrt.Ns
			if _, ok := aMap[name]; ok { // If already resolved, skip
				continue
			}
			addrs, err := res.LookupIPAddr(context.Background(), name)
			if err != nil {
				log.Minorf("Cannot resolve NS address of %s for %s:%s",
					name, t.Domain, dnsutil.ShortenLookupError(err).Error())
				continue
			}
			for _, ip := range addrs {
				if ip.To4() != nil {
					t.A = append(t.A, newA(name, ip))
				} else {
					t.AAAA = append(t.AAAA, newAAAA(name, ip))
				}
			}
		}
	}
}

// IsCompletelyLame returns true of none of the name servers have any address records. It
// is also considered completely lame if there are no name servers to begin with!
func (t *Authority) IsCompletelyLame() bool {
	if len(t.NS) == 0 {
		return true
	}

	nMap := make(map[string]struct{}) // Linear search is probably ok too
	for _, rr := range t.NS {
		if rrt, ok := rr.(*dns.NS); ok {
			nMap[rrt.Ns] = struct{}{}
		}
	}

	for _, rr := range t.AAAA {
		if _, ok := nMap[rr.Header().Name]; ok {
			return false
		}
	}

	for _, rr := range t.A {
		if _, ok := nMap[rr.Header().Name]; ok {
			return false
		}
	}

	return true
}

// newNS converts LookupNS results into dns.RRs
func newNS(qName, nsName string) *dns.NS {
	rr := new(dns.NS)
	rr.Hdr.Name = qName
	rr.Hdr.Rrtype = dns.TypeNS
	rr.Hdr.Class = dns.ClassINET
	rr.Hdr.Ttl = 59 // Should be populated by caller, but this is a sentinal safety net
	rr.Ns = nsName

	return rr
}

// newAAAA converts LookupIPAddr results into dns.RRs
func newAAAA(qName string, ip net.IP) *dns.AAAA {
	rr := new(dns.AAAA)
	rr.Hdr.Name = qName
	rr.Hdr.Rrtype = dns.TypeAAAA
	rr.Hdr.Class = dns.ClassINET
	rr.Hdr.Ttl = 59 // Should be populated by caller, but this is a sentinal safety net
	rr.AAAA = ip

	return rr
}

// newA converts LookupIPAddr results into dns.RRs
func newA(qName string, ip net.IP) *dns.A {
	rr := new(dns.A)
	rr.Hdr.Name = qName
	rr.Hdr.Rrtype = dns.TypeA
	rr.Hdr.Class = dns.ClassINET
	rr.Hdr.Ttl = 59 // Should be populated by caller, but this is a sentinal safety net
	rr.A = ip

	return rr
}
