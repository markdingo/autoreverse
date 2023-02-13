package main

import (
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/delegation"
	"github.com/markdingo/autoreverse/dnsutil"
)

type authority struct {
	delegation.Authority
	forward bool // Whether a forward or reverse authority
	cidr    *net.IPNet
}

func newAuthority(da *delegation.Authority, forward bool) *authority {
	auth := &authority{}
	auth.Authority = *da
	auth.forward = forward

	return auth
}

var soaTime = time.Now() // Set here so tests can over-ride

func (t *authority) synthesizeSOA(mboxDomain string, TTLAsSecs uint32) {
	t.SOA.Hdr.Name = t.Domain
	t.SOA.Hdr.Class = dns.ClassINET
	t.SOA.Hdr.Rrtype = dns.TypeSOA
	t.SOA.Hdr.Ttl = TTLAsSecs
	if len(t.NS) > 0 { // Zero is possible for locals
		t.SOA.Ns = t.NS[0].(*dns.NS).Ns
	} else {
		t.SOA.Ns = t.Domain
	}

	t.SOA.Mbox = "hostmaster." + mboxDomain // Why not?
	t.SOA.Serial = uint32(soaTime.Unix())

	t.SOA.Refresh = 110040 // None of these timers really have much meaning
	t.SOA.Retry = 110080   // but we have to populate them with something so give them
	t.SOA.Expire = 28      // signature values which make "von Fastrand" proud.
	t.SOA.Minttl = 9030    // Hit me up if you recognize all of these numbers.
}

// authorities contains the Zones Of Authority which are primarily used to determine
// whether queries are in-domain or not. Once populated, sort() should be called to ensure
// findInDomain() functions properly.
type authorities struct {
	slice []*authority
}

// Only append if unique. Return true if appended.
func (t *authorities) append(add *authority) bool {
	if !add.forward && add.cidr == nil {
		panic("Attempt to add reverse authority with no CIDR")
	}
	for _, auth := range t.slice {
		if add.Domain == auth.Domain {
			return false
		}
	}
	t.slice = append(t.slice, add)

	return true
}

func (t *authorities) len() int {
	return len(t.slice)
}

// sort arranges the slice of authorities to be in most-specific-first order to ensure
// that findInDomain() returns the most specific zone.
//
// Label count is the primary sort key, with less labels coming earler. If the label
// counts are equal there can't possibly be an overlap so it doesn't matter which order
// they come in, but this function uses the alphabetical FQDN as the secondary sort key
// which produces stable results and a visually convenient order for external viewers.
func (t *authorities) sort() {
	sort.Slice(t.slice,
		func(i, j int) bool {
			di := t.slice[i].Domain
			dj := t.slice[j].Domain
			ilc := strings.Count(di, ".")
			jlc := strings.Count(dj, ".")
			if ilc != jlc { // If label counts differ,
				return ilc > jlc // the smaller count wins
			}

			return di > dj
		},
	)
}

// findInDomain returns the matching authority for the qName or nil.
//
// The search is serial as it's a suffix match rather than an exact match. Possibly could
// have some fancy suffix tree to mimic the DNS hierarchy, but in most cases the number of
// authorities is likely to be now more than 2 or 3, so a serial search probably beats a
// fancy tree search any way.
//
// Authorities are assumed to have already been sorted by sortAuthorities which ensures
// this function will return the longest prefix/most-specific match.
func (t *authorities) findInDomain(qName string) *authority {
	for _, auth := range t.slice {
		if dnsutil.InDomain(qName, auth.Domain) {
			return auth
		}
	}

	return nil
}

// findIPInDomain finds the matching reverse authority which contains the
// IP. Return nil if not found.
func (t *authorities) findIPInDomain(ip net.IP) *authority {
	for _, auth := range t.slice {
		if !auth.forward && auth.cidr.Contains(ip) {
			return auth
		}
	}

	return nil
}
