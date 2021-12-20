package delegation

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/resolver"
)

// NewFinder constructs a Finder struct
func NewFinder(r resolver.Resolver) *Finder {
	return &Finder{resolver: r}
}

// FindAndProbe attempts to find and verify the parent and target delegation material for
// the name in the probe. There are three steps:
//
// 1) Find parents
// 2) Query parents for target delegation details
// 3) Probe target name servers to self-identify
//
// As per the usual go idiom, if error is returned nothing can be said about the contents
// of Results. An error return is pretty catastrophic as it usually means an underlying
// package has failed unexpectedly. Most "errors" are likely to be lookup or probe
// failures which are indicated in Results rather than via an error return.
//
// If error is nil, Results contains at least the Parent Authority and potentially the
// Target Authority if the parent provided that information.
//
// If ProbeSuccess is true, then both Authorities are present as at least one target name
// server on one ip address responded correctly to the probe.
func (t *Finder) FindAndProbe(pr Probe) (R Results, err error) {
	log.Minor("FindAndProbe:", pr.Target())
	log.Debug("F&P Probe:", dnsutil.PrettyRR(pr.Answer(), true))
	R.Parent, R.Target, err = t.findAuthorities(pr)
	if err != nil {
		log.Minorf("Find:%s:err %s", pr.Target(), err.Error())
		return
	}

	// Give up if target wasn't found. This is not an "error" return as such as the
	// parent Authority is valid and may be of some use to the caller - such as for
	// logging purposes.
	if R.Target == nil {
		log.Minorf("Find:%s:Parent %s:no delegation",
			pr.Target(), R.Parent.Domain)
		return
	}

	// Make sure the target isn't completely lame. That is, lacking any name servers
	// (if that's even possible) or lacking any ip addresses for any name servers. We
	// obviously can't probe if there are no ip addresses to try.
	if R.Target.IsCompletelyLame() {
		log.Minorf("Find:%s:Parent %s:Target is 100%% lame",
			pr.Target(), R.Parent.Domain)
		return
	}

	// We have addresses for the name server(s) of the target domain, send a probe to
	// each in turn until we get one good response. Ignore all other errors as we have
	// no clue how our sibling name servers may respond. Start probing ipv6 addresses,
	// but if they all fail, try any legacy ipv4 addresses.

	log.Minorf("Find:%s:Probing Target Name Servers (AAAA=%d,A=%d)",
		pr.Target(), len(R.Target.AAAA), len(R.Target.A))
	allIPs := R.Target.AAAA
	allIPs = append(allIPs, R.Target.A...)
	for _, rr := range allIPs {
		ans, matches := t.exchangeAndValidate(pr, rr)
		switch {
		case matches:
			R.ProbeSuccess = true
			log.Minor("Find:Good Probe response by ", dnsutil.PrettyAddr(rr, true))
			return
		case ans != nil:
			log.Minorf("Find:Wrong Probe response by %s of %s",
				dnsutil.PrettyAddr(rr, true),
				dnsutil.PrettyRR(ans, true))
		default:
			log.Minor("Find:No Probe response by ", dnsutil.PrettyAddr(rr, true))
		}
	}

	return
}

// findAuthorities collects delegation details for the target domain and, indirectly, most
// of the delegation details for the parent/delegating domain.
//
// That means finding the parent's name servers and directly querying them for the target
// NSes and their addresses - if in-bailiwick of the parents. If the delegating name
// servers are out-of-bailiwick the resolver is used to find their addresses.
//
// The end result of gathering these target delegation details is that the caller can
// synthesize the target zone SOA and probe the target name servers to self-identify.
//
//
// If an error causes complete failure to find any authority, return error with pa and ta
// undefined. Otherwise at least the parent authority is returned.
//
// Parent Authority contains a full set of name server names but may not contain a full
// set of name server addresses as this function resolves these addresses on-the-fly and
// stops as soon as it has all the target domain details it needs.
//
// If the Target Authority is found, it is returned in ta, otherwise nil. Target Authority
// is only ever set if Parent Authority is set and if the target name servers and their
// addresses have been determined.
func (t *Finder) findAuthorities(pr Probe) (pa, ta *Authority, err error) {
	parent, nsSet, err := t.findZoneCut(pr) // Find cut above target
	if err != nil {                         // Error from net.Resolver or no target
		return
	}

	// Populate Parent Authority. The caller can now rely on the Parent Authority for
	// whatever purpose they have in mind, even if the target ends up not returning an
	// Authority. The names returned by LookupNS() are converted into dns.RRs by
	// newNS().

	pa = &Authority{Domain: parent}
	for _, host := range nsSet {
		pa.NS = append(pa.NS, newNS(parent, host))
	}

	// Having found the parent, use its details to populate the target.

	// Iterate over the parent's name server names first resolving their address(es)
	// then querying each address for NS details of the target. Once the target NS
	// names are known, re-query the parent's name servers and ask for the target name
	// server addresses if they are in-bailiwick and if they weren't previously
	// supplied as additionals in the NS response (which would normally be the case).

	log.Minorf("findAuthorities:Resolving Delegation of %s at %s", pr.Target(), parent)
	for _, ns := range nsSet { // Resolve each name server
		addrs, e1 := t.resolver.LookupIPAddr(context.Background(), ns)
		if e1 != nil {
			log.Minorf("Could not resolve parent %s:%s",
				ns, dnsutil.ShortenLookupError(e1).Error())
			continue
		}
		for _, ip := range addrs {
			if ip.To4() != nil {
				pa.A = append(pa.A, newA(ns, ip))
			} else {
				pa.AAAA = append(pa.AAAA, newAAAA(ns, ip))
			}
			q := dns.Question{Name: pr.Target(),
				Qtype: dns.TypeNS, Qclass: dns.ClassINET}
			r, _, e2 := t.resolver.FullExchange(context.Background(),
				resolver.NewExchangeConfig(), q, ip.String(), ns)
			if e2 != nil {
				log.Debugf("Resolver error from parent %s/%s for %s/NS:%s",
					ns, ip.String(), q.Name, e2.Error())
				continue
			}
			if r.MsgHdr.Rcode == dns.RcodeNameError { // NXDomain stops us cold
				log.Minorf("NXDomain from parent %s/%s for %s/NS",
					ns, ip.String(), q.Name)
				return
			}
			if r.MsgHdr.Rcode != dns.RcodeSuccess { // Odd return from parent
				log.Debugf("Odd %s from parent %s/%s for %s/NS",
					dns.RcodeToString[r.MsgHdr.Rcode], ns, ip.String(), q.Name)
				continue
			}
			if !dnsutil.ValidDelegation(r) {
				log.Debugf("Invalid Delegation from parent %s/%s for %s/NS",
					ns, ip.String(), q.Name)
				continue
			}

			// A valid delegation means we found the target name servers and
			// were able to resolve at least one of the name server
			// addresses. We allow that not all name servers may resolve
			// because lameness is not uncommon in the DNS world and domains
			// still function so long as at least one address exists and
			// responds. The Authority.IsCompletelyLame() function determines
			// if none of the name servers have addresses and thus the
			// authority is not of much value.

			// The Target Authority is populated from this delegation material
			// and the subsequent name server lookups. This includes the
			// actual delegation domain as returned by the parent. It is the
			// resonsibility of the caller to check that this is what they
			// expect as it may not be.

			candidateTarget := &Authority{}
			candidateTarget.populateFromDelegation(r)

			// It's possible that a buggy parent responded to the query
			// incorrectly by providing a delegation to another domain it
			// manages. Highly unlikely, but we don't want the wrong domain
			// name to propagate thru autoreverse, so catch it here rather
			// than let the bogus data enter the system.

			if candidateTarget.Domain != pr.Target() {
				log.Majorf("Alert:Wrong delegation %s from parent %s/%s for %s/NS",
					candidateTarget.Domain, ns, ip.String(), q.Name)
				continue
			}

			ta = candidateTarget // Phew! Finally accepted
			ta.resolveMissingNSAddresses(t.resolver)
			return
		}
	}

	return
}

// findZoneCut walks up the DNS from the parents of the target towards the root trying to
// find the zone cut for the target domain. It returns an error if a cut isn't found by the
// top of the search - as dictated by the probe.
//
// The probe has created the start point where it sees fit, but normally that's one label
// up from the target domain.
//
// The reason for walking rather than relying on a single query is that delegation does
// not have to occur at every label so all we know for sure is that the delegation - if it
// exists at all - occurs "somewhere up there". E.g. you could have the zone of
// example.net. with the following delegation:
//
// $ORIGIN example.net.
// nsa IN A 192.0.2.61
// s3.s2.s1 IN NS nsa
//
// Which means there's a cut between net. and example.net. and a cut between
// example.net. and s3.s2.s1.example.net. This means a LookupNS() fails at
// s2.s1.example.net. and s1.example.net. because there are no name servers there.
//
// While such gaps are uncommon in the forward direction, they are routine in the reverse,
// so clearly we have to cope with it one way or the other.
//
// In the interest of being nice to TLD servers, it might be argued that walking towards
// the roots could stop at a label count of two in the forward direction, but there are
// cases where that will miss legitimate non-infrastructure delegations, .e.g.,
// sf.ca.us. is only visible in us. and now with the plethora of TLDs, who knows what is
// possible? The one saving grace is that the search doesn't continue up to the roots -
// they are bombarded with enough bogus queries already without us adding to the list.
//
// Returns parent domain above the cut and parent name servers or error.
func (t *Finder) findZoneCut(pr Probe) (parent string, nsSet []string, err error) {
	level := 0
	for iter := pr.Begin(); iter != pr.End(); iter = pr.Next(iter) {
		parent = pr.Zone(iter)
		log.Minorf("findZoneCut:%d Parent NS Lookup %s", level, parent)
		nsSet, err = t.resolver.LookupNS(context.Background(), parent)
		if err == nil {
			log.Minorf("findZoneCut:%d Parent NS Lookup ok (%d): %s",
				level, len(nsSet), strings.Join(nsSet, ","))
			return
		}
		level++
	}

	err = fmt.Errorf("No Delegation found for %s up to %s", pr.Target(), parent)

	return
}

// Given a single address, exchange the probe question and validate the response. Return
// answer count and matches=true if the response is valid. A return of answers>0 and
// matches=false means that some other name server responded, or possibly the
// query/response was mangled by some muddle-ware.
func (t *Finder) exchangeAndValidate(pr Probe, addr dns.RR) (ans dns.RR, matches bool) {
	ec := resolver.NewExchangeConfig()
	var ip net.IP
	switch rrt := addr.(type) {
	case *dns.A:
		ip = rrt.A
	case *dns.AAAA:
		ip = rrt.AAAA
	default:
		fmt.Println("Danger:Impossible RR given to exchangeAndValidate ", addr)
		return
	}

	r, _, err := t.resolver.FullExchange(context.Background(), ec, pr.Question(),
		ip.String(), addr.Header().Name)
	if err != nil {
		return
	}

	if len(r.Answer) == 0 {
		return
	}

	return r.Answer[0], pr.AnswerMatches(r.Answer[0])
}
