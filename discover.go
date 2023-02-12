package main

import (
	"fmt"
	"net"

	"github.com/markdingo/autoreverse/delegation"
	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/log"
)

// Ask the Delegation Finder to discover the forward and reverse zones by probing.
func (t *autoReverse) discover() error {
	finder := delegation.NewFinder(t.resolver)

	if len(t.cfg.delegatedForward) > 0 { // Only discover delegate forwards, not locals
		err := t.discoverForward(finder, t.cfg.delegatedForward)
		if err != nil {
			return err
		}
	}

	err := t.discoverAllReverses(finder)
	if err != nil {
		return err
	}

	return nil
}

// discoverForward searches the forward DNS for the authoritative parents of our domain.
//
// Start with the forward discovery as it's highly likely that the reverse discovery will
// refer to the forward and be queried from resolvers by the probe process. The end result
// of a successful forward probe is the addition of an Authority to t.authorities which
// will be added into the server mutables as part of the reverse probe.
func (t *autoReverse) discoverForward(finder *delegation.Finder, domain string) error {
	pr := delegation.NewForwardProbe(domain)
	for _, srv := range t.servers {
		srv.setMutables(t.forward, pr, t.authorities)
	}
	q := pr.Question()
	log.Major("Forward: Find ", domain, " with ", dnsutil.PrettyQuestion(q))

	fr, err := finder.FindAndProbe(pr)
	if err != nil {
		return fmt.Errorf("Forward:%w", err)
	}

	log.Minor("Forward: Parent found: ", fr.Parent.Domain,
		" Name Servers: ", dnsutil.PrettyShortNSSet(fr.Parent.NS))

	if fr.Target == nil {
		return fmt.Errorf("Forward:Parent %s has no delegation for %s",
			fr.Parent.Domain, domain)
	}

	log.Minor("Forward: Target found: ", fr.Target.Domain,
		" Name Servers: ", dnsutil.PrettyShortNSSet(fr.Target.NS))

	if !fr.ProbeSuccess {
		return fmt.Errorf("Forward: Probe failed to self-identify %s", fr.Target.Domain)
	}

	auth := newAuthority(fr.Target, true)
	auth.Source = domain
	auth.synthesizeSOA(fr.Parent.Domain, t.cfg.TTLAsSecs)
	logAuth(auth, "Forward")

	t.forwardAuthority = auth
	t.addAuthority(auth)

	return nil
}

// discoverAllReverses searches the reverse DNS for the authoritative parents of all our
// reverse domains.
func (t *autoReverse) discoverAllReverses(finder *delegation.Finder) error {
	// Set the reverse probe in the mutables so the dns server responds and also set
	// the current authorities to *only* the forward zone. We don't want earlier
	// Authorities from reverse discoveries to perturb later discoveries so reverses
	// are never added to mutables while in discovery mode - they are all added by
	// Run() post-discovery.
	var fwdOnly authorities
	if t.forwardAuthority != nil { // This must always be true I think
		fwdOnly.append(t.forwardAuthority)
	}
	for _, srv := range t.servers {
		srv.setMutables(t.forward, nil, fwdOnly)
	}

	for _, ipNet := range t.delegatedReverses {
		err := t.discoverReverse(finder, t.forward, ipNet)
		if err != nil {
			return err
		}
	}

	return nil
}

// Discover one reverse zone by walking then probing.
func (t *autoReverse) discoverReverse(finder *delegation.Finder, forward string, ipNet *net.IPNet) error {
	pr := delegation.NewReverseProbe(forward, ipNet) // Create the Probe
	for _, srv := range t.servers {
		mutables := srv.getMutables() // Replace or set probe in server mutables
		srv.setMutables(mutables.ptrSuffix, pr, mutables.authorities)
	}
	q := pr.Question()
	domain := ipNet.String()
	log.Major("Reverse: Find ", domain, " with ", dnsutil.PrettyQuestion(q))

	fr, err := finder.FindAndProbe(pr)
	if err != nil {
		return fmt.Errorf("Reverse:%w", err)
	}

	log.Minor("Reverse: Parent found: ", fr.Parent.Domain,
		" Name Servers: ", dnsutil.PrettyShortNSSet(fr.Parent.NS))

	if fr.Target == nil {
		return fmt.Errorf("Reverse:Parent %s has no delegation for %s",
			fr.Parent.Domain, domain)
	}

	log.Minor("Reverse: Target found: ", fr.Target.Domain,
		" Name Servers: ", dnsutil.PrettyShortNSSet(fr.Target.NS))

	if !fr.ProbeSuccess {
		return fmt.Errorf("Reverse: Probe failed to self-identify %s", fr.Target.Domain)
	}

	auth := newAuthority(fr.Target, false)
	auth.cidr = ipNet
	auth.Source = ipNet.String()
	auth.synthesizeSOA(forward, t.cfg.TTLAsSecs)

	if !t.addAuthority(auth) {
		return fmt.Errorf("-reverse %s is duplicated", auth.Domain)
	}

	logAuth(auth, "Reverse")

	return nil
}

// Print auth details to log - should be called after SOA synthetic
func logAuth(auth *authority, name string) {
	log.Major(name, " Zone of Authority ", auth.Domain)
	log.Minor(dnsutil.PrettySOA(&auth.SOA, false))
	log.Minor(dnsutil.PrettyRRSet(auth.NS, false))
	if len(auth.A) > 0 {
		log.Minor(dnsutil.PrettyRRSet(auth.A, true))
	}
	if len(auth.AAAA) > 0 {
		log.Minor(dnsutil.PrettyRRSet(auth.AAAA, true))
	}
}
