package main

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
)

// Synthesize the --local-forward zone which includes making an SOA.
func (t *autoReverse) generateLocalForward(forward string) {
	auth := &authority{forward: true}
	auth.Source = "--local-forward"
	auth.Domain = dns.CanonicalName(forward)
	auth.synthesizeSOA(auth.Domain, t.cfg.TTLAsSecs)
	logAuth(auth, "Local Forward")
	t.forwardAuthority = auth
	t.addAuthority(auth)
}

// Synthesize zones for --local-reverse zones. This includes making an SOA and copying the
// forward NS details which may or may not be present and may or may not be right...
// generateLocalReverses relies on the forward zone already being set.
func (t *autoReverse) generateLocalReverses() error {
	for _, ipNet := range t.localReverses {
		auth := &authority{cidr: ipNet}
		auth.Source = "--local-reverse"

		// The reverse zone is needed to match the PTR queries. In a slightly
		// hacky way, we generate a full PTR qName - because that function already
		// exists - and trim off the excess tokens based on the prefix length.

		domain := dnsutil.IPToReverseQName(ipNet.IP) // full PTR qName
		ones, bits := ipNet.Mask.Size()
		var remove int
		if bits == 32 { // ipv4
			remove = 4 - ones/8 // Octets to remove
		} else {
			remove = 32 - ones/4 // Nibbles to remove
		}
		tokens := strings.Split(domain, ".")
		if len(tokens) <= remove {
			return fmt.Errorf("Internal error, local %s (%d) < %d tokens",
				domain, len(tokens), remove)
		}
		domain = strings.Join(tokens[remove:], ".")
		auth.Domain = domain

		// Now we have a domain the NS qNames can be mutated
		for _, ns := range t.forwardAuthority.NS {
			rr := dns.Copy(ns) // Take a copy as we modify
			rr.Header().Name = auth.Domain
			auth.NS = append(auth.NS, rr)

		}
		auth.synthesizeSOA(t.forward, t.cfg.TTLAsSecs)
		if !t.addAuthority(auth) {
			return fmt.Errorf("--local-reverse %s is duplicated", auth.Domain)
		}
		logAuth(auth, "Local Reverse")
	}

	return nil
}
