package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Check everything that could likely be a typo or usage error. Mostly check in order
// presented by the flag package.
func (t *autoReverse) ValidateCommandLineOptions() error {
	for _, url := range t.cfg.PTRDeduceURLs { // Transfer -PTR-zones to config
		pz, err := newPTRZoneFromURL(t.resolver, url)
		if err != nil {
			return fmt.Errorf("--PTR-deduce url.Parse failed:%w", err)
		}
		t.cfg.PTRZones = append(t.cfg.PTRZones, pz)
	}

	if t.cfg.TTL < time.Second {
		return fmt.Errorf("--TTL must be at least 1 second")
	}
	t.cfg.TTLAsSecs = uint32(t.cfg.TTL.Seconds() + 0.5) // Round up to next second

	if len(t.cfg.delegatedForward) == 0 && len(t.cfg.localForward) == 0 {
		return fmt.Errorf("Must supply one of --forward or --local-forward")
	}

	if len(t.cfg.delegatedForward) > 0 {
		labs, is := dns.IsDomainName(t.cfg.delegatedForward)
		if !is || labs < 2 {
			return fmt.Errorf("Invalid domain name: --forward %s",
				t.cfg.delegatedForward)
		}
		t.cfg.delegatedForward = dns.CanonicalName(t.cfg.delegatedForward)
	}
	if len(t.cfg.localForward) > 0 {
		labs, is := dns.IsDomainName(t.cfg.localForward)
		if !is || labs < 2 {
			return fmt.Errorf("Invalid domain name: --local-forward %s",
				t.cfg.localForward)
		}
		t.cfg.localForward = dns.CanonicalName(t.cfg.localForward)
	}
	if len(t.cfg.delegatedForward) > 0 {
		if len(t.cfg.localForward) > 0 {
			return fmt.Errorf("Cannot have both --forward and --local-forward")
		}
		t.forward = dns.CanonicalName(t.cfg.delegatedForward)
	} else {
		t.forward = dns.CanonicalName(t.cfg.localForward)
	}

	if len(t.cfg.listen) == 0 {
		t.cfg.listen = append(t.cfg.listen, defaultListen)
	} else {
		for ix, addr := range t.cfg.listen {
			t.cfg.listen[ix] = normalizeHostPort(addr, defaultService)
		}
	}

	var err error
	t.localReverses, err = convertReverseCIDRs("--local-reverse", t.cfg.localReverse)
	if err != nil {
		return err
	}

	// This test is not very sound as IsGlobalUnicast() considers ULAs to be
	// global. As it happens a new net package is in the works for 1.18-ish which will
	// hopefully support address categorization much better than is done today. Given
	// that this is only a warning it doesn't warrant writing our own
	// IsItASafeLocalCIDR() function.
	for _, ipNet := range t.localReverses {
		if ipNet.IP.IsGlobalUnicast() {
			warning(nil, "--local-reverse", ipNet.String(),
				"may be a Global Unicast CIDR")
		}
	}

	t.delegatedReverses, err = convertReverseCIDRs("--reverse", t.cfg.delegatedReverse)
	if err != nil {
		return err
	}
	for _, ipNet := range t.delegatedReverses {
		if !ipNet.IP.IsGlobalUnicast() {
			warning(nil, "--reverse", ipNet.String(), "is not a Global Unicast CIDR")
		}
	}

	if len(t.localReverses) == 0 && len(t.delegatedReverses) == 0 {
		return fmt.Errorf("Must supply one of --reverse or --local-reverse")
	}

	if t.cfg.maxAnswers < 0 {
		return fmt.Errorf("--max-answers %d must not be less than zero", t.cfg.maxAnswers)
	}

	if len(t.cfg.passthru) > 0 {
		t.cfg.passthru = normalizeHostPort(t.cfg.passthru, defaultService)
		h, _, err := net.SplitHostPort(t.cfg.passthru)
		if err != nil {
			return fmt.Errorf("--passthru host %s invalid syntax:%w",
				t.cfg.passthru, err)
		}

		addrs, err := t.resolver.LookupIPAddr(context.Background(), h)
		if err != nil {
			return fmt.Errorf("--passthru host %s Lookup error:%w",
				t.cfg.passthru, err)
		}
		if len(addrs) == 0 {
			return fmt.Errorf("--passthru host %s has no IP address(es)",
				t.cfg.passthru)
		}
		t.cfg.passthru = normalizeHostPort(t.cfg.passthru, defaultService)
	}

	if t.cfg.reportInterval < time.Second {
		return fmt.Errorf("--report must be at least 1 second")
	}

	t.cfg.nsidAsHex = hex.EncodeToString([]byte(t.cfg.nsid)) // Convert nsid to hex
	t.cfg.generateNSIDOpt()

	return nil
}

// Given a list of --local-reverse or --reverse CIDR strings, convert them into real CIDRs
// and confirm they are valid in our context which is largely a prefix modulo limit as
// imposed on the way they are expressed in the reverse DNS.
func convertReverseCIDRs(option string, cidrs []string) (ipNets []*net.IPNet, err error) {
	for _, cidr := range cidrs {
		var ipNet *net.IPNet
		_, ipNet, err = net.ParseCIDR(cidr)
		if err != nil {
			err = fmt.Errorf("%s %s:%w", option, cidr, err)
			return
		}
		ones, bits := ipNet.Mask.Size()
		if bits == 32 { // ipv4 - only three possible choices
			if ones != 24 && ones != 16 && ones != 8 {
				err = fmt.Errorf("%s %s prefix length %d must 24, 16 or 8",
					option, cidr, ones)
				return
			}
		}

		if bits == 128 { // ipv6 - be absurdly generous in possible ranges
			if ones%4 != 0 || ones > 124 || ones < 16 {
				err = fmt.Errorf("%s %s prefix length %d must be a multiple of 4 and in range 16-124",
					option, cidr, ones)
				return
			}
		}
		ipNets = append(ipNets, ipNet)
	}

	return
}

// Be helpful with host:port and host:service strings. If the original string only
// contains a naked IP address, append the domain service to create a fully formed
// Host:Port. Otherwise split it up to see if it's already in host:port, if not append the
// domain service and hope for the best. This function is useful for prepping Listen() and
// Dial() host:port strings.
func normalizeHostPort(addr, service string) string {
	ip := net.ParseIP(addr)
	if ip != nil { // naked IP?
		return net.JoinHostPort(addr, service)
	}
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.JoinHostPort(addr, service)
	}

	return addr
}
