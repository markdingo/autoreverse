package database

// Compatibility functions to mimic the old PTR database autoreverse expects

import (
	"net"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
)

// Convert the supplied rr (A, AAAA or PTR) into a PTR and add it into the database.
func (t *Database) Add(rr dns.RR) bool {
	ptr, _ := dnsutil.DeducePtr(rr)
	if ptr == nil { // Must not be a legit RR
		return false
	}
	return t.AddRR(ptr)
}

// Lookup looks up the supplied ip address and returns all unique PTRs associated with it.
func (t *Database) Lookup(ipStr string) (ar []dns.RR) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}
	qName := dnsutil.IPToReverseQName(ip)
	if len(qName) == 0 {
		return
	}

	ar, _ = t.LookupRR(dns.ClassINET, dns.TypePTR, qName)

	return
}
