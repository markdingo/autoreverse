package database

import (
	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
)

// Database is constructed with NewDatabase() and populated with Add()
type Database struct {
	ptrMap map[string]map[string]dns.RR
}

func NewDatabase() *Database {
	return &Database{
		ptrMap: make(map[string]map[string]dns.RR),
	}
}

// Add adds converts an address (or an existing PTR) RR to a PTR and adds it into the
// database. Returns true if the RR was an address record.
func (t *Database) Add(rr dns.RR) bool {
	ptr, ip := dnsutil.DeducePtr(rr)
	if ptr == nil { // Must not be an legit RR
		return false
	}
	pmap := t.ptrMap[ip]
	if pmap == nil {
		pmap = make(map[string]dns.RR)
		t.ptrMap[ip] = pmap
	}
	pmap[ptr.Ptr] = ptr // This may overwrite a duplicate ip/qName

	return true
}

// Count returns the total count of all PTR RRs in the database.
func (t *Database) Count() int {
	var c int
	for _, ptrMap := range t.ptrMap {
		c += len(ptrMap)
	}

	return c
}

// Lookup looks up the supplied ip address and returns all unique PTRs associated with it.
func (t *Database) Lookup(ipStr string) (ar []dns.RR) {
	pmap := t.ptrMap[ipStr]
	if pmap == nil {
		return
	}
	for _, ptr := range pmap {
		ar = append(ar, ptr)
	}

	return
}
