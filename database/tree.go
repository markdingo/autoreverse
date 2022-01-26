package database

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
)

// If RR is a.b.c. IN A 1.2.3.4, then the reference to the RR is:
//
// rrSet := database.cm[IN].children[c].children[b].children[a].tm[A]

type classMap map[uint16]*node
type typeMap map[uint16][]dns.RR

type node struct {
	tm       typeMap  // Both of these maps are created on-demand so that the
	children labelMap // presence of a map implies at least one map entry.
}

type labelMap map[string]*node

// Database is constructed with NewDatabase() - using a default construction will result
// in a panic due to unconstructed maps.
type Database struct {
	cm    classMap
	count int // RRs added
}

// NewDatabase *must* be used to construct a new database
func NewDatabase() *Database {
	return &Database{cm: make(classMap)}
}

// Add the RR into the map. Return true if it was added. Return false it's a duplicate or
// an impossible RR (which should never be the case).
func (t *Database) AddRR(rr dns.RR) bool {
	qClass := rr.Header().Class
	qType := rr.Header().Rrtype
	qName := dnsutil.ChompCanonicalName(rr.Header().Name)
	labels := strings.Split(qName, ".")
	if len(labels) == 0 {
		return false
	}
	parent := t.cm[qClass] // Get or create root node for this class
	if parent == nil {
		parent = &node{}
		t.cm[qClass] = parent
	}

	for ix := len(labels) - 1; ix >= 0; ix-- { // Iterate down the labels
		if parent.children == nil {
			parent.children = make(labelMap)
		}
		child := parent.children[labels[ix]]
		if child == nil {
			child = &node{}
			parent.children[labels[ix]] = child
		}
		parent = child
	}

	// "parent" points to the bottom of the qName tree which is not necessarily the
	// bottom of the database tree.

	tm := parent.tm // Get or create the typeMap for this node
	if tm == nil {
		tm = make(typeMap)
		parent.tm = tm
	}

	rrset, ok := tm[qType]
	if !ok { // No RRs for this type so it's an easy add
		tm[qType] = []dns.RR{dns.Copy(rr)}
		t.count++
		return true
	}

	// Compare existing RRs to avoid duplication

	for _, eRR := range rrset {
		if dnsutil.RRIsEqual(eRR, rr) {
			return false
		}
	}

	// dns.RR is effectively a pointer, so make a copy of the RR when placing it in
	// the database so callers cannot use their rr pointer to modify our database
	// copy. Just a bit of paranoia here.

	tm[qType] = append(rrset, dns.Copy(rr))
	t.count++

	return true
}

// LookupRR returns an array of copies of matching RRs. Copies are important as we know
// caller are likely to modify the results, particularly TTL. nxDomain is true if there is
// no node for the qName. Note a node is only every created when there is something to add
// into it so the presence of a node implies RRs or children.
func (t *Database) LookupRR(qClass, qType uint16, qName string) (ans []dns.RR, nxDomain bool) {
	nxDomain = true
	qName = dnsutil.ChompCanonicalName(qName)
	labels := strings.Split(qName, ".")
	if len(labels) == 0 {
		nxDomain = len(t.cm) > 0 // Should never occur in practice
		return
	}

	parent := t.cm[qClass] // Iterate from the root of the desired class
	if parent == nil {
		return
	}
	for ix := len(labels) - 1; ix >= 0; ix-- {
		if parent.children == nil {
			return
		}
		child := parent.children[labels[ix]]
		if child == nil {
			return
		}
		parent = child
	}

	// "parent" points to the bottom of the qName tree

	nxDomain = false // Because either tm entries or children will always be present

	tm := parent.tm // Look up type map for this node
	if tm == nil {
		return
	}

	rrset, ok := tm[qType]
	if !ok {
		return
	}

	for _, rr := range rrset {
		ans = append(ans, dns.Copy(rr))
	}

	return
}

// Count returns the total count of all RRs in the database.
func (t *Database) Count() int {
	return t.count
}

func (t *Database) Dump() {
	fmt.Println("Database Dump", t.count)
	for ct, parent := range t.cm {
		t.dumpChildren(dns.ClassToString[ct]+" ", "", parent)
	}
}

func (t *Database) dumpChildren(prefix, qName string, parent *node) {
	thisPrefix := prefix
	nextPrefix := strings.Repeat(" ", len(thisPrefix))
	for _, rrset := range parent.tm {
		fmt.Print(thisPrefix, " ", dnsutil.PrettyRRSet(rrset, true))
		thisPrefix = nextPrefix
		fmt.Println()
	}
	for label, child := range parent.children {
		t.dumpChildren(prefix+" ", label+"."+qName, child)
	}
}
