package main

import (
	"sort"
	"strings"

	"github.com/markdingo/autoreverse/delegation"
	"github.com/markdingo/autoreverse/dnsutil"
)

// authorities contains the Zones Of Authority which are primarily used to determine
// whether queries are in-bailiwick or not. Once populated, sort() should be called to
// ensure findInBailiwick() functions properly.
type authorities struct {
	slice []*delegation.Authority
}

// Only append if unique. Return true if appended.
func (t *authorities) append(add *delegation.Authority) bool {
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
// that findInBailiwick() returns the most specific zone.
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

// findInBailiwick returns the matching delegation.Authority for the qName or nil.
//
// The search is serial as it's a suffix match rather than an exact match. Possibly could
// have some fancy suffix tree to mimic the DNS hierarchy, but in most cases the number of
// authorities is likely to be now more than 2 or 3, so a serial search probably beats a
// fancy tree search any way.
//
// Authorities are assumed to have already been sorted by sortAuthorities which ensures
// this function will return the longest prefix/most-specific match.
func (t *authorities) findInBailiwick(qName string) *delegation.Authority {
	for _, auth := range t.slice {
		if dnsutil.InBailiwick(qName, auth.Domain) {
			return auth
		}
	}

	return nil
}
