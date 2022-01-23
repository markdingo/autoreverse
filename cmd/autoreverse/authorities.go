package main

import (
	"sort"
	"strings"

	"github.com/markdingo/autoreverse/delegation"
	"github.com/markdingo/autoreverse/dnsutil"
)

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

// sortAuthorities arranges the slice of authorities to be in most-labels-first order as
// the dns query handler searches from first to last for a matching suffix. Thus this sort
// ensure the most specific authority is seen first. If the label count is the same there
// can't possibly be an overlap so it doesn't matter which order they come in, but this
// sort makes it alphabetical just so it produces stable results that hopefully makes some
// sense to external viewers.

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
