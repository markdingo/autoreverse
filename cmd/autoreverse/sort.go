package main

import (
	"sort"
	"strings"

	"github.com/markdingo/autoreverse/delegation"
)

// sortAuthorities arranges the slice of authorities to be in most-labels-first order as
// the dns query handler searches from first to last for a matching suffix. Thus this sort
// ensure the most specific authority is seen first. If the label count is the same there
// can't possibly be an overlap so it doesn't matter which order they come in, but this
// sort makes it alphabetical just so it produces stable results that hopefully makes some
// sense to external viewers.
func sortAuthorities(slice []*delegation.Authority) []*delegation.Authority {
	sort.Slice(slice,
		func(i, j int) bool {
			ilc := strings.Count(slice[i].Domain, ".")
			jlc := strings.Count(slice[j].Domain, ".")
			if ilc != jlc { // If label counts differ,
				return ilc > jlc // the smaller count wins
			}

			return slice[i].Domain > slice[j].Domain
		},
	)

	return slice
}
