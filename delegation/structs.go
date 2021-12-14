package delegation

// All exported structs are defined here.

import (
	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/resolver"
)

// Finder is the container used to manage FindAndProbe requests. As you can see, it merely
// contains a resolver which may or may not offer some efficiencies to the find process.
type Finder struct {
	resolver resolver.Resolver
}

// Results are return by Finder.Find()
type Results struct {
	ProbeSuccess bool   // If probe responded as desired
	Respondent   dns.RR // Name server which answered the probe
	Parent       *Authority
	Target       *Authority
}
