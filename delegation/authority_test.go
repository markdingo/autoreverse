package delegation

import (
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
	"github.com/markdingo/autoreverse/mock/resolver"
)

func TestAuthorityLame(t *testing.T) {
	a := &Authority{}
	if !a.IsCompletelyLame() {
		t.Error("An empty Authority should be completely lame")
	}
	// Create not in-domain and in-domain name servers
	ns1, _ := dns.NewRR("autoreverse.example.net. IN NS ns1.autoreverse.example.net")
	ns2, _ := dns.NewRR("autoreverse.example.net. IN NS ns2.autoreverse.example.net")
	a.NS = append(a.NS, ns1)
	a.NS = append(a.NS, ns2)
	if !a.IsCompletelyLame() {
		t.Error("No addresses should still be lame")
	}
	// ns3 is not a name server
	a1, _ := dns.NewRR("ns3.autoreverse.example.net IN A 192.0.2.1")
	a.A = append(a.A, a1)
	if !a.IsCompletelyLame() {
		t.Error("No Address matches NS yet, should be lame still")
	}

	a1, _ = dns.NewRR("ns1.autoreverse.example.net IN A 192.0.2.253") // Match ns1
	a.A = append(a.A, a1)
	if a.IsCompletelyLame() {
		t.Error("A RR should mean no longer lame")
	}

	a.A = []dns.RR{}                                                        // Reset
	a2, _ := dns.NewRR("ns2.autoreverse.example.net IN AAAA 2001:db8:7::1") // Match ns2
	a.AAAA = append(a.AAAA, a2)
	if a.IsCompletelyLame() {
		t.Error("AAAA RR should mean no longer lame")
	}
}

func TestAuthorityPopulate(t *testing.T) {
	m := new(dns.Msg)
	a := &Authority{}
	a.populateFromDelegation(m) // Empty message should be a no-op

	if len(a.Source) > 0 || len(a.Domain) > 0 || len(a.SOA.Header().Name) > 0 ||
		len(a.NS) > 0 || len(a.A) > 0 || len(a.AAAA) > 0 {
		t.Error("Authority changed with a noop msg", a, a.SOA.String())
	}

	ns1, _ := dns.NewRR("autoreverse.example.net. IN NS ns1.autoreverse.example.net")
	ns2, _ := dns.NewRR("autoreverse.example.net. IN NS ns2.autoreverse.example.net")
	a1, _ := dns.NewRR("ns1.autoreverse.example.net IN A 192.0.2.1")
	a2, _ := dns.NewRR("ns2.autoreverse.example.net IN AAAA 2001:db8:7::1")
	a3, _ := dns.NewRR("ns3.autoreverse.example.net IN A 192.0.2.1")
	m.Ns = append(m.Ns, ns1)
	m.Ns = append(m.Ns, ns2)
	m.Extra = append(m.Extra, a2)
	m.Extra = append(m.Extra, a1)
	m.Extra = append(m.Extra, a3)

	a.populateFromDelegation(m)
	if len(a.Domain) == 0 {
		t.Error("populateFrom didn't set Domain", a)
	}

	if a.IsCompletelyLame() {
		t.Error("populateFrom didn't make the Authority non-lame", a)
	}
}

func TestNewRRs(t *testing.T) {
	m := new(dns.Msg)
	a := &Authority{Source: "TestNewRRs"}

	ns1 := newNS("autoreverse.example.net.", "ns1.autoreverse.example.net.")
	ns2 := newNS("autoreverse.example.net.", "ns2.autoreverse.example.net.")
	a1 := newA("ns1.autoreverse.example.net.", net.ParseIP("192.0.2.1"))
	a2 := newAAAA("ns2.autoreverse.example.net.", net.ParseIP("2001:db8:7::1"))
	a3 := newA("ns3.autoreverse.example.net.", net.ParseIP("192.0.2.2"))
	m.Ns = append(m.Ns, ns1)
	m.Ns = append(m.Ns, ns2)
	m.Extra = append(m.Extra, a1)
	m.Extra = append(m.Extra, a2)
	m.Extra = append(m.Extra, a3)

	a.populateFromDelegation(m)
	if len(a.Domain) == 0 {
		t.Error("populateFrom didn't set Domain", a)
	}

	if a.IsCompletelyLame() {
		t.Error("populateFrom with New* RRs, didn't make the Authority non-lame", a)
	}
}

func TestResolveMissing(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MinorLevel)
	res := resolver.NewResolver("./testdata/authority")
	a := &Authority{Source: "TestResolveMissing", Domain: "autoreverse.example.net"}

	ns1 := newNS("autoreverse.example.net.", "ns1.autoreverse.example.net.")
	ns2 := newNS("autoreverse.example.net.", "ns2.autoreverse.example.net.")
	ns3 := newNS("autoreverse.example.net.", "ns3.example.org.")

	a.NS = append(a.NS, ns1)
	a.NS = append(a.NS, ns2)
	a.NS = append(a.NS, ns3)
	a.resolveMissingNSAddresses(res)
	if a.IsCompletelyLame() {
		got := out.String()
		t.Error("Name servers were not resolved", a, got)
	}

	if len(a.AAAA) != 1 || len(a.A) != 2 {
		t.Error("Not lame, but not right address count", len(a.AAAA), len(a.A))
	}

	// Second time should be a no-op

	a.resolveMissingNSAddresses(res)
	if a.IsCompletelyLame() {
		got := out.String()
		t.Error("Name servers were not resolved", a, got)
	}

	if len(a.AAAA) != 1 || len(a.A) != 2 {
		t.Error("Not lame, but not right address count", len(a.AAAA), len(a.A))
	}
}
