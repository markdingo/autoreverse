package dnsutil

import (
	"testing"

	"github.com/miekg/dns"
)

func TestValidDelegation(t *testing.T) {
	m := new(dns.Msg)
	res := ValidDelegation(m)
	if res {
		t.Error("Did not expect an empty message to be a valid delegation")
	}

	m.MsgHdr.Rcode = dns.RcodeSuccess
	ns, err := dns.NewRR("example.net. IN NS a.ns.example.net")
	if err != nil {
		t.Fatal("Setup error", err)
	}
	m.Ns = append(m.Ns, ns)

	res = ValidDelegation(m)
	if !res {
		t.Error("Did not expect good message to fail", m)
	}

	mgood := *m // Save this good one as we re-use it as a template
	m.MsgHdr.Rcode = dns.RcodeNameError
	if ValidDelegation(m) {
		t.Error("Bad rcode should not be valid")
	}

	*m = mgood
	m.Answer = append(m.Answer, new(dns.A))
	if ValidDelegation(m) {
		t.Error("Ans > 0 should fail")
	}

	*m = mgood
	nsBad, err := dns.NewRR("example.net. IN NS a.ns.example.net")
	if err != nil {
		t.Fatal("Setup error", err)
	}
	nsBad.Header().Class = dns.ClassCHAOS
	m.Ns = append(m.Ns, nsBad)
	if ValidDelegation(m) {
		t.Error("Wrong Class in Ns should fail")
	}

	*m = mgood
	a, _ := dns.NewRR("example.net. IN A 127.0.0.1")
	a.Header().Rrtype = dns.TypeNS
	m.Ns = append(m.Ns, a)
	if ValidDelegation(m) {
		t.Error("Bogus go type case should have been detected")
	}
}
