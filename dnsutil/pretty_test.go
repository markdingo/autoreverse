package dnsutil

import (
	"testing"

	"github.com/miekg/dns"
)

func TestPretty(t *testing.T) {
	m := new(dns.Msg)
	s := PrettyMsg1(m)
	exp := "0 f= NOERROR Q=0- Ans=0- Ns=0- Extra=0-" // Completely empty
	if s != exp {
		t.Error("PrettyMsg1 empty msg got", s, "not", exp)
	}

	rr1, _ := dns.NewRR("x.example. IN AAAA ::1")
	rr2, _ := dns.NewRR("y.example. IN MX 10 a.b.")
	m.Ns = append(m.Ns, rr1)
	m.Answer = append(m.Answer, rr1)
	m.Answer = append(m.Answer, rr2)
	m.Extra = append(m.Extra, rr1)
	m.MsgHdr.Id = 4321
	m.MsgHdr.Response = true
	m.MsgHdr.Authoritative = true
	m.MsgHdr.Truncated = true

	s = PrettyMsg1(m)
	exp = "4321 f=qr+aa+tc NOERROR Q=0- Ans=2-AAAA,MX Ns=1-AAAA Extra=1-AAAA"
	if s != exp {
		t.Error("PrettyMsg1 full msg got", s, "not", exp)
	}

	// Question

	m.SetQuestion("example.org", dns.TypeSOA)
	s = PrettyQuestion(m.Question[0])
	exp = "IN/SOA example.org"
	if s != exp {
		t.Error("PrettyQuestion wrong", s, "not", exp)
	}

	// NS

	rr, _ := dns.NewRR("example.org IN NS a.ns.example.org")
	s = PrettyNS(rr.(*dns.NS), false)
	exp = "IN/NS 3600 a.ns.example.org."
	if s != exp {
		t.Error("PrettyNS 1", s)
	}

	s = PrettyNS(rr.(*dns.NS), true)
	exp = "example.org. IN/NS 3600 a.ns.example.org."
	if s != exp {
		t.Error("PrettyNS 2", s)
	}
	s = PrettyRR(rr, true)
	if s != exp {
		t.Error("PrettyNS 3", s)
	}

	// ShortNSSet

	rr1, _ = dns.NewRR("example.org IN NS b.ns.example.org")
	s = PrettyShortNSSet([]dns.RR{rr, rr1})
	exp = "a.ns.example.org., b.ns.example.org."
	if s != exp {
		t.Error("PrettyNSSet", s)
	}

	// SOA

	rr, _ = dns.NewRR("example.net IN SOA internal. hostmaster. 1 2 3 4 5")
	s = PrettySOA(rr.(*dns.SOA), false)
	exp = "IN/SOA 3600 internal. hostmaster. 1 2 3 4 5"
	if s != exp {
		t.Error("PrettySOA 1", s)
	}
	s = PrettySOA(rr.(*dns.SOA), true)
	exp = "example.net. IN/SOA 3600 internal. hostmaster. 1 2 3 4 5"
	if s != exp {
		t.Error("PrettySOA 2", s)
	}
	s = PrettyRR(rr, true)
	if s != exp {
		t.Error("PrettySOA 3", s)
	}

	// AAAA

	rr1, _ = dns.NewRR("f1.example.net. IN AAAA ::1")
	s = PrettyAAAA(rr1.(*dns.AAAA), false)
	exp = "IN/AAAA 3600 ::1"
	if s != exp {
		t.Error("PrettyAAAA 1", s)
	}
	s = PrettyAAAA(rr1.(*dns.AAAA), true)
	exp = "f1.example.net. IN/AAAA 3600 ::1"
	if s != exp {
		t.Error("PrettyAAAA 2", s)
	}
	s = PrettyRR(rr1, true)
	if s != exp {
		t.Error("PrettyAAAA 3", s)
	}

	// A

	rr2, _ = dns.NewRR("f1.example.net. IN A 127.0.0.1")
	s = PrettyA(rr2.(*dns.A), false)
	exp = "IN/A 3600 127.0.0.1"
	if s != exp {
		t.Error("PrettyA 1", s)
	}
	s = PrettyA(rr2.(*dns.A), true)
	exp = "f1.example.net. IN/A 3600 127.0.0.1"
	if s != exp {
		t.Error("PrettyA 2", s)
	}
	s = PrettyRR(rr2, true)
	if s != exp {
		t.Error("PrettyA 3", s)
	}

	// PTR

	rr3, _ := dns.NewRR("0.0.192.in-addr.arpa. IN PTR f1.example.net")
	s = PrettyPTR(rr3.(*dns.PTR), false)
	exp = "IN/PTR 3600 f1.example.net."
	if s != exp {
		t.Error("PrettyPTR 1", s)
	}
	s = PrettyPTR(rr3.(*dns.PTR), true)
	exp = "0.0.192.in-addr.arpa. IN/PTR 3600 f1.example.net."
	if s != exp {
		t.Error("PrettyPTR 2", s)
	}
	s = PrettyRR(rr3, true)
	if s != exp {
		t.Error("PrettyPTR 3", s)
	}

	// RRSet
	s = PrettyRRSet([]dns.RR{rr1, rr2, rr3}, false)
	exp = "IN/AAAA 3600 ::1, IN/A 3600 127.0.0.1, IN/PTR 3600 f1.example.net."
	if s != exp {
		t.Error("PrettyRRSet 1", s)
	}

	// Addr
	rr, _ = dns.NewRR("oct.example.net IN A 127.0.0.1")
	s = PrettyAddr(rr, false)
	exp = "127.0.0.1"
	if s != exp {
		t.Error("PrettyAddr 1", s)
	}
	s = PrettyAddr(rr, true)
	exp = "oct.example.net/127.0.0.1"
	if s != exp {
		t.Error("PrettyAddr 1", s)
	}

	rr, _ = dns.NewRR("hex.example.net IN AAAA ::1")
	s = PrettyAddr(rr, false)
	exp = "::1"
	if s != exp {
		t.Error("PrettyAddr 2", s)
	}
	s = PrettyAddr(rr, true)
	exp = "hex.example.net/::1"
	if s != exp {
		t.Error("PrettyAddr 2", s)
	}

	rr, _ = dns.NewRR("hex.example.net IN MX 10 mailer.")
	s = PrettyAddr(rr, true)
	exp = "hex.example.net/?PrettyAddr?"
	if s != exp {
		t.Error("PrettyAddr 3", s)
	}
}
