package database

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAddRR(t *testing.T) {
	db := NewDatabase()
	tf := db.AddRR(newRR("a.b.c. IN A 1.2.3.4"))
	if !tf {
		t.Error("Expected Add to work")
	}
	tf = db.AddRR(newRR("a.b.c. IN A 1.2.3.4"))
	if tf {
		t.Error("Expected Second Add to fail")
	}
	c := db.Count()
	if c != 1 {
		t.Error("Count should be one, not", c)
	}
	db.AddRR(newRR("a.b.c. IN A 1.2.3.5"))
	db.AddRR(newRR("a.b.c. IN AAAA ::1"))
	db.AddRR(newRR("a.b.c.d.e.f. IN AAAA ::1"))
	db.AddRR(newRR("a.w.x.b.c.d.e.f. IN AAAA ::1"))
	db.AddRR(newRR("3.f.6.d.4.d.3.b.c.4.3.0.1.3.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa. IN PTR a.b.c."))
	c = db.Count()
	if c != 6 {
		t.Error("Count should be six, not", c)
	}
}

func TestLookup(t *testing.T) {
	type testCase struct {
		qClass  uint16
		qType   uint16
		qName   string
		arCount int
		nx      bool
	}
	testCases := []testCase{
		{dns.ClassINET, dns.TypeA, ".", 0, true},                 // No class
		{dns.ClassHESIOD, dns.TypeTXT, "bind.version.", 0, true}, // No class
		{dns.ClassINET, dns.TypeA, "b.c.", 0, false},             // a.b.c. exists
		{dns.ClassCHAOS, dns.TypeTXT, "bind.version.", 1, false},
		{dns.ClassCHAOS, dns.TypeA, "bind.version.", 0, false},
		{dns.ClassINET, dns.TypeA, "a.b.c.d.e.f.", 0, false},
		{dns.ClassINET, dns.TypeAAAA, "a.b.c.d.e.f.", 1, false},
		{dns.ClassINET, dns.TypeAAAA, "w.a.b.c.d.e.f.", 0, true}, // Too deep

		{dns.ClassINET, dns.TypeAAAA, "a.b.c.d.e.f.", 1, false},
		{dns.ClassINET, dns.TypeAAAA, "a.b.", 0, true}, // No TLD of b.
		{dns.ClassINET, dns.TypePTR, "0.168.192.in-addr.arpa.", 0, false},
		{dns.ClassINET, dns.TypePTR, "2.0.168.192.in-addr.arpa.", 0, true},
		{dns.ClassINET, dns.TypePTR,
			"3.f.6.d.4.d.3.b.c.4.3.0.1.3.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
			1, false},
		{dns.ClassINET, dns.TypePTR,
			"f.6.d.4.d.3.b.c.4.3.0.1.3.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
			0, false},
		{dns.ClassINET, dns.TypePTR,
			"1.3.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
			0, false},
	}

	db := NewDatabase()
	ar, nx := db.LookupRR(dns.ClassINET, dns.TypeA, "a.")
	if len(ar) > 0 {
		t.Error("Lookup of empty DB returned RRset", ar)
	}
	if !nx {
		t.Error("Lookup of empty DB returned NoError")
	}
	db.AddRR(newRR("a.b.c. IN A 1.2.3.4"))
	db.AddRR(newRR("a.b.c. IN A 1.2.3.5")) // 2 A RRs
	db.AddRR(newRR("a.b.c. IN AAAA ::1"))  // and 1 AAAA RR and zero MX RRs
	db.AddRR(newRR("a.b.c.d.e.f. IN AAAA ::1"))
	db.AddRR(newRR("a.w.x.b.c.d.e.f. IN AAAA ::1"))
	db.AddRR(newRR("bind.version. CH TXT '10.1'"))
	db.AddRR(newRR("3.f.6.d.4.d.3.b.c.4.3.0.1.3.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa. IN PTR a.b.c."))
	db.AddRR(newRR("1.0.168.192.in-addr.arpa. IN PTR w.x.y."))
	for ix, tc := range testCases {
		ar, nx = db.LookupRR(tc.qClass, tc.qType, tc.qName)
		if len(ar) != tc.arCount {
			t.Error(ix, "Wrong rrset count", len(ar), tc.arCount)
		}
		if nx != tc.nx {
			t.Error(ix, "Wrong NXDomain of", nx)
		}
	}
}

func TestImmutable(t *testing.T) {
	db := NewDatabase()
	rr1 := newRR("a.b.c. IN A 1.2.3.4")
	db.AddRR(rr1)
	rr1.Header().Ttl = 53
	ans, _ := db.LookupRR(dns.ClassINET, dns.TypeA, "a.b.c.")
	for _, a := range ans {
		if a.Header().Ttl == 53 {
			t.Error("Was able to modify in-DB copy of RR", ans)
		}
	}

	// Second and subsequent RRs take a different code path in Add() so check that
	// path as well. Also test for modification on returned RRs.
	rr1 = newRR("a.b.c. IN A 1.2.3.5")
	db.AddRR(rr1)
	rr1.Header().Ttl = 53
	ans, _ = db.LookupRR(dns.ClassINET, dns.TypeA, "a.b.c.")
	for _, a := range ans {
		if a.Header().Ttl == 53 {
			t.Error("Was able to modify in-DB copy of RR", ans)
		}
		a.Header().Ttl = 55
	}

	ans, _ = db.LookupRR(dns.ClassINET, dns.TypeA, "a.b.c.")
	for _, a := range ans {
		if a.Header().Ttl == 55 {
			t.Error("Was able to modify returned copy of RR", ans)
		}
	}
}

// Allow newRR in function calls by dealing with errors locally
func newRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic("newRR Setup error with: " + s)
	}

	return rr
}
