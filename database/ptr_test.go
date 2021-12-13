package database_test

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/database"
)

func TestDatabaseAdd(t *testing.T) {
	db := database.NewDatabase()

	ip1 := "192.0.2.27"

	rr, _ := dns.NewRR("a.example.net. IN 123 A " + ip1)
	db.Add(rr) // Should add
	db.Add(rr) // Should be discarded as a duplicate
	rr, _ = dns.NewRR("b.example.net. IN 123 A " + ip1)
	db.Add(rr) // Should add

	ip2 := "192.0.2.28"
	rr, _ = dns.NewRR("a.example.net. IN 123 A " + ip2)
	db.Add(rr)           // Should add
	if db.Count() != 3 { // Should have two PTRs
		t.Error("Count should be 3, not", db.Count())
	}

	ptrs := db.Lookup(ip1)
	if len(ptrs) != 2 {
		t.Error("Lookup of", ip1, "should return 2 PTRs, not", len(ptrs))
	} else {
		foundA := false
		foundB := false
		names := []string{}
		for _, pRR := range ptrs {
			p := pRR.(*dns.PTR)
			if p.Hdr.Class != dns.ClassINET || p.Hdr.Rrtype != dns.TypePTR {
				t.Error("PTR class/Type should match",
					dns.ClassToString[p.Hdr.Class],
					dns.TypeToString[p.Hdr.Rrtype])
			}
			names = append(names, p.Ptr)
			if p.Ptr == "a.example.net." {
				foundA = true
			}
			if p.Ptr == "b.example.net." {
				foundB = true
			}
		}
		if !foundA || !foundB {
			t.Error("Did not find both a. and b.", names)
		}
	}

	ptrs = db.Lookup(ip2)
	if len(ptrs) != 1 {
		t.Error("Lookup of", ip2, "should return 1 ptr, not", len(ptrs))
	}
}
