package database

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAddPTR(t *testing.T) {
	db := NewDatabase()
	db.Add(newRR("a.b.c. IN A 1.2.3.4"))
	db.Add(newRR("w.x. IN AAAA ::1"))
	db.Add(newRR("3.f.6.d.4.d.3.b.c.4.3.0.1.3.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa. IN PTR a.b.c."))
	for ix, k := range []string{"4.3.2.1.in-addr.arpa.",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
		"3.f.6.d.4.d.3.b.c.4.3.0.1.3.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa."} {
		ar, nx := db.LookupRR(dns.ClassINET, dns.TypePTR, k)
		if len(ar) != 1 {
			t.Error(ix, "Wrong rrset count", len(ar))
		}
		if nx {
			t.Error(ix, "Unexpected NXDomain")
		}
	}
}
