package main

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/database"
	"github.com/markdingo/autoreverse/delegation"
	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/mock"
	"github.com/markdingo/autoreverse/resolver"
)

// Test that all of the Zone-Of-Authority resources are correctly looked up
func TestAuthority(t *testing.T) {
	soaTime = time.Unix(1357997531, 0) // Override time.Now() so SOA.Serial is a known value

	// Create out-of-bailiwick and in-bailiwick name servers
	ns1, _ := dns.NewRR("autoreverse.example.net. IN NS ns1.example.org")
	ns2, _ := dns.NewRR("autoreverse.example.net. IN NS ns2.autoreverse.example.net")
	a1, _ := dns.NewRR("ns2.autoreverse.example.net IN A 192.168.0.1")
	a2, _ := dns.NewRR("ns2.autoreverse.example.net IN AAAA 2001:db8:7::1")
	auth := &delegation.Authority{Domain: "example.net.",
		NS:   []dns.RR{ns1, ns2},
		A:    []dns.RR{a1},
		AAAA: []dns.RR{a2}}

	ar := newAutoReverse(nil, nil)
	ar.cfg.TTLAsSecs = 600
	ar.synthesizeSOA(auth, "example.net.")

	exp := "example.net.	600	IN	SOA	ns1.example.org. hostmaster.example.net. 1357997531 110040 110080 28 9030"
	got := auth.SOA.String()
	if exp != got {
		t.Error("Synthesized SOA mismatch. Got", got, "Expect", exp)
	}

	server := newServer(&config{}, database.NewGetter(), resolver.NewResolver(), "", "") // Make a skeletal server
	server.authorities = append(server.authorities, auth)
	wtr := &mock.ResponseWriter{}

	wtr.Reset()
	q := setQuestion(dns.ClassINET, dns.TypeSOA, "example.net.")
	server.ServeDNS(wtr, q)
	resp := wtr.Get()
	if resp == nil {
		t.Fatal("Setup failed")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Error("Expected success for SOA lookup. got",
			dnsutil.RcodeToString(resp.Rcode), "\n", resp)
	}
	if len(resp.Answer) != 1 || len(resp.Ns) != 2 || len(resp.Extra) < 1 {
		t.Error("Expected 1,2,>=1 not", len(resp.Answer), len(resp.Ns), len(resp.Extra))
	}

	q = setQuestion(dns.ClassINET, dns.TypeANY, "example.net.")
	server.ServeDNS(wtr, q)
	resp = wtr.Get()
	if resp == nil {
		t.Fatal("Setup failed")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Error("Expected success for SOA lookup. got",
			dnsutil.RcodeToString(resp.Rcode), "\n", resp)
	}
	if len(resp.Answer) != 1 || len(resp.Ns) != 0 || len(resp.Extra) < 1 {
		t.Error("Expected 1,0,>=1 not", len(resp.Answer), len(resp.Ns), len(resp.Extra))
	}

	q = setQuestion(dns.ClassINET, dns.TypeNS, "example.net.")
	server.ServeDNS(wtr, q)
	resp = wtr.Get()
	if resp == nil {
		t.Fatal("Setup failed")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Error("Expected success for NS lookup. got",
			dnsutil.RcodeToString(resp.Rcode), "\n", resp)
	}
	if len(resp.Answer) != 2 || len(resp.Ns) != 0 || len(resp.Extra) < 2 {
		t.Error("Expected 2,0,>=20 not", len(resp.Answer), len(resp.Ns), len(resp.Extra))
	} else {
		if arr, ok := resp.Answer[0].(*dns.NS); !ok {
			t.Error("Expected NS")
		} else {
			if arr.Ns != "ns1.example.org." {
				t.Error("Wrong A RR returned", arr)
			}
		}
	}

	q = setQuestion(dns.ClassINET, dns.TypeMX, "example.net.")
	server.ServeDNS(wtr, q)
	resp = wtr.Get()
	if resp == nil {
		t.Fatal("Setup failed")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Error("Expected NO Error for MX lookup. got",
			dnsutil.RcodeToString(resp.Rcode), "\n", resp)
	}

	q = setQuestion(dns.ClassINET, dns.TypeA, "ns2.autoreverse.example.net.")
	server.ServeDNS(wtr, q)
	resp = wtr.Get()
	if resp == nil {
		t.Fatal("Setup failed")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Error("Expected success for A lookup. got",
			dnsutil.RcodeToString(resp.Rcode), "\n", resp)
	}
	if len(resp.Answer) != 1 || len(resp.Ns) != 0 || len(resp.Extra) < 1 {
		t.Error("Expected 1,0,>0 not", len(resp.Answer), len(resp.Ns), len(resp.Extra))
	} else {
		if arr, ok := resp.Answer[0].(*dns.A); !ok {
			t.Error("Expected A")
		} else {
			if arr.A.String() != "192.168.0.1" {
				t.Error("Wrong A RR returned", arr)
			}
		}
	}

	q = setQuestion(dns.ClassINET, dns.TypeAAAA, "ns2.autoreverse.example.net.")
	server.ServeDNS(wtr, q)
	resp = wtr.Get()
	if resp == nil {
		t.Fatal("Setup failed")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Error("Expected success for AAAA lookup. got",
			dnsutil.RcodeToString(resp.Rcode), "\n", resp)
	}
	if len(resp.Answer) != 1 || len(resp.Ns) != 0 || len(resp.Extra) < 1 {
		t.Error("Expected 1,0,>0 not", len(resp.Answer), len(resp.Ns), len(resp.Extra))
	} else {
		if arr, ok := resp.Answer[0].(*dns.AAAA); !ok {
			t.Error("Expected AAAA")
		} else {
			if arr.AAAA.String() != "2001:db8:7::1" {
				t.Error("Wrong AAAA RR returned", arr)
			}
		}
	}

	// Test with a minimalist Authority
	auth = &delegation.Authority{Domain: "example.net.", NS: []dns.RR{ns2}}
	ar.synthesizeSOA(auth, "example.net")
	server.authorities[0] = auth

	q = setQuestion(dns.ClassINET, dns.TypeSOA, "example.net.")
	server.ServeDNS(wtr, q)
	resp = wtr.Get()
	if resp == nil {
		t.Fatal("Setup failed")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Error("Expected success for SOA lookup. got",
			dnsutil.RcodeToString(resp.Rcode), "\n", resp)
	}

	q = setQuestion(dns.ClassINET, dns.TypeNS, "example.net.")
	server.ServeDNS(wtr, q)
	resp = wtr.Get()
	if resp == nil {
		t.Fatal("Setup failed")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Error("Expected success for NS lookup. got",
			dnsutil.RcodeToString(resp.Rcode), "\n", resp)
	}

	q = setQuestion(dns.ClassINET, dns.TypeA, "ns2.autoreverse.example.net.")
	server.ServeDNS(wtr, q)
	resp = wtr.Get()
	if resp == nil {
		t.Fatal("Setup failed")
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Error("Expected NXDomain for A lookup. got",
			dnsutil.RcodeToString(resp.Rcode), "\n", resp)
	}

	q = setQuestion(dns.ClassINET, dns.TypeAAAA, "ns2.autoreverse.example.net.")
	server.ServeDNS(wtr, q)
	resp = wtr.Get()
	if resp == nil {
		t.Fatal("Setup failed")
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Error("Expected NXDomain for AAAA lookup. got",
			dnsutil.RcodeToString(resp.Rcode), "\n", resp)
	}
}
