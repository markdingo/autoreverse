package resolver

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	real "github.com/markdingo/autoreverse/resolver"
)

func TestMockResolver(t *testing.T) {
	r := NewResolver("./testdata")
	ips, err := r.LookupIPAddr(context.Background(), "example.mock")
	if err != nil {
		t.Fatal("Setup error with example.mock", err.Error())
	}

	if len(ips) != 1 {
		t.Error("Expected one address, not", len(ips))
	}
	if ips[0].String() != "127.0.0.1" {
		t.Error("Expected 127.0.0.1, not", ips[0].String())
	}

	ips, err = r.LookupIPAddr(context.Background(), "www.apple.com")
	if err != nil {
		t.Fatal("Setup error with www.apple.com", err.Error())
	}
	if len(ips) != 4 {
		t.Error("Expected 4 addresses for www.apple.com, not", len(ips))
	}

	in := new(dns.Msg)
	in.Question = append(in.Question, dns.Question{Name: "a.ns.example.net",
		Qclass: dns.ClassCHAOS, Qtype: dns.TypeMX})
	out, _, err := r.SingleExchange(context.Background(), real.NewExchangeConfig(),
		in, "192.0.2.254", "192.0.2.254")
	if err != nil {
		t.Error("Setup error for r.SingleExchange", err.Error())
	} else if out == nil {
		t.Fatal("No out with no error from SingleExchange")
	}

	if out.MsgHdr.Rcode != dns.RcodeSuccess {
		t.Error("Expected Success, not", out.MsgHdr.Rcode)
	}
	if len(out.Answer) != 6 || len(out.Ns) != 4 || len(out.Extra) != 1 {
		t.Error("Wrong RR Count. Want 6, 4, 1. Got",
			len(out.Answer), len(out.Ns), len(out.Extra))
	}
}
