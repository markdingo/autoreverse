package main

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestCookies(t *testing.T) {
	testCases := []struct {
		input          string
		present, valid bool
		client, server string
	}{
		{"0123456789", true, false,
			"0123456789", ""}, // Client short
		{"0123456789abcdef", true, true,
			"0123456789abcdef", ""}, // Client only good
		{"0123456789abcdeffedcba9876543210", true, true,
			"0123456789abcdef", "fedcba9876543210"},
		{"0123456789abcdeffe", true, false,
			"0123456789abcdef", "fe"}, // Server short
		{"0123456789abcdeffedcba9876543210fedcba9876543210fe",
			true, true,
			"0123456789abcdef", "fedcba9876543210fedcba9876543210fe"}, // Server long
	}

	for ix, tc := range testCases {
		query := setQuestion(dns.ClassCHAOS, dns.TypeTXT, "version.bind.")
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		e := new(dns.EDNS0_COOKIE)
		e.Code = dns.EDNS0COOKIE
		e.Cookie = tc.input
		o.Option = append(o.Option, e)
		query.Extra = append(query.Extra, o)
		var src net.Addr
		req := newRequest(query, src, "udp")
		req.opt = o
		req.findCookies()
		if req.cookiesValid != tc.valid {
			t.Error(ix, "Valids mismatch. Exp:", tc.valid, "Got:", req.cookiesValid)
		}
		if req.clientCookie != tc.client {
			t.Error(ix, "Clients mismatch. Exp:", tc.client, "Got:", req.clientCookie)
		}
		if req.serverCookie != tc.server {
			t.Error(ix, "Servers mismatch. Exp:", tc.server, "Got:", req.serverCookie)
		}
	}
}
