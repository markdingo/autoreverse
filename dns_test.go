package main

import (
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/markdingo/autoreverse/database"
	"github.com/markdingo/autoreverse/delegation"
	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
	"github.com/markdingo/autoreverse/resolver"

	"github.com/miekg/dns"
)

// This series of tests is essentially in order of the flow of ServeDNS in dns.go. Some of
// the bigger tests have been put into separate modules, such as chaos and authority.

// Early validation testing prior to authority
func TestDNSFormErr(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	server := newServer(&config{logQueriesFlag: true}, database.NewGetter(), resolver.NewResolver(), nil, "", "") // Make a skeletal server
	t.Run("Empty Message", func(t *testing.T) { testInvalid(t, server, new(dns.Msg)) })

	m := setQuestion(dns.ClassINET, dns.TypeSOA, "example.net.")
	q := dns.Question{Name: "xxx", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	m.Question = append(m.Question, q) // Two questions
	t.Run("Two Questions", func(t *testing.T) { testInvalid(t, server, m) })

	m = setQuestion(dns.ClassINET, dns.TypeSOA, "example.net.")
	m.Answer = append(m.Answer, newRR("example.net. IN A 127.0.0.1"))
	t.Run("Non-empty Answer", func(t *testing.T) { testInvalid(t, server, m) })

	m = setQuestion(dns.ClassINET, dns.TypeSOA, "example.net.")
	m.Ns = append(m.Ns, newRR("example.net. IN A 127.0.0.1"))
	t.Run("Non-empty NS", func(t *testing.T) { testInvalid(t, server, m) })

	m = setQuestion(dns.ClassINET, dns.TypeSOA, "example.net.")
	m.Opcode = dns.OpcodeNotify
	t.Run("Wrong op-code", func(t *testing.T) { testInvalid(t, server, m) })

	// Check the logging output while we're at it
	exp := `ru=FORMERR q=None/ s=127.0.0.2:4056 id=0 h=U sz=12/0 C=0/0/0 Malformed Query
ru=FORMERR q=SOA/example.net. s=127.0.0.2:4056 id=1 h=U sz=12/0 C=0/0/0 Malformed Query
ru=FORMERR q=SOA/example.net. s=127.0.0.2:4056 id=1 h=U sz=12/0 C=0/0/0 Malformed Query
ru=FORMERR q=SOA/example.net. s=127.0.0.2:4056 id=1 h=U sz=12/0 C=0/0/0 Malformed Query
ru=FORMERR q=SOA/example.net. s=127.0.0.2:4056 id=1 h=U sz=12/0 C=0/0/0 Malformed Query
`
	got := out.String()
	if got != exp {
		t.Error("Log data differs. Got:", got, "Exp:", exp)
	}
}

// Sub-test for TestFormErr
func testInvalid(t *testing.T, server *server, m *dns.Msg) {
	wtr := &mock.ResponseWriter{}
	server.ServeDNS(wtr, m)
	resp := wtr.Get()
	if resp == nil {
		t.Fatal("Setup failed")
	}
	if resp.Rcode != dns.RcodeFormatError {
		t.Error("Expected format error, not", dnsutil.RcodeToString(resp.Rcode))
	}
}

func TestDNSProbe(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MinorLevel)

	res := resolver.NewResolver()
	cfg := &config{logQueriesFlag: true}
	server := newServer(cfg, database.NewGetter(), res, nil, "", "")
	rand.Seed(0) // Make probe generation predictable
	a1 := &authority{forward: true}
	a1.Domain = "fozzy.example.net."
	pr := delegation.NewForwardProbe(a1.Domain)
	var auths authorities
	auths.append(a1)
	server.setMutables("", pr, auths)

	// First send a bogus query in probe mode
	query := setQuestion(dns.ClassINET, dns.TypeMX, "example.org")
	query.Id = 2
	wtr := &mock.ResponseWriter{}
	server.ServeDNS(wtr, query)
	resp := wtr.Get()
	if resp == nil {
		t.Fatal("Setup error - No response to probe query")
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Error("Expected RcodeRefused, not", dnsutil.RcodeToString(resp.Rcode))
	}

	query = new(dns.Msg)
	query.Id = 1
	query.RecursionDesired = false
	query.Question = append(query.Question, pr.Question())

	server.ServeDNS(wtr, query)
	resp = wtr.Get()
	if resp == nil {
		t.Fatal("Setup error - No response to probe query")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Error("Expected RcodeSuccess, not", dnsutil.RcodeToString(resp.Rcode))
	}
	if !dnsutil.RRIsEqual(resp.Answer[0], pr.Answer()) {
		t.Error("Probe response was not as expected", resp.Answer[0], pr.Answer())
	}

	// Check logging output
	exp := `ru=REFUSED q=MX/example.org. s=127.0.0.2:4056 id=2 h=U sz=40/1232 C=0/0/1 Non-probe query during probe:not in-domain
  Valid Probe received from 127.0.0.2:4056
ru=ok q=AAAA/cubyh.fozzy.example.net. s=127.0.0.2:4056 id=1 h=U sz=103/1232 C=1/0/1 Probe match
`

	got := out.String()
	if got != exp {
		t.Error("Log data differs. \n Got:", got, "Exp:", exp)
	}

}

func TestDNSWrongClass(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MajorLevel)

	wtr := &mock.ResponseWriter{}

	res := resolver.NewResolver()
	cfg := &config{logQueriesFlag: true}
	server := newServer(cfg, database.NewGetter(), res, nil, "", "")
	a := &authority{forward: true}
	a.Domain = "example.net."
	var auths authorities
	auths.append(a)
	server.setMutables("", nil, auths)

	// First try with an invalid type
	query := setQuestion(dns.ClassHESIOD, dns.TypeNS, "ns.example.net.")
	server.ServeDNS(wtr, query)
	resp := wtr.Get()
	if resp == nil {
		t.Fatal("Setup error - No response to HESIOD query")
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Error("Expected RcodeRefused, not", dnsutil.RcodeToString(resp.Rcode))
	}

	// Check error logging
	exp := "ru=REFUSED q=NS/ns.example.net. s=127.0.0.2:4056 id=1 h=U sz=43/1232 C=0/0/1 Wrong class HS\n"
	got := out.String()
	if exp != got {
		t.Error("Error log mismatch. \n Got:", got, "Exp:", exp)
	}

	out.Reset()
	query = setQuestion(2021, dns.TypeA, "2021.example.net.")
	server.ServeDNS(wtr, query)
	resp = wtr.Get()
	if resp == nil {
		t.Fatal("Setup error - No response to Class 2021 query")
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Error("Expected RcodeRefused, not", dnsutil.RcodeToString(resp.Rcode))
	}

	// Check error logging
	exp = "ru=REFUSED q=A/2021.example.net. s=127.0.0.2:4056 id=1 h=U sz=45/1232 C=0/0/1 Wrong class C-2021\n"
	got = out.String()
	if exp != got {
		t.Error("Error log mismatch. \n Got:", got, "Exp:", exp)
	}
}

const (
	nsidAsText = "Jammin"
	nsidAsHex  = "4a616d6d696e"
)

func TestDNSServeBadPTR(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MajorLevel)

	wtr := &mock.ResponseWriter{}

	res := resolver.NewResolver()
	cfg := &config{logQueriesFlag: true, synthesizeFlag: true}
	server := newServer(cfg, database.NewGetter(), res, nil, "", "")
	a1 := &authority{forward: true}
	a1.Domain = "misc.example.net."
	a2 := &authority{}
	a2.Domain = "f.f.f.f.d.2.d.f.ip6.arpa."
	var err error
	_, a2.cidr, err = net.ParseCIDR("fd2d:ffff::/64")
	if err != nil {
		t.Fatal("Setup Error", err)
	}
	a3 := &authority{}
	a3.Domain = "2.0.192.in-addr.arpa."
	_, a3.cidr, err = net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal("Setup Error", err)
	}

	var auths authorities
	a1.synthesizeSOA("example.net.", 60)
	a2.synthesizeSOA("example.net.", 60)
	a3.synthesizeSOA("example.net.", 60)
	auths.append(a1)
	auths.append(a2)
	auths.append(a3)
	auths.sort()
	server.setMutables("", nil, auths)

	testCases := []struct {
		qType   uint16
		qName   string
		synth   bool
		rCode   int
		answers int
		auths   int
		log     string
	}{
		{dns.TypePTR, "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa.", true,
			dns.RcodeSuccess, 1, 0, // Baseline good response
			"ru=ok q=PTR/0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa. " +
				"s=127.0.0.2:4056 id=1 h=U sz=197/1232 C=1/0/1 Synth\n"},

		{dns.TypePTR, "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa.", true,
			dns.RcodeSuccess, 0, 1, // First two nibbles missing (truncated) should return NoError, empty Answer and SOA
			"ru=ne q=PTR/0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa. " +
				"s=127.0.0.2:4056 id=1 h=U sz=203/1232 C=0/1/1 Trunc-qmin\n"},

		{dns.TypePTR, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.f.f.f.d.2.d.f.ip6.arpa.", true,
			dns.RcodeRefused, 0, 0, // Not in-domain
			"ru=REFUSED q=PTR/1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.f.f.f.d.2.d.f.ip6.arpa. " +
				"s=127.0.0.2:4056 id=1 h=U sz=101/1232 C=0/0/1 not in-domain\n"},

		{dns.TypePTR, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa.", false,
			dns.RcodeNameError, 0, 1, // No Synth, but in-domain, not alternative answers so SOA
			"ru=NXDOMAIN q=PTR/1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa. " +
				"s=127.0.0.2:4056 id=1 h=U sz=207/1232 C=0/1/1 No Synth\n"},

		{dns.TypeA, "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa.", true,
			dns.RcodeSuccess, 0, 1, // Baseline query with wrong qType
			"ru=ne q=A/0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa. " +
				"s=127.0.0.2:4056 id=1 h=U sz=207/1232 C=0/1/1 Not PTR\n"},
	}

	for ix, tc := range testCases {
		query := setQuestion(dns.ClassINET, tc.qType, tc.qName)
		out.Reset()
		cfg.synthesizeFlag = tc.synth

		server.ServeDNS(wtr, query)
		resp := wtr.Get()
		if resp == nil {
			t.Fatal(ix, "Setup error - No response to PTR query")
		}

		if resp.Rcode != tc.rCode || len(resp.Answer) != tc.answers || len(resp.Ns) != tc.auths {
			t.Errorf("%d Expected %s, answers=%d and auths=%d, not %s, %d and %d",
				ix, dnsutil.RcodeToString(tc.rCode), tc.answers, tc.auths,
				dnsutil.RcodeToString(resp.Rcode), len(resp.Answer), len(resp.Ns))
			continue
		}
		if len(tc.log) == 0 { // Compare log message?
			continue
		}
		got := out.String()
		if tc.log != got {
			t.Error(ix, "Log mismatch.\n Got:", got, "Exp:", tc.log)
		}
	}
}

// NSID, UDPsize and any other corner cases that come to mind
func TestDNSMisc(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MajorLevel)

	wtr := &mock.ResponseWriter{}

	res := resolver.NewResolver()
	cfg := &config{logQueriesFlag: true, chaosFlag: true, synthesizeFlag: true,
		nsid: nsidAsText, nsidAsHex: nsidAsHex}
	cfg.generateNSIDOpt()
	ar := newAutoReverse(cfg, res)
	newDB := database.NewDatabase()
	ar.loadFromChaos(newDB)
	ar.dbGetter.Replace(newDB)
	server := newServer(cfg, ar.dbGetter, res, nil, "", "")

	a1 := &authority{}
	a1.Domain = "misc.example.net."
	a1.forward = true
	ar.authorities.append(a1)
	server.setMutables("", nil, ar.authorities)

	query := setQuestion(dns.ClassCHAOS, dns.TypeTXT, "version.bind.")

	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	e1 := new(dns.EDNS0_NSID)
	e1.Code = dns.EDNS0NSID
	o.Option = append(o.Option, e1)
	query.Extra = append(query.Extra, o)

	server.ServeDNS(wtr, query)
	resp := wtr.Get()
	if resp == nil {
		t.Fatal("Setup error - No response to CHAOS query")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Error("Expected RcodeSuccess, not", dnsutil.RcodeToString(resp.Rcode))
	}

	// Check UDP Size settings to see that only sensible values are accepted
	for ix, sz := range []uint16{100, 600, dnsutil.MaxUDPSize - 1, dnsutil.MaxUDPSize + 1} {
		query := setQuestion(dns.ClassCHAOS, dns.TypeTXT, "version.bind.")
		query.SetEdns0(sz, false)

		server.ServeDNS(wtr, query)
		resp := wtr.Get()
		if resp == nil {
			t.Error(ix, "Setup error - No response to CHAOS query")
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			t.Error(ix, "Expected RcodeSuccess, not", dnsutil.RcodeToString(resp.Rcode))
			continue
		}
		edns := resp.IsEdns0()
		if edns == nil {
			t.Error(ix, "Should have got an EDNS Size option")
			continue
		}
		mz := edns.UDPSize()
		if sz < 512 || sz > dnsutil.MaxUDPSize { // What do we expect back?
			sz = dnsutil.MaxUDPSize
		}
		if mz != sz {
			t.Error("UDPSize came back as", mz, "expected", sz)
		}
	}

	// Issue invalid forward queries that *look* like they might work.

	testCases := []struct {
		qType uint16
		qName string
	}{
		{dns.TypeA, "192.0.2.misc.example.net."},       // Synthetic hosts are "-" separated
		{dns.TypeA, "192-0-2.misc.example.net."},       // Malformed ipv4
		{dns.TypeA, "fd2d::1.misc.example.net."},       // Not ipv4
		{dns.TypeAAAA, "fd2d::1.misc.example.net."},    // Synthetic hosts are "-" separated
		{dns.TypeAAAA, "fd2d--1--2.misc.example.net."}, // Malformed ipv6
		{dns.TypeAAAA, "192-0-2-1.misc.example.net."},  // Not ipv6
	}

	for ix, tc := range testCases {
		query = setQuestion(dns.ClassINET, tc.qType, tc.qName)
		server.ServeDNS(wtr, query)
		resp = wtr.Get()
		if resp == nil {
			t.Error(ix, "Setup error - No response to bogus query")
			continue
		}

		if resp.Rcode != dns.RcodeNameError {
			t.Error(ix, "Expected NXDOMAIN, not", dnsutil.RcodeToString(resp.Rcode))
			continue
		}
	}

	// Check logging
	exp := `ru=ok q=TXT/version.bind. s=127.0.0.2:4056 id=1 h=Un sz=106/1232 C=1/0/1
ru=ok q=TXT/version.bind. s=127.0.0.2:4056 id=1 h=U sz=96/1232 C=1/0/1
ru=ok q=TXT/version.bind. s=127.0.0.2:4056 id=1 h=U sz=96/600 C=1/0/1
ru=ok q=TXT/version.bind. s=127.0.0.2:4056 id=1 h=U sz=96/1231 C=1/0/1
ru=ok q=TXT/version.bind. s=127.0.0.2:4056 id=1 h=U sz=96/1232 C=1/0/1
ru=NXDOMAIN q=A/192.0.2.misc.example.net. s=127.0.0.2:4056 id=1 h=U sz=86/1232 C=0/1/1
ru=NXDOMAIN q=A/192-0-2.misc.example.net. s=127.0.0.2:4056 id=1 h=U sz=86/1232 C=0/1/1
ru=NXDOMAIN q=A/fd2d::1.misc.example.net. s=127.0.0.2:4056 id=1 h=U sz=86/1232 C=0/1/1
ru=NXDOMAIN q=AAAA/fd2d::1.misc.example.net. s=127.0.0.2:4056 id=1 h=U sz=86/1232 C=0/1/1
ru=NXDOMAIN q=AAAA/fd2d--1--2.misc.example.net. s=127.0.0.2:4056 id=1 h=U sz=89/1232 C=0/1/1
ru=NXDOMAIN q=AAAA/192-0-2-1.misc.example.net. s=127.0.0.2:4056 id=1 h=U sz=88/1232 C=0/1/1
`
	got := out.String()
	if exp != got {
		t.Error("Misc log mismatch got:\n", got, "\nexp:\n", exp)
	}
}

func TestDNSGoodAnswers(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MajorLevel)

	wtr := &mock.ResponseWriter{}
	res := resolver.NewResolver()
	cfg := &config{logQueriesFlag: true, synthesizeFlag: true, delegatedForward: "a.zig.", TTLAsSecs: 3600}
	ar := newAutoReverse(cfg, res)
	a1 := &authority{forward: true}
	a1.Domain = cfg.delegatedForward
	a2 := &authority{}
	a2.Domain = "f.f.f.f.d.2.d.f.ip6.arpa."
	_, a2.cidr, _ = net.ParseCIDR("fd2d:ffff::/64")
	a3 := &authority{}
	a3.Domain = "2.0.192.in-addr.arpa."
	_, a3.cidr, _ = net.ParseCIDR("192.0.2.0/24")
	ar.authorities.append(a1)
	ar.authorities.append(a2)
	ar.authorities.append(a3)
	newDB := database.NewDatabase()
	ar.loadFromAuthorities(newDB)
	ar.dbGetter.Replace(newDB)
	server := newServer(cfg, ar.dbGetter, res, nil, "", "")
	server.setMutables("a.zig.", nil, ar.authorities)

	var testCases = []struct {
		qType  uint16
		qName  string
		expect dns.RR
		log    string
	}{
		{dns.TypePTR, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa.",
			newRR("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa. IN PTR fd2d-ffff--1.a.zig."),
			"ru=ok q=PTR/1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa. " +
				"s=127.0.0.2:4056 id=10 h=U sz=205/1232 C=1/0/1 Synth\n"},

		{dns.TypePTR, "2.0.0.0.0.0.0.0.0.0.0.0.0.f.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa.",
			newRR("2.0.0.0.0.0.0.0.0.0.0.0.0.f.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa. IN PTR fd2d-ffff--f0-0-0-2.a.zig."),
			"ru=ok q=PTR/2.0.0.0.0.0.0.0.0.0.0.0.0.f.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa. " +
				"s=127.0.0.2:4056 id=11 h=U sz=212/1232 C=1/0/1 Synth\n"},

		{dns.TypePTR, "1.2.0.192.in-addr.arpa.",
			newRR("1.2.0.192.in-addr.arpa. IN PTR 192-0-2-1.a.zig."),
			"ru=ok q=PTR/1.2.0.192.in-addr.arpa. s=127.0.0.2:4056 id=12 h=U sz=102/1232 C=1/0/1 Synth\n"},

		{dns.TypePTR, "254.2.0.192.in-addr.arpa.",
			newRR("254.2.0.192.in-addr.arpa. IN PTR 192-0-2-254.a.zig."),
			"ru=ok q=PTR/254.2.0.192.in-addr.arpa. s=127.0.0.2:4056 id=13 h=U sz=108/1232 C=1/0/1 Synth\n"},

		{dns.TypeA, "192-0-2-1.a.zig.", newRR("192-0-2-1.a.zig. IN A 192.0.2.1"),
			"ru=ok q=A/192-0-2-1.a.zig. s=127.0.0.2:4056 id=14 h=U sz=75/1232 C=1/0/1\n"},

		{dns.TypeA, "192-0-2-254.a.zig.", newRR("192-0-2-254.a.zig. IN A 192.0.2.254"),
			"ru=ok q=A/192-0-2-254.a.zig. s=127.0.0.2:4056 id=15 h=U sz=79/1232 C=1/0/1\n"},

		{dns.TypeAAAA, "fd2d-ffff--1.a.zig.", newRR("fd2d-ffff--1.a.zig. IN AAAA fd2d:ffff::1"),
			"ru=ok q=AAAA/fd2d-ffff--1.a.zig. s=127.0.0.2:4056 id=16 h=U sz=93/1232 C=1/0/1\n"},

		{dns.TypeAAAA, "fd2d-ffff--f0-0-0-2.a.zig.", newRR("fd2d-ffff--f0-0-0-2.a.zig. IN AAAA fd2d:ffff::f0:0:0:2"),
			"ru=ok q=AAAA/fd2d-ffff--f0-0-0-2.a.zig. s=127.0.0.2:4056 id=17 h=U sz=107/1232 C=1/0/1\n"},
	}

	for ix, tc := range testCases {
		query := setQuestion(dns.ClassINET, tc.qType, tc.qName)
		query.Id = uint16(ix + 10)
		server.ServeDNS(wtr, query)
		resp := wtr.Get()
		if resp == nil {
			t.Fatal(ix, "Setup error - No response to PTR query")
		}
		if resp.Rcode != dns.RcodeSuccess {
			t.Error(ix, "Expected RcodeSuccess, not", dnsutil.RcodeToString(resp.Rcode))
			continue
		}
		if len(resp.Answer) != 1 {
			t.Error(ix, "Wrong number of Answers", len(resp.Answer))
			continue
		}
		ans := resp.Answer[0]
		if !dnsutil.RRIsEqual(ans, tc.expect) {
			t.Error(ix, "Wrong PTR returned. \nExp:", tc.expect, "\nGot:", ans)
			continue
		}
		got := out.String()
		out.Reset()
		if got != tc.log {
			t.Error(ix, "Log mismatch. \nExp", tc.log, "\nGot", got)
			continue
		}
	}
}

// Test that all of the Zone-Of-Authority resources are correctly looked up
func TestDNSAuthorityLookups(t *testing.T) {
	soaTime = time.Unix(1357997531, 0) // Override time.Now() so SOA.Serial is a known value

	// Create not in-domain and in-domain name servers
	ns1, _ := dns.NewRR("autoreverse.example.net. IN NS ns1.example.org")
	ns2, _ := dns.NewRR("autoreverse.example.net. IN NS ns2.autoreverse.example.net")
	a1, _ := dns.NewRR("ns2.autoreverse.example.net IN A 192.168.0.1")
	a2, _ := dns.NewRR("ns2.autoreverse.example.net IN AAAA 2001:db8:7::1")
	auth := &authority{forward: true}
	auth.Domain = "example.net."
	auth.NS = []dns.RR{ns1, ns2}
	auth.A = []dns.RR{a1}
	auth.AAAA = []dns.RR{a2}

	ar := newAutoReverse(nil, nil)
	ar.cfg.TTLAsSecs = 600
	auth.synthesizeSOA("example.net.", ar.cfg.TTLAsSecs)
	ar.authorities.append(auth)
	newDB := database.NewDatabase()
	ar.loadFromAuthorities(newDB)
	ar.dbGetter.Replace(newDB)
	exp := "example.net.	600	IN	SOA	ns1.example.org. hostmaster.example.net. 1357997531 110040 110080 28 9030"
	got := auth.SOA.String()
	if exp != got {
		t.Error("Synthesized SOA mismatch. Got", got, "Expect", exp)
	}

	server := newServer(ar.cfg, ar.dbGetter, resolver.NewResolver(), nil, "", "") // Make a skeletal server
	server.authorities.append(auth)
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
	auth = &authority{}
	auth.Domain = "example.net."
	auth.NS = []dns.RR{ns2}

	auth.synthesizeSOA("example.net", ar.cfg.TTLAsSecs)
	server.authorities.slice[0] = auth // Looking inside is a bit of a hack for this test

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
	if resp.Rcode != dns.RcodeSuccess {
		t.Error("Expected NoError for A lookup. got",
			dnsutil.RcodeToString(resp.Rcode), "\n", resp)
	}

	q = setQuestion(dns.ClassINET, dns.TypeAAAA, "ns2.autoreverse.example.net.")
	server.ServeDNS(wtr, q)
	resp = wtr.Get()
	if resp == nil {
		t.Fatal("Setup failed")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Error("Expected NOError for AAAA lookup. got",
			dnsutil.RcodeToString(resp.Rcode), "\n", resp)
	}

	q = setQuestion(dns.ClassINET, dns.TypeNS, "ns1.example.org.")
	server.ServeDNS(wtr, q)
	resp = wtr.Get()
	if resp == nil {
		t.Fatal("Setup failed")
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Error("Expected Refused for not in-domain NS lookup. got",
			dnsutil.RcodeToString(resp.Rcode), "\n", resp)
	}
}

func TestDNSCookies(t *testing.T) {
	var testCases = []struct {
		addQuery bool
		in, out  string
		rcode    int
		note     string
	}{
		{false, "0123456789abcdef", "", dns.RcodeSuccess, "Query Server Cookie"},
		{true, "", "", dns.RcodeFormatError, "Malformed"},                   // No cCookie
		{true, "01", "", dns.RcodeFormatError, "Malformed"},                 // Short cCookie
		{true, "0123456789abcdefab", "", dns.RcodeFormatError, "Malformed"}, // Short sCookie
		{true, "0123456789abcdefab", "", dns.RcodeFormatError, "Malformed"}, // Short sCookie
		{true, "0123456789abcdef010000000000200078f6dcfbf17e8504",
			"0123456789abcdef01000000", dns.RcodeSuccess,
			"mismatch"}, // Short sCookie
	}

	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MajorLevel)
	wtr := &mock.ResponseWriter{}
	res := resolver.NewResolver()
	cfg := &config{logQueriesFlag: true, chaosFlag: true}
	ar := newAutoReverse(cfg, res)
	newDB := database.NewDatabase()
	ar.loadFromChaos(newDB)
	ar.dbGetter.Replace(newDB)
	server := newServer(cfg, ar.dbGetter, res, nil, "", "")
	var auths authorities
	server.setMutables("a.zig.", nil, auths)

	for ix, tc := range testCases {
		query := new(dns.Msg)
		query.Id = uint16(ix)
		if tc.addQuery {
			query.Question = append(query.Question,
				dns.Question{Name: "version.bind.", Qclass: dns.ClassCHAOS, Qtype: dns.TypeTXT})
		}
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		e := new(dns.EDNS0_COOKIE)
		e.Code = dns.EDNS0COOKIE
		e.Cookie = tc.in
		opt.Option = append(opt.Option, e)
		query.Extra = append(query.Extra, opt)

		out.Reset()
		server.ServeDNS(wtr, query)

		resp := wtr.Get()
		if resp == nil {
			t.Fatal(ix, "Setup error - No response to cookie query")
		}
		s := out.String()

		if resp.Rcode != tc.rcode {
			t.Error(ix, "Wrong rcode. Expected", dnsutil.RcodeToString(tc.rcode),
				"got", dnsutil.RcodeToString(resp.Rcode))
			t.Log(s)
		}
		if len(tc.out) > 0 {
			opt = resp.IsEdns0()
			if opt == nil {
				t.Fatal(ix, "OPT Missing from response")
			}
			var so *dns.EDNS0_COOKIE
			var ok bool
			for _, subopt := range opt.Option {
				if so, ok = subopt.(*dns.EDNS0_COOKIE); ok {
					break
				}
			}
			if so == nil {
				t.Fatal(ix, "dns.EDNS0_COOKIE not in OPT")
			}
			if !strings.Contains(so.Cookie, tc.out) {
				t.Error(ix, "Out mis-match. Expect:", tc.out, "in", so.Cookie)
				t.Log(s)
			}
		}

		if !strings.Contains(s, tc.note) {
			t.Error(ix, "Wrong lognote. Expected", tc.note)
			t.Log(s)
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

// Similar to dns.SetQuestion but allow Class and force ID so test comparisons are easier.
func setQuestion(c, t uint16, z string) *dns.Msg {
	q := new(dns.Msg)
	q.Id = 1
	q.Question = append(q.Question,
		dns.Question{Name: dns.CanonicalName(z), Qclass: c, Qtype: t})

	return q
}
