package main

import (
	"math/rand"
	"strings"
	"testing"

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
func TestFormErr(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	server := newServer(&config{logQueriesFlag: true}, database.NewGetter(), resolver.NewResolver(), "", "") // Make a skeletal server
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

func TestProbe(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MinorLevel)

	res := resolver.NewResolver()
	cfg := &config{logQueriesFlag: true}
	server := newServer(cfg, database.NewGetter(), res, "", "")
	rand.Seed(0) // Make probe generation predictable
	a1 := &delegation.Authority{Domain: "fozzy.example.net."}
	pr := delegation.NewForwardProbe(a1.Domain)
	auths := make([]*delegation.Authority, 0, 1)
	auths = append(auths, a1)
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
	exp := `ru=REFUSED q=MX/example.org. s=127.0.0.2:4056 id=2 h=U sz=40/1232 C=0/0/1 Non-probe query during prone:out of bailiwick
  Valid Probe received from 127.0.0.2:4056
ru=ok q=AAAA/cubyh.fozzy.example.net. s=127.0.0.2:4056 id=1 h=U sz=103/1232 C=1/0/1 Probe match
`

	got := out.String()
	if got != exp {
		t.Error("Log data differs. Got:", got, "Exp:", exp)
	}

}

func TestWrongClass(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MajorLevel)

	wtr := &mock.ResponseWriter{}

	res := resolver.NewResolver()
	cfg := &config{logQueriesFlag: true}
	server := newServer(cfg, database.NewGetter(), res, "", "")

	// First try with an invalid type
	query := setQuestion(dns.ClassHESIOD, dns.TypeNS, "ns.hs.")
	server.ServeDNS(wtr, query)
	resp := wtr.Get()
	if resp == nil {
		t.Fatal("Setup error - No response to HESIOD query")
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Error("Expected RcodeRefused, not", dnsutil.RcodeToString(resp.Rcode))
	}

	// Check error logging
	exp := "ru=REFUSED q=NS/ns.hs. s=127.0.0.2:4056 id=1 h=U sz=34/1232 C=0/0/1 Wrong class HS\n"
	got := out.String()
	if exp != got {
		t.Error("Error log mismatch. Got:", got, "Exp:", exp)
	}

	out.Reset()
	query = setQuestion(2021, dns.TypeA, "2021.A.")
	server.ServeDNS(wtr, query)
	resp = wtr.Get()
	if resp == nil {
		t.Fatal("Setup error - No response to Class 2021 query")
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Error("Expected RcodeRefused, not", dnsutil.RcodeToString(resp.Rcode))
	}

	// Check error logging
	exp = "ru=REFUSED q=A/2021.a. s=127.0.0.2:4056 id=1 h=U sz=35/1232 C=0/0/1 Wrong class C-2021\n"
	got = out.String()
	if exp != got {
		t.Error("Error log mismatch. Got:", got, "Exp:", exp)
	}
}

const (
	nsidAsText = "Jammin"
	nsidAsHex  = "4a616d6d696e"
)

func TestServeBadPTR(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MajorLevel)

	wtr := &mock.ResponseWriter{}

	res := resolver.NewResolver()
	cfg := &config{logQueriesFlag: true, synthesizeFlag: true}
	server := newServer(cfg, database.NewGetter(), res, "", "")
	a1 := &delegation.Authority{Domain: "misc.example.net."}
	a2 := &delegation.Authority{Domain: "f.f.f.f.d.2.d.f.ip6.arpa."}
	a3 := &delegation.Authority{Domain: "2.0.192.in-addr.arpa."}

	server.setMutables("", nil, []*delegation.Authority{a1, a2, a3})

	query := setQuestion(dns.ClassINET, dns.TypePTR, "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa.")
	server.ServeDNS(wtr, query)
	resp := wtr.Get()
	if resp == nil {
		t.Error("Setup error - No response to PTR query")
	} else if resp.Rcode != dns.RcodeNameError {
		t.Error("Expected RcodeNameError, not", dnsutil.RcodeToString(resp.Rcode))
	}

	cfg.synthesizeFlag = false
	query = setQuestion(dns.ClassINET, dns.TypePTR, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa")
	server.ServeDNS(wtr, query)
	resp = wtr.Get()
	if resp == nil {
		t.Error("Setup error - No response to PTR query")
	} else if resp.Rcode != dns.RcodeNameError {
		t.Error("Expected RcodeNameError, not", dnsutil.RcodeToString(resp.Rcode))
	}

	// Check logging
	exp := `ru=NXDOMAIN q=PTR/0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa. s=127.0.0.2:4056 id=1 h=U sz=130/1232 C=0/1/1
ru=NXDOMAIN q=PTR/fd2d:ffff::1 s=127.0.0.2:4056 id=1 h=U sz=134/1232 C=0/1/1 No Synth
`

	got := out.String()
	if exp != got {
		t.Error("TestServeBadPTR log mismatch got:", got, "exp:", exp)
	}
}

// NSID, UDPsize and any other corner cases that come to mind
func TestMisc(t *testing.T) {
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

	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MajorLevel)

	wtr := &mock.ResponseWriter{}

	res := resolver.NewResolver()
	cfg := &config{logQueriesFlag: true, chaosFlag: true, synthesizeFlag: true,
		nsid: nsidAsText, nsidAsHex: nsidAsHex}
	cfg.generateNSIDOpt()
	server := newServer(cfg, database.NewGetter(), res, "", "")

	a1 := &delegation.Authority{Domain: "misc.example.net."}
	auths := make([]*delegation.Authority, 0, 1)
	auths = append(auths, a1)
	server.setMutables("", nil, auths)

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

func TestGoodAnswers(t *testing.T) {
	var testCases = []struct {
		qType  uint16
		qName  string
		expect dns.RR
	}{
		{dns.TypePTR, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa.",
			newRR("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa. IN PTR fd2d-ffff--1.a.zig.")},
		{dns.TypePTR, "2.0.0.0.0.0.0.0.0.0.0.0.0.f.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa.",
			newRR("2.0.0.0.0.0.0.0.0.0.0.0.0.f.0.0.0.0.0.0.0.0.0.0.f.f.f.f.d.2.d.f.ip6.arpa. IN PTR fd2d-ffff--f0-0-0-2.a.zig.")},

		{dns.TypePTR, "1.2.0.192.in-addr.arpa.",
			newRR("1.2.0.192.in-addr.arpa. IN PTR 192-0-2-1.a.zig.")},
		{dns.TypePTR, "254.2.0.192.in-addr.arpa.",
			newRR("254.2.0.192.in-addr.arpa. IN PTR 192-0-2-254.a.zig.")},

		{dns.TypeA, "192-0-2-1.a.zig.", newRR("192-0-2-1.a.zig. IN A 192.0.2.1")},
		{dns.TypeA, "192-0-2-254.a.zig.", newRR("192-0-2-254.a.zig. IN A 192.0.2.254")},

		{dns.TypeAAAA, "fd2d-ffff--1.a.zig.", newRR("fd2d-ffff--1.a.zig. IN AAAA fd2d:ffff::1")},
		{dns.TypeAAAA, "fd2d-ffff--f0-0-0-2.a.zig.", newRR("fd2d-ffff--f0-0-0-2.a.zig. IN AAAA fd2d:ffff::f0:0:0:2")},
	}

	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MajorLevel)

	wtr := &mock.ResponseWriter{}

	res := resolver.NewResolver()
	cfg := &config{logQueriesFlag: true, synthesizeFlag: true, delegatedForward: "a.zig.", TTLAsSecs: 3600}
	server := newServer(cfg, database.NewGetter(), res, "", "")
	a1 := &delegation.Authority{Domain: cfg.delegatedForward}
	a2 := &delegation.Authority{Domain: "f.f.f.f.d.2.d.f.ip6.arpa."}
	a3 := &delegation.Authority{Domain: "2.0.192.in-addr.arpa."}

	server.setMutables("a.zig.", nil, []*delegation.Authority{a1, a2, a3})

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
			t.Error(ix, "Wrong PTR returned. Exp", tc.expect, "Got", ans)
		}
	}

	// Check logs
	exp := `ru=ok q=PTR/fd2d:ffff::1 s=127.0.0.2:4056 id=10 h=U sz=205/1232 C=1/0/1 Synth
ru=ok q=PTR/fd2d:ffff::f0:0:0:2 s=127.0.0.2:4056 id=11 h=U sz=212/1232 C=1/0/1 Synth
ru=ok q=PTR/192.0.2.1 s=127.0.0.2:4056 id=12 h=U sz=102/1232 C=1/0/1 Synth
ru=ok q=PTR/192.0.2.254 s=127.0.0.2:4056 id=13 h=U sz=108/1232 C=1/0/1 Synth
ru=ok q=A/192-0-2-1.a.zig. s=127.0.0.2:4056 id=14 h=U sz=75/1232 C=1/0/1
ru=ok q=A/192-0-2-254.a.zig. s=127.0.0.2:4056 id=15 h=U sz=79/1232 C=1/0/1
ru=ok q=AAAA/fd2d-ffff--1.a.zig. s=127.0.0.2:4056 id=16 h=U sz=93/1232 C=1/0/1
ru=ok q=AAAA/fd2d-ffff--f0-0-0-2.a.zig. s=127.0.0.2:4056 id=17 h=U sz=107/1232 C=1/0/1
`
	got := out.String()
	if exp != got {
		t.Error("PTR log mismatch. Exp", exp, "Got", got)
	}
}

func TestCookies(t *testing.T) {
	var testCases = []struct {
		addQuery bool
		in, out  string
		rcode    int
		note     string
	}{
		{false, "0123456789abcdef", "", dns.RcodeSuccess, "Cookie-only"},
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
	server := newServer(cfg, database.NewGetter(), res, "", "")
	server.setMutables("", nil, []*delegation.Authority{})

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
