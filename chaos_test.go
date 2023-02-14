package main

import (
	"testing"

	"github.com/markdingo/autoreverse/database"
	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
	"github.com/markdingo/autoreverse/resolver"

	"github.com/miekg/dns"
)

func TestDNSChaos(t *testing.T) {
	cfg := &config{logQueriesFlag: true, projectURL: "projectURL",
		nsid: "nsid1", TTLAsSecs: 60, chaosFlag: true}
	expect := commonCHAOSPrefix + " " + cfg.projectURL
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MajorLevel)

	wtr := &mock.ResponseWriter{}
	res := resolver.NewResolver()
	ar := newAutoReverse(cfg, res)
	newDB := database.NewDatabase()
	ar.loadFromChaos(newDB)
	ar.dbGetter.Replace(newDB)
	server := newServer(cfg, ar.dbGetter, res, nil, "", "")

	// First try with wrong type
	query := setQuestion(dns.ClassCHAOS, dns.TypeNS, "version.bind.")
	server.ServeDNS(wtr, query)
	resp := wtr.Get()
	if resp == nil {
		t.Fatal("Setup error - No response to chaos query")
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Error("Expected RcodeRefused, not", dns.RcodeToString[wtr.Get().Rcode])
	}

	// Check error logging
	exp := "ru=REFUSED q=NS/version.bind. s=127.0.0.2:4056 id=1 h=U sz=41/1232 C=0/0/1\n"
	got := out.String()
	if exp != got {
		t.Error("Error log mismatch. \n Got:", got, "Exp:", exp)
	}

	// Check not chaos flag set

	cfg.chaosFlag = false
	out.Reset()
	query = setQuestion(dns.ClassCHAOS, dns.TypeTXT, "version.bind.")
	query.Id = 2
	server.ServeDNS(wtr, query)
	resp = wtr.Get()
	if resp == nil {
		t.Fatal("Setup error - No response to chaos query")
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Error("Expected RcodeRefused, not", dnsutil.RcodeToString(resp.Rcode))
	}

	// Check error logging
	exp = "ru=REFUSED q=TXT/version.bind. s=127.0.0.2:4056 id=2 h=U sz=41/1232 C=0/0/1 not in-domain\n"
	got = out.String()
	if exp != got {
		t.Error("Error log mismatch \n Got:", got, "Exp:", exp)
	}

	// Now with flag set

	out.Reset()
	cfg.chaosFlag = true

	testCases := []struct{ in, out string }{
		{"version.bind.", expect},
		{"version.server.", expect},
		{"authors.bind.", expect},
		{"hostname.bind.", "nsid1"},
		{"id.server.", "nsid1"},
		{"nope", ""},
	}

	for ix, tc := range testCases {
		query = setQuestion(dns.ClassCHAOS, dns.TypeTXT, tc.in)
		query.Id = uint16(3 + ix)
		server.ServeDNS(wtr, query)
		resp = wtr.Get()
		if resp == nil {
			t.Fatal(ix, "Setup error - No response to chaos query")
		}
		if resp.Rcode != dns.RcodeSuccess {
			if len(tc.out) > 0 { // Expect an error if no response expected
				t.Error(ix,
					"Expected RcodeSuccess, not",
					dnsutil.RcodeToString(resp.Rcode))
			}
			continue
		}

		if len(resp.Answer) != 1 {
			t.Error(ix, "Wrong number of answers", len(resp.Answer))
			continue
		}
		ans := resp.Answer[0]
		if txt, ok := ans.(*dns.TXT); ok {
			if len(txt.Txt) != 1 {
				t.Error(ix, "Wrong TXT count", len(txt.Txt))
				continue
			}
			if txt.Txt[0] != tc.out {
				t.Error(ix, "Response not as expected: got", txt.Txt[0], "exp", tc.out)
			}
		} else {
			t.Error(ix, "Did not get a TXT answer", ans)
		}
	}

	// Check logging to confirm responses - good enough
	exp = `ru=ok q=TXT/version.bind. s=127.0.0.2:4056 id=3 h=U sz=106/1232 C=1/0/1
ru=ok q=TXT/version.server. s=127.0.0.2:4056 id=4 h=U sz=110/1232 C=1/0/1
ru=ok q=TXT/authors.bind. s=127.0.0.2:4056 id=5 h=U sz=106/1232 C=1/0/1
ru=ok q=TXT/hostname.bind. s=127.0.0.2:4056 id=6 h=U sz=73/1232 C=1/0/1
ru=ok q=TXT/id.server. s=127.0.0.2:4056 id=7 h=U sz=65/1232 C=1/0/1
ru=REFUSED q=TXT/nope. s=127.0.0.2:4056 id=8 h=U sz=33/1232 C=0/0/1
`
	got = out.String()
	if exp != got {
		t.Error("Log mismatch\ngot >>"+got+"<<\nexp >>"+exp+"<<", len(got), len(exp))
	}
}
