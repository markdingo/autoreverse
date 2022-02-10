package main

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/mock"
)

func TestFindNSID(t *testing.T) {
	query := setQuestion(dns.ClassINET, dns.TypeA, "localhost.")
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	e := new(dns.EDNS0_NSID)
	o.Option = append(o.Option, e)
	query.Extra = append(query.Extra, o)
	req := newRequest(query, nil, "udp")
	req.opt = o

	nsid := req.findNSID()
	if nsid == nil {
		t.Error("Failed to find NSID opt")
	}
}

func TestGenOpt(t *testing.T) {
	query := setQuestion(dns.ClassINET, dns.TypeA, "localhost.")
	req := newRequest(query, nil, "udp")
	o := req.genOpt()
	if o != nil {
		t.Error("Did not expect an OPT with no settings")
	}

	req.maxSize = 800
	req.nsidOut = "abcd"
	cCookie, _ := hex.DecodeString("0123456789abcdef")
	sCookie, _ := hex.DecodeString("abcdef0123456789")
	req.cookieOut = cCookie
	req.cookieOut = append(req.cookieOut, sCookie...)
	o = req.genOpt()
	if o == nil {
		t.Fatal("Expected an OPT")
	}
	req.opt = o

	mz := req.opt.UDPSize()
	if mz != 800 {
		t.Error("UDPSize did not make it to OPT", mz)
	}

	e := req.findNSID()
	if e == nil {
		t.Error("Expected to find NSID sub-opt")
	} else {
		nsid := e.Nsid
		if nsid != "abcd" {
			t.Error("NSID mismatch. Exp: abcd, Got:", nsid)
		}
	}

	req.findCookies()
	if !req.cookiesPresent {
		t.Error("Cookies should be present")
	}
	if bytes.Compare(req.clientCookie, cCookie) != 0 {
		t.Errorf("Client cookie did not transfer %x", req.clientCookie)
	}
	if bytes.Compare(req.serverCookie, sCookie) != 0 {
		t.Errorf("Server cookie did not transfer %x", req.serverCookie)
	}
}

func TestGenV1Cookie(t *testing.T) {
	ip := "0.0.0.0:53"
	var secrets [2]uint64
	var clock uint32
	var cCookie [8]byte
	got := genV1Cookie(secrets, clock, ip, cCookie[:])
	expect, _ := hex.DecodeString("000000000000000001000000000000009cfc753b7275ad7f")
	if bytes.Compare(got, expect[:]) != 0 {
		t.Errorf("Zero-value cookie wrong. Expected: %x Got %x\n", expect, got)
	}

	clock++
	got = genV1Cookie(secrets, clock, ip, cCookie[:])
	if bytes.Compare(got, expect[:]) == 0 {
		t.Errorf("Clock-tick cookie should have changed")
	}
	clock = 0

	secrets[0] = 1
	got = genV1Cookie(secrets, clock, ip, cCookie[:])
	if bytes.Compare(got, expect[:]) == 0 {
		t.Errorf("New secrets cookie should have changed")
	}
	secrets[0] = 0

	ip = "0.0.0.1:53"
	got = genV1Cookie(secrets, clock, ip, cCookie[:])
	if bytes.Compare(got, expect[:]) == 0 {
		t.Errorf("New IP cookie should have changed")
	}
	ip = "0.0.0.0:53"

	cCookie[0] = 1
	got = genV1Cookie(secrets, clock, ip, cCookie[:])
	if bytes.Compare(got, expect[:]) == 0 {
		t.Errorf("New cCookie cookie should have changed")
	}
	cCookie[0] = 0
}

func TestValidateOrGenerate(t *testing.T) {
	testCases := []struct {
		ipv4           bool
		client, server string
		unixTime       int64
		valid          bool
		output         string
	}{
		{true, "0123456789abcdef", "", 0x2000, false, // No sCookie
			"0123456789abcdef010000000000200078f6dcfbf17e8504"},

		{true, "0123456789abcdef", "010000000000200078f6dcfbf17e8504", 0x2000, true,
			"0123456789abcdef010000000000200078f6dcfbf17e8504"}, // Correct sCookie

		// TS is within range, but is GT reissue gap so a new cookie is expected
		{true, "0123456789abcdef", "010000000000200078f6dcfbf17e8504",
			0x2000 + maxBehindGap - 1, true,
			"0123456789abcdef0100000000002e0f2ef2835de77f0e45"},

		// TS is too old, should fail and get a new cookie
		{true, "0123456789abcdef", "010000000000200078f6dcfbf17e8504",
			0x2000 + maxBehindGap + 1, false,
			"0123456789abcdef0100000000002e113c19eb1777e9d7e0"},

		{true, "0123456789abcdef", "0200000000001000e99b04f5b59e5343", 0x2000, false, // Version
			"0123456789abcdef010000000000200078f6dcfbf17e8504"},

		{true, "0123456789abcdef", "0101000000001000e99b04f5b59e5343", 0x2000, false, // RFFU
			"0123456789abcdef010000000000200078f6dcfbf17e8504"},

		// IPV6
		{false, "0123456789abcdef", "", 0x2000, false, // No sCookie
			"0123456789abcdef010000000000200091992114bd52a849"},

		{false, "0123456789abcdef", "010000000000200091992114bd52a849", 0x2000, true,
			"0123456789abcdef010000000000200091992114bd52a849"}, // Correct sCookie
	}

	var secrets [2]uint64
	for ix, tc := range testCases {
		query := setQuestion(dns.ClassCHAOS, dns.TypeTXT, "version.bind.")
		var ip string
		if tc.ipv4 {
			ip = "127.0.0.1:53"
		} else {
			ip = "[::1]:4051"
		}
		src := mock.NewNetAddr("udp", ip)
		req := newRequest(query, src, "udp")
		req.clientCookie, _ = hex.DecodeString(tc.client)
		req.serverCookie, _ = hex.DecodeString(tc.server)
		v := req.validateOrGenerateCookie(secrets, tc.unixTime)
		if v != tc.valid {
			t.Error("Err", ix, "Valid mismatch. Expected", tc.valid)
		}
		if len(tc.output) > 0 { // Is output expected?
			exp, _ := hex.DecodeString(tc.output)
			if bytes.Compare(exp, req.cookieOut) != 0 {
				t.Errorf("Err %d cookieOut mismatch. Got %x. Exp %s\n",
					ix, req.cookieOut, tc.output)
			}
		}
	}
}

func TestNormalizeTimestamps(t *testing.T) {
	testCases := []struct {
		ourClock, theirClock uint32
		oursGreater          bool
	}{
		{0x10, 0x2, true},       // Regular values - no wrap
		{0x80000001, 0x2, true}, // ours-theirs is one shy of wrapDistance

		{0x80000007, 0x7, false}, // ours-theirs equals wrapDistance
		{0x7, 0x80000007, false}, // The undefined cases mentioned in in rfc1982

		{0x80000102, 0x100, true}, // ours-theirs > wrapDistance

		{0x2, 0x80000001, false}, // Test bottom half of conditional
		{0x100, 0x80000102, false},
		{0x100, 0x80000102, false},
	}

	for ix, tc := range testCases {
		ourClock64, theirClock64 := normalizeTimestamps(tc.ourClock, tc.theirClock)
		if tc.oursGreater {
			if ourClock64 <= theirClock64 {
				t.Error(ix, ourClock64, "Not Greater", theirClock64)
			}
		} else {
			if ourClock64 > theirClock64 {
				t.Error(ix, ourClock64, "Is Greater", theirClock64)
			}
		}
	}
}

// 82 ns/op on a mac m1, so pretty fast
func BenchmarkGenV1Cookie(b *testing.B) {
	ip := "0.0.0.0:53"
	var secrets [2]uint64
	var clock uint32
	var cCookie [8]byte
	for i := 0; i < b.N; i++ {
		genV1Cookie(secrets, clock, ip, cCookie[:])
	}
}
