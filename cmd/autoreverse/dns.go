package main

import (
	"encoding/hex"
	"fmt"
	"time"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/log"
)

// Called from miekg - handles all DNS queries. All query logic is embedded in this one
// rather large function.
func (t *server) ServeDNS(wtr dns.ResponseWriter, query *dns.Msg) {
	req := newRequest(query, wtr.RemoteAddr(), t.network)
	req.stats.gen.queries++

	if t.cfg.logQueriesFlag {
		defer req.log()
	}
	defer t.addStats(&req.stats) // Add req.stats to t.stats

	// Validate query. Extra can have EDNS options so don't length check that slice.
	// As of RFC7873 a query with no questions and a COOKIE OPT is valid but we don't
	// do cookies yet, so treat it as invalid.
	//
	// miekg.DefaultMsgAcceptFunc does some checking prior to the query arriving here,
	// but we are slightly more paranoid.
	if len(req.query.Question) > 0 {
		req.question = req.query.Question[0]           // Populate early for logger
		req.qName = strings.ToLower(req.question.Name) // Normalize
		req.logQName = req.qName                       // Can override with compact qName
	}

	req.opt = req.query.IsEdns0() // Extract Opt values nice and early

	if (len(t.cfg.nsid) > 0) && (req.findNSID() != nil) {
		req.nsidOut = t.cfg.nsidAsHex
	}

	// We don't really do much with cookies yet apart from exchange them with clients
	// and note whether they are correct or not. Mostly this is laying the ground-work
	// so that it's easy to add differentiation later.

	req.findCookies()
	if req.cookiesPresent {
		req.stats.gen.cookie++
		if !req.cookieWellFormed { // This means the OPT is malformed
			req.response.SetRcodeFormatError(query)
			t.writeMsg(wtr, req)
			req.stats.gen.formatError++
			req.addNote("Malformed cookie")
			return
		}
		if !req.validateOrGenerateCookie(t.cookieSecrets, time.Now().Unix()) {
			if len(req.serverCookie) > 0 {
				req.addNote("Server cookie mismatch")
				req.stats.gen.wrongCookie++
			}
		}
		req.stats.gen.cookie++
		log.Majorf("Cookies: qo=%t C=(%d) %s S=(%d) %s out=%s",
			len(req.query.Question) == 0,
			len(req.clientCookie), hex.EncodeToString(req.clientCookie),
			len(req.serverCookie), hex.EncodeToString(req.serverCookie),
			hex.EncodeToString(req.cookieOut))
	}

	// Is this a cookie-only request?
	if len(req.clientCookie) > 0 && len(req.serverCookie) == 0 && len(req.query.Question) == 0 {
		req.response.SetReply(query)
		t.writeMsg(wtr, req)
		req.addNote("Cookie-only query")
		return
	}

	// After the weird cookie-request, we now only accept "normal" queries
	if len(req.query.Question) != 1 ||
		len(req.query.Answer) != 0 ||
		len(req.query.Ns) != 0 ||
		req.query.Opcode != dns.OpcodeQuery {
		req.response.SetRcodeFormatError(query)
		t.writeMsg(wtr, req)
		req.stats.gen.formatError++
		req.addNote("Malformed Query")
		return
	}

	// If query contains a UDP size value, use it if it's reasonable
	if t.network == dnsutil.UDPNetwork {
		req.maxSize = dnsutil.MaxUDPSize // Default unless over-ridden
		if req.opt != nil {
			mz := req.opt.UDPSize()
			if (mz > 512) && (mz <= dnsutil.MaxUDPSize) { // Reasonable?
				req.maxSize = mz
			}
		}
	}

	req.ptrDB = t.dbGetter.Current() // Final setup for request prior to dispatching
	req.mutables = t.getMutables()   // Get current mutables from server instance

	// Pre-processing checks and setup is complete. The order of dispatching is: probe
	// queries first followed by chaos followed by regular queries.

	// Probes can be sent multiple times and this function responds possitively each
	// time. Whether probes are oneshot or multishot process is determined by probe
	// senders not probe receivers. And probe senders do that be modifying the
	// mutables.
	//
	// It's important that if the probe doesn't match, the query continues on with the
	// regular query processing as a partially established autoreverse instance may be
	// necessary to answer forward queries while working out authority for the reverse
	// zone. This is particularly likely when the forward and reverse are serviced by
	// the same name server - which is expected to be common in the autoreverse case.

	if req.probe != nil {
		if req.probe.QuestionMatches(req.question) {
			log.Minor("Valid Probe received from ", req.src)
			req.addNote("Probe match")
			req.response.SetReply(req.query)
			req.response.Answer = append(req.response.Answer, req.probe.Answer())
			t.writeMsg(wtr, req)
			return
		}
		req.addNote("Non-probe query during prone")
	}

	// Chaos helps check reachability thru firewalls, port forwarding and whatnot.

	if t.cfg.chaosFlag &&
		req.question.Qclass == dns.ClassCHAOS &&
		req.question.Qtype == dns.TypeTXT {
		t.serveCHAOS(wtr, req)
		req.stats.gen.chaos++
		return
	}

	// All special-case dispatching is complete. All legitimate queries must now be in
	// a zone of authority which is only ever in ClassINET. This following test is one
	// of the reasons why passthru is INET-only. These tests *could* be rearranged to
	// allow passthru of other classes, but why bother? The focus is more about
	// autoreverse processing.

	if req.question.Qclass != dns.ClassINET { // Only serve INET henceforth
		req.addNote(fmt.Sprintf("Wrong class %s",
			dnsutil.ClassToString(dns.Class(req.question.Qclass))))
		t.serveRefused(wtr, req)
		req.stats.gen.wrongClass++
		return
	}

	req.setAuthority()
	if req.auth == nil { // One of our domains?
		if len(t.cfg.passthru) > 0 { // Nope - do we passthru?
			t.passthru(wtr, req)
		} else {
			req.addNote("out of bailiwick")
			t.serveRefused(wtr, req)
			req.stats.gen.noAuthority++
		}
		return
	}

	switch req.question.Qtype { // Normal Query Dispatch
	case dns.TypeANY:
		if req.qName == req.auth.Domain {
			req.response.SetRcode(req.query, dns.RcodeSuccess)
			req.response.Answer = append(req.response.Answer, &req.auth.SOA)
			req.stats.gen.authZoneANY++
			t.writeMsg(wtr, req)
			return
		}

	case dns.TypeSOA:
		if req.qName == req.auth.Domain {
			req.response.SetRcode(req.query, dns.RcodeSuccess)
			req.response.Answer = append(req.response.Answer, &req.auth.SOA)
			req.response.Ns = append(req.response.Ns, req.auth.NS...)
			req.response.Extra = append(req.response.Extra, req.auth.A...)
			req.response.Extra = append(req.response.Extra, req.auth.AAAA...)
			req.stats.gen.authZoneSOA++
			t.writeMsg(wtr, req)
			return
		}

	case dns.TypeNS:
		if req.qName == req.auth.Domain {
			req.response.SetRcode(req.query, dns.RcodeSuccess)
			req.response.Answer = append(req.response.Ns, req.auth.NS...)
			req.response.Extra = append(req.response.Extra, req.auth.A...)
			req.response.Extra = append(req.response.Extra, req.auth.AAAA...)
			req.stats.gen.authZoneNS++
			t.writeMsg(wtr, req)
			return
		}

	case dns.TypePTR:
		if t.servePTR(wtr, req) {
			return
		}

	case dns.TypeA:
		if t.MatchQNameAndServe(wtr, req, req.auth.A) {
			req.stats.gen.authZoneA++
			return
		}
		if t.cfg.synthesizeFlag && t.serveA(wtr, req) {
			return
		}

	case dns.TypeAAAA:
		if t.MatchQNameAndServe(wtr, req, req.auth.AAAA) {
			req.stats.gen.authZoneAAAA++
			return
		}
		if t.cfg.synthesizeFlag && t.serveAAAA(wtr, req) {
			return
		}
	}

	// In our authority, but nothing we recognize - ergo NXDomain

	t.serveNXDomain(wtr, req)
}

func (t *server) serveRefused(wtr dns.ResponseWriter, req *request) {
	req.response.SetRcode(req.query, dns.RcodeRefused)
	t.writeMsg(wtr, req)
}

func (t *server) serveNXDomain(wtr dns.ResponseWriter, req *request) {
	req.response.SetRcode(req.query, dns.RcodeNameError)
	req.response.Ns = append(req.response.Ns, &req.auth.SOA)
	t.writeMsg(wtr, req)
	req.stats.gen.nxDomain++
}

// Expecting 192-0-2-1.Domain. Unlike ipv6, there is no compression of the IP address to
// cover multiple zero octets, which makes parsing simpler. IOWs, 192.0.0.1 does not get
// converted into 192--1.
//
// We are expecting just synthetic names but mdns programs tend to generate a bunch of
// oddball queries such as lb._dns-sd._udp.128.2.0.192.in-addr.arpa which are
// in-bailiwick, but if we don't get a match that we can serve, let the caller deal with.
//
// Return true if the query was answered.
func (t *server) serveA(wtr dns.ResponseWriter, req *request) bool {
	statsp := &req.stats.AForward
	statsp.queries++

	hostname := strings.TrimSuffix(req.qName, "."+req.auth.Domain)
	if strings.Index(hostname, ".") >= 0 { // Don't allow 192.0.2.0.domain - should be 192-0-2-0.domain
		statsp.malformed++
		return false
	}
	ipStr := strings.ReplaceAll(hostname, "-", ".")
	ip := net.ParseIP(ipStr)
	if ip == nil { // Couldn't convert back into an ip address
		statsp.malformed++
		return false
	}
	ip = ip.To4()
	if ip == nil {
		statsp.malformed++
		return false
	}
	if len(ip) != net.IPv4len {
		statsp.malformed++
		return false
	}

	req.response.SetReply(req.query)
	rr := new(dns.A)
	rr.Hdr.Name = req.question.Name
	rr.Hdr.Class = req.question.Qclass
	rr.Hdr.Rrtype = req.question.Qtype
	rr.Hdr.Ttl = t.cfg.TTLAsSecs
	rr.A = ip
	req.response.Answer = append(req.response.Answer, rr)
	t.writeMsg(wtr, req)
	statsp.good++
	statsp.answers += len(req.response.Answer)

	return true
}

// Expecting 2001-db83--1.domain. Convert the synthetic name back into an IP address and
// reply with an AAAA.
//
// Return true if the query was answered.
func (t *server) serveAAAA(wtr dns.ResponseWriter, req *request) bool {
	statsp := &req.stats.AAAAForward
	statsp.queries++

	hostname := strings.TrimSuffix(req.qName, "."+req.auth.Domain)

	if strings.Index(hostname, ":") >= 0 { // Don't allow fd00::1.domain - should be fd00--1.domain
		statsp.malformed++
		return false
	}

	ipStr := strings.ReplaceAll(hostname, "-", ":")
	ip := net.ParseIP(ipStr)
	if ip == nil { // Couldn't convert back into an ip address
		statsp.malformed++
		return false
	}
	if len(ip) != net.IPv6len {
		statsp.malformed++
		return false
	}

	req.response.SetReply(req.query)
	rr := new(dns.AAAA)
	rr.Hdr.Name = req.question.Name
	rr.Hdr.Class = req.question.Qclass
	rr.Hdr.Rrtype = req.question.Qtype
	rr.Hdr.Ttl = t.cfg.TTLAsSecs
	rr.AAAA = ip
	req.response.Answer = append(req.response.Answer, rr)
	t.writeMsg(wtr, req)
	statsp.good++
	statsp.answers += len(req.response.Answer)

	return true
}

// Expecting the usual reverse syntax. Return true if we answered the question, otherwise
// let the caller deal with any subsequent processing. The PTR database is consulted first
// to see if there are deduced PTRs for this qName. If no database entries are found *and*
// the config allows synthetic responses, generate one.
func (t *server) servePTR(wtr dns.ResponseWriter, req *request) bool {
	var (
		reverseIPStr string
		ip           net.IP
		err          error
		ar           []dns.RR
		statsp       *queryStats
	)

	switch {
	case strings.HasSuffix(req.qName, dnsutil.V4Suffix):
		statsp = &req.stats.APtr
		statsp.queries++
		reverseIPStr = strings.TrimSuffix(req.qName, dnsutil.V4Suffix)
		ip, err = dnsutil.InvertPtrToIPv4(reverseIPStr)
		if err == nil {
			ar = req.ptrDB.Lookup(ip.String())
		}

	case strings.HasSuffix(req.qName, dnsutil.V6Suffix):
		statsp = &req.stats.AAAAPtr
		statsp.queries++
		reverseIPStr = strings.TrimSuffix(req.qName, dnsutil.V6Suffix)
		ip, err = dnsutil.InvertPtrToIPv6(reverseIPStr)
		if err == nil {
			ar = req.ptrDB.Lookup(ip.String())
		}

	default: // Unexpected suffix - Dispatcher should not have let this in
		log.Major("Danger:Dispatcher should never let in ", req.qName)
		req.response.SetRcodeFormatError(req.query)
		t.writeMsg(wtr, req)
		req.stats.gen.formatError++
		req.addNote("bad Mux")
		return true
	}

	if err != nil { // Reverse IP address could not be parsed from qName
		statsp.malformed++ // Not really malformed in the general sense, just our sense
		return false       // Punt to caller
	}

	req.logQName = ip.String() // Log a more compact variant
	if len(ar) == 0 {          // If database returned zero PTRs
		if t.cfg.synthesizeFlag { // and config allows synthesis, then make one up!
			ar = append(ar,
				dnsutil.SynthesizePTR(req.qName, req.mutables.ptrSuffix, ip))
			req.addNote("Synth")
		} else {
			req.addNote("No Synth")
			t.serveNXDomain(wtr, req)
			statsp.noSynth++
			return true
		}
	}

	// The slice "ar" now contains all the candidate answers. Set TTLs for RRs that
	// are at zero and restrict count to the maximum allowed. The writeMsg() function
	// worries about message truncation.
	req.response.SetReply(req.query)
	for _, rr := range ar {
		if t.cfg.maxAnswers <= 0 || len(req.response.Answer) < t.cfg.maxAnswers {
			if rr.Header().Ttl == 0 {
				rr.Header().Ttl = t.cfg.TTLAsSecs
			}
			req.response.Answer = append(req.response.Answer, rr)
		}
	}

	// Truncate msg to fit max size. Only relevant if connection is UDP.
	if req.maxSize > 0 {
		req.response.Truncate(int(req.maxSize)) // Removes excess RRs and sets TC=1 if needed
	}

	t.writeMsg(wtr, req)
	statsp.good++
	statsp.answers += len(req.response.Answer)

	return true
}

// Add matching RRs to the response and send. If any RRs match, return true. If no RRs
// match, don't send and return false.
func (t *server) MatchQNameAndServe(wtr dns.ResponseWriter, req *request, rrs []dns.RR) bool {
	for _, rr := range rrs {
		if rr.Header().Name == req.qName {
			req.response.Answer = append(req.response.Answer, rr)
		}
	}

	if len(req.response.Answer) == 0 {
		return false
	}

	req.response.SetRcode(req.query, dns.RcodeSuccess)
	t.writeMsg(wtr, req)

	return true
}

// writeMsg finalized the output message with all of the common processing then calls
// the response writer to send the message. Any error is recorded in req.logError
func (t *server) writeMsg(wtr dns.ResponseWriter, req *request) {
	opt := req.genOpt()
	if opt != nil {
		req.response.Extra = append(req.response.Extra, opt)
	}

	req.response.Authoritative = true

	req.msgSize = req.response.Len() // Transfer to Stats for reporting purposes
	req.compressed = req.response.Compress
	req.truncated = req.response.MsgHdr.Truncated

	err := wtr.WriteMsg(req.response)
	if err != nil {
		req.logError = fmt.Errorf("WriteMsg failed: %s", dnsutil.ShortenLookupError(err))
	}
}
