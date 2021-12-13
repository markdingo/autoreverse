package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/log"
)

// Called from miekg - handles all DNS queries. All query logic is embedded in this one
// rather large function.
func (t *server) ServeDNS(wtr dns.ResponseWriter, query *dns.Msg) {
	req := &request{query: query, response: new(dns.Msg),
		src: wtr.RemoteAddr(), network: t.network}
	if len(t.network) == 0 {
		t.network = dnsutil.UDPNetwork
	}
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

	// Extract Opt valies which should always be possible

	req.nsidRequested = (len(t.cfg.nsid) > 0) && (findNSID(query) != nil)
	req.clientCookie, req.serverCookie = findCookie(query)

	if len(req.query.Question) != 1 ||
		len(req.query.Answer) != 0 ||
		len(req.query.Ns) != 0 ||
		req.query.Opcode != dns.OpcodeQuery {
		req.response.SetRcodeFormatError(query)
		t.writeMsg(wtr, req)
		req.stats.gen.formatError++
		req.logNote = "Malformed Query"
		return
	}

	req.ptrDB = t.dbGetter.Current()

	// If query contains a UDP size value, use it if it's reasonable
	if t.network == dnsutil.UDPNetwork {
		req.maxSize = dnsutil.MaxUDPSize // Default unless over-ridden
		edns := req.query.IsEdns0()
		if edns != nil {
			mz := edns.UDPSize()
			if (mz > 512) && (mz <= dnsutil.MaxUDPSize) { // Reasonable?
				req.maxSize = mz
			}
		}
	}

	// Pre-processing checks and setup is complete. Time to dispatch on the
	// query. Order is important which porbe queries first followed by chaos.

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

	req.mutables = t.getMutables() // Get current mutables from server instance
	if req.probe != nil {
		if req.probe.QuestionMatches(req.question) {
			log.Minor("Valid Probe received from ", req.src)
			req.logNote = "Probe match"
			req.response.SetReply(req.query)
			req.response.Answer = append(req.response.Answer, req.probe.Answer())
			t.writeMsg(wtr, req)
			return
		}
		req.logNote = "Non-probe query during prone"
	}

	// Choas helps check reachability thru firewalls, port forwarding and whatnot.

	if t.cfg.chaosFlag &&
		req.question.Qclass == dns.ClassCHAOS &&
		req.question.Qtype == dns.TypeTXT {
		t.serveCHAOS(wtr, req)
		req.stats.gen.chaos++
		return
	}

	// All special-case dispatching is complete. All legitimate queries must now be in
	// one our zones of authority which is only ever in ClassINET. This following test
	// is one of the reasons why passthru is INET-only. These tests *could* be
	// rearranged to allow it, but why bother? The focus is more about autoreverse
	// processing.

	if req.question.Qclass != dns.ClassINET { // Only serve INET henceforth
		req.logNote = "Wrong class " + dns.ClassToString[req.question.Qclass]
		t.serveRefused(wtr, req)
		req.stats.gen.wrongClass++
		return
	}

	req.setAuthority()
	if req.auth == nil { // One of our domains?
		if len(t.cfg.passthru) > 0 { // Nope - do we passthru?
			t.passthru(wtr, req)
		} else {
			req.logNote = "out of bailiwick"
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

// Should this be RcodeserverFailure rather than Refused?
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
// oddball queries such as lb._dns-sd._udp.128.2.0.192.in-addr.arpa which is in-bailiwick
// if we don't get a match that we can serve, let the caller deal with.
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

// Expecting the usual reverse syntax. Return true if we answered the question. Otherwise
// let the caller deal with any subsequent processing. The PTR database is consulted first
// to see if there is deduce PTRs for this qName. If no database entries are found *and*
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
		req.logNote = "bad Mux"
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
			req.logNote = "Synth"
		} else {
			req.logNote = "No Synth"
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

	// Truncate msg to fit max size. Only relevent if connection is UDP.
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
	var opt dns.OPT
	optSet := false
	if req.nsidRequested { // Add pre-populated NSID option?
		opt = t.cfg.nsidOpt // Take a copy as we may override DNS size
		optSet = true
		req.response.Extra = append(req.response.Extra, &opt)
		req.stats.gen.nsid++
	}
	if len(req.clientCookie) > 0 {
		req.stats.gen.cookie++
	}
	if req.maxSize > 0 {
		if optSet {
			opt.SetUDPSize(req.maxSize)
		} else {
			req.response.SetEdns0(req.maxSize, false)
		}
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

// Search OPT RRs for an NSID request. OPT is the Matryoshka dolls of Internet protocols.
// Return the EDNS opt if found, otherwise nil.
func findNSID(query *dns.Msg) *dns.EDNS0_NSID {
	opt := query.IsEdns0() // OPT RR?
	if opt == nil {
		return nil
	}

	for _, subopt := range opt.Option {
		if so, ok := subopt.(*dns.EDNS0_NSID); ok {
			return so
		}
	}

	return nil
}

// Search OPT RRs for a rfc7873 cookie. Return the client and server cookie if
// found. Returned empty client string indicate the option wasn't found or was
// ineffective.
func findCookie(query *dns.Msg) (client, server string) {
	opt := query.IsEdns0() // OPT RR?
	if opt == nil {
		return
	}

	for _, subopt := range opt.Option {
		if so, ok := subopt.(*dns.EDNS0_COOKIE); ok {
			client = so.Cookie[:16]
			server = so.Cookie[16:]
			return
		}
	}

	return
}
