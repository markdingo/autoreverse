package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/log"
)

// Many serve* functions either serve their answer or return a pending result as they do
// not know whether the caller has other options available to them. serveResult conveys
// that info back to the caller.
type serveResult int

const (
	serveDone serveResult = iota // Caller concludes request processing
	NoError                      // Caller calls serveNoError() if no options remain
	NXDomain                     // Caller calls serveNxDomain() if no options remain
	FormErr                      // Caller calls serveFormErr()
)

func (t *serveResult) String() string {
	switch *t {
	case serveDone:
		return "serveDone"
	case NoError:
		return "NoError"
	case NXDomain:
		return "NXDomain"
	case FormErr:
		return "FormErr"
	}

	return fmt.Sprintf("?? sr %d", *t)
}

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
	// As of RFC7873 a query with no questions and a COOKIE OPT is valid.
	//
	// miekg.DefaultMsgAcceptFunc does some checking prior to the query arriving here,
	// but we are slightly more paranoid.
	if len(req.query.Question) > 0 {
		req.question = req.query.Question[0]           // Populate early for logger
		req.qName = strings.ToLower(req.question.Name) // Normalize
		req.logQName = req.qName                       // Can override
	}

	req.opt = req.query.IsEdns0() // Extract Opt values nice and early

	if (len(t.cfg.nsid) > 0) && (req.findNSID() != nil) {
		req.nsidOut = t.cfg.nsidAsHex
		req.stats.gen.nsid++
	}

	// We don't take any action based on cookies yet apart from exchange them with
	// clients and note whether they are correct or not. Mostly this is laying the
	// ground-work so that it's easy to add differentiation later.

	req.findCookies()
	if req.cookiesPresent {
		req.stats.gen.cookie++
		if !req.cookieWellFormed { // Specifically this means the OPT is malformed
			t.serveFormErr(wtr, req)
			req.addNote("Malformed cookie")
			req.stats.gen.malformedCookie++
			return
		}
		if !req.validateOrGenerateCookie(t.cookieSecrets, time.Now().Unix()) {
			if len(req.serverCookie) > 0 {
				req.addNote("Server cookie mismatch")
				req.stats.gen.wrongCookie++
			}
		}
	}

	// Is this a cookie-only request?
	if len(req.clientCookie) > 0 && len(req.serverCookie) == 0 && len(req.query.Question) == 0 {
		req.response.SetReply(query)
		t.writeMsg(wtr, req)
		req.addNote("Cookie-only query")
		req.stats.gen.cookieOnly++
		return
	}

	// Subsequent to the weird non-request cookie-request, we only accept "normal"
	// queries. Pretty much all of the following tests are performed by miekg prior to
	// calling ServeDNS(), but precisely what validation will be performed, is
	// undocumented and perhaps may vary over time thus the "belts and braces"
	// approach.
	if len(req.query.Question) != 1 ||
		len(req.query.Answer) != 0 ||
		len(req.query.Ns) != 0 ||
		req.query.Opcode != dns.OpcodeQuery {
		t.serveFormErr(wtr, req)
		req.addNote("Malformed Query")
		req.stats.gen.badRequest++
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

	req.db = t.dbGetter.Current()  // Final setup for request prior to dispatching
	req.mutables = t.getMutables() // Get current mutables from server instance

	// Pre-processing complete. Dispatch order:
	//
	// 1. Probe
	// 2. Chaos via database
	// 3. In-Bailiwick or Passthru
	// 4. Not ClassINET
	// 5. Special Authority Queries (SOA, NS, ANY)
	// 6. Database
	// 7. Synthesis
	// 8. Pending serveResult

	//		dnsutil.ClassToString(dns.Class(req.question.Qclass)),
	//		dnsutil.TypeToString(req.question.Qtype), req.question.Name)
	// Dispatch 1. Probe
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
		req.addNote("Non-probe query during probe")
	}

	// Dispatch 2. Chaos via database
	// nsd returns "Refused" for any non-matching CHAOS. I'm not sure I agree with
	// this since our CHAOS RRs are in a hierarchy database. But it's such an
	// edge-case that for now I'll mostly go along with the group-think. Another
	// factor is that we have not Zone Of Authority and thus no SOA so other responses
	// such as NoError cannot be generated properly, so "Refused" is our
	// get-out-of-jail card.
	if t.cfg.chaosFlag && req.question.Qclass == dns.ClassCHAOS {
		req.stats.gen.chaos++
		if t.serveDatabase(wtr, req) != serveDone {
			t.serveRefused(wtr, req)
			req.stats.gen.chaosRefused++
		}
		return
	}

	// Dispatch 3. In-Bailiwick or Passthru
	req.setAuthority()
	if req.auth == nil { // One of our domains?
		if len(t.cfg.passthru) > 0 { // Nope - do we passthru?
			t.passthru(wtr, req)
			return
		}
		req.addNote("out of bailiwick")
		t.serveRefused(wtr, req)
		req.stats.gen.noAuthority++
		return
	}

	// Dispatch 4. Not ClassINET
	if req.question.Qclass != dns.ClassINET {
		t.serveRefused(wtr, req)
		req.addNote(fmt.Sprintf("Wrong class %s",
			dnsutil.ClassToString(dns.Class(req.question.Qclass))))
		req.stats.gen.wrongClass++
		return
	}

	// Dispatch 5. Special Authority Queries

	// Handle queries which require special treatment such as populating Extra or
	// Authority RRs or oddball qTypes. Otherwise fall thru to try serveDatabase which
	// can server all regular RRs for the Authority Zone.
	if req.qName == req.auth.Domain {
		switch req.question.Qtype {
		case dns.TypeANY:
			req.response.SetRcode(req.query, dns.RcodeSuccess)
			req.response.Answer = append(req.response.Answer, &req.auth.SOA)
			req.stats.gen.authZoneANY++
			t.writeMsg(wtr, req)
			return

		case dns.TypeSOA:
			req.response.SetRcode(req.query, dns.RcodeSuccess)
			req.response.Answer = append(req.response.Answer, &req.auth.SOA)
			req.response.Ns = append(req.response.Ns, req.auth.NS...)
			req.response.Extra = append(req.response.Extra, req.auth.A...)
			req.response.Extra = append(req.response.Extra, req.auth.AAAA...)
			req.stats.gen.authZoneSOA++
			t.writeMsg(wtr, req)
			return

		case dns.TypeNS:
			req.response.SetRcode(req.query, dns.RcodeSuccess)
			req.response.Answer = append(req.response.Ns, req.auth.NS...)
			req.response.Extra = append(req.response.Extra, req.auth.A...)
			req.response.Extra = append(req.response.Extra, req.auth.AAAA...)
			req.stats.gen.authZoneNS++
			t.writeMsg(wtr, req)
			return
		}
	}

	// Dispatch 6. Database - remember result in case synthesis is not enabled
	pending := t.serveDatabase(wtr, req)
	switch pending {
	case serveDone:
		req.addNote("DB")
		if len(req.response.Answer) >= 1 { // Log first label of PTRs found in the DB
			if prr, ok := req.response.Answer[0].(*dns.PTR); ok {
				ar := strings.SplitN(prr.Ptr, ".", 2)
				if len(ar) > 0 { // which it always should be
					req.addNote(ar[0])
				}
			}
		}
		req.stats.gen.dbDone++
		return
	case NoError:
		req.stats.gen.dbNoError++
	case NXDomain:
		req.stats.gen.dbNXDomain++
	case FormErr:
		req.stats.gen.dbFormErr++
	}

	// Dispatch 7. Synthesis.

	// If synthesize is allowed the pending results of the previous call to
	// serveDatabase() are overridden, otherwise they'll stand. Synthesis is only
	// allowed if configured *and* if the qName is a child of the Authority.
	if t.cfg.synthesizeFlag && len(req.qName) > len(req.auth.Domain) {
		if req.auth.forward {
			pending = t.serveForward(wtr, req)
			req.stats.gen.synthForward++
		} else {
			pending = t.serveReverse(wtr, req)
			req.stats.gen.synthReverse++
		}
		switch pending {
		case serveDone:
			req.stats.gen.synthDone++
		case NoError:
			req.stats.gen.synthNoError++
		case NXDomain:
			req.stats.gen.synthNXDomain++
		case FormErr:
			req.stats.gen.synthFormErr++
		}

	} else {
		req.addNote("No Synth")
		req.stats.gen.noSynth++
	}

	// Dispatch 8. Pending serveResult
	switch pending {
	case NoError:
		t.serveNoError(wtr, req)
	case NXDomain:
		t.serveNXDomain(wtr, req)
	case FormErr:
		t.serveFormErr(wtr, req)
	}
}

func (t *server) serveNoError(wtr dns.ResponseWriter, req *request) {
	req.response.SetRcode(req.query, dns.RcodeSuccess)
	req.response.Ns = append(req.response.Ns, &req.auth.SOA)
	t.writeMsg(wtr, req)
}

// I don't know why miekg has a specific function for FormErr and a generic one for all
// other returns, but I'll use the specific one just in case there's a good reason beyond
// being an historical artifact.
func (t *server) serveFormErr(wtr dns.ResponseWriter, req *request) {
	req.response.SetRcodeFormatError(req.query)
	t.writeMsg(wtr, req)
}

func (t *server) serveNXDomain(wtr dns.ResponseWriter, req *request) {
	req.response.SetRcode(req.query, dns.RcodeNameError)
	req.response.Ns = append(req.response.Ns, &req.auth.SOA)
	t.writeMsg(wtr, req)
}

func (t *server) serveRefused(wtr dns.ResponseWriter, req *request) {
	req.response.SetRcode(req.query, dns.RcodeRefused)
	t.writeMsg(wtr, req)
}

func (t *server) serveDatabase(wtr dns.ResponseWriter, req *request) serveResult {
	ar, nx := req.db.LookupRR(req.question.Qclass, req.question.Qtype, req.qName)
	if len(ar) == 0 {
		if nx {
			return NXDomain
		}
		return NoError
	}

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
		req.response.Truncate(int(req.maxSize)) // Removes excess RRs and sets TC=1
	}

	t.writeMsg(wtr, req)

	return serveDone
}

// The qName is in a known forward domain and given we're called after the database
// lookup, that means the query can only legitimately be an address query of a reverse of
// a synthesized PTR and thus should be something like:
//
// dig -t $qType fd2d-ffff-1234-fe--1.$forward // fd2d:ffff:1234:fe::/64
// dig -t $qType 192-168-0-123.$forward // 192.168.0.0/24
// dig -t $qType 192-168--1.$forward // 192:168::/64
//
// The IP address needs to be extract from the qName and checked against our reverse
// authorities to ensure it's an IP address that we could have concievably generated a
// PTR. Note that because this is all algorithmic, all legitimate IP addresses can be
// queried against the forward authorities at any time.
//
// To extract the IP address we need to first know whether it's an ipv4 or ipv6 address.
// It's subtle but ipv4 qNames have a unique pattern because they don't compress zero
// octets, unlike ipv6. Specifically, well formed ipv4 forwards are always four non-zero
// length decimals separated by '-'. Anything else has to either be an ipv6 address or
// invalid. We take advantage of this distinction to determine how to dispatch to the
// appropriate handler.
//
// This convolution is necessary because we need to distinguish between NoError and
// NXDomain. The naive (and wrong) approach is to use the $qType to decide how to decode
// the qName prefix.
func (t *server) serveForward(wtr dns.ResponseWriter, req *request) serveResult {
	ipStr := strings.TrimSuffix(req.qName, "."+req.auth.Domain)
	ar := strings.SplitN(ipStr, "-", 4)
	is4 := true
	if len(ar) != 4 || strings.Contains(ar[3], "-") { // A legit ipv4?
		is4 = false
	} else {
		for _, v := range ar {
			if len(v) == 0 {
				is4 = false
				break
			}
		}
	}

	if is4 {
		return t.serveA(wtr, req)
	}

	return t.serveAAAA(wtr, req)
}

// Expecting 192-0-2-1.$forward. Unlike ipv6, there is no compression of the IP address to
// cover multiple zero octets, which makes parsing simpler. IOWs, 192.0.0.1 does not get
// converted into 192--1.
func (t *server) serveA(wtr dns.ResponseWriter, req *request) serveResult {
	req.stats.AForward.queries++

	ipStr := strings.TrimSuffix(req.qName, "."+req.auth.Domain)
	if strings.Index(ipStr, ".") >= 0 { // Don't allow 192.0.2.0.domain - should be 192-0-2-0.domain
		return NXDomain
	}
	ipStr = strings.ReplaceAll(ipStr, "-", ".")
	ip := net.ParseIP(ipStr)
	if ip == nil { // Couldn't convert back into an ip address
		return NXDomain
	}
	ip = ip.To4()
	if ip == nil || len(ip) != net.IPv4len { // serveForward() checking should catch this
		return NXDomain
	}

	// If ip is not in-bailwick of our reverse zones then NXDomain
	if req.authorities.findIPInBailiwick(ip) == nil {
		return NXDomain
	}

	if req.question.Qtype != dns.TypeA { // If wrong type, NoError
		return NoError
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
	req.stats.AForward.good++
	req.stats.AForward.answers += len(req.response.Answer)

	return serveDone
}

// Expecting 2001-db83--1.domain. Convert the synthetic name back into an IP address and
// reply with an AAAA.
func (t *server) serveAAAA(wtr dns.ResponseWriter, req *request) serveResult {
	req.stats.AAAAForward.queries++

	ipStr := strings.TrimSuffix(req.qName, "."+req.auth.Domain)
	if strings.Index(ipStr, ":") >= 0 { // Don't allow fd00::1.domain - should be fd00--1.domain
		return NXDomain
	}

	ipStr = strings.ReplaceAll(ipStr, "-", ":")
	ip := net.ParseIP(ipStr)
	if ip == nil { // Couldn't convert back into an ip address
		return NXDomain
	}
	if len(ip) != net.IPv6len {
		return NXDomain
	}

	// If ip is not in-bailwick of our reverse zones then NXDomain
	if req.authorities.findIPInBailiwick(ip) == nil {
		return NXDomain
	}

	if req.question.Qtype != dns.TypeAAAA { // If wrong type, NoError
		return NoError
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
	req.stats.AAAAForward.good++
	req.stats.AAAAForward.answers += len(req.response.Answer)

	return serveDone
}

// The domain is a known reverse domain which means that a well formed query should be a
// query such as:
//
// dig -t $qType 168.192.in-addr.arpa.
// dig -t $qType 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.
//
// An invertible, but truncated IP is of the form:
//
// dig -t $qType 0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.
//
// As with serveForward() most of this code is dealing with malformed queries and
// determining what the correct response is. E.g. chopping a few nibbles off the front of
// an ip6.arpa query can easily still be in-bailiwick resulting in NOError whereas the
// same thing for in-addpr.arpa will almost certainly be NXDomain.
//
// Since qName is known to be in-bailiwick of a reverse authority and since this function
// is called *after* database lookup attempts, cases to handle are:
//
// 1. Uninvertible IPs such as those with impossible hex characters - serve NXDomain
// 2. An invertible, but truncated IP - serve NoError - most likely qname minimization probe
// 3. An invertible IP with $qType!=PTR - serve NoError
// 4. An invertible IP with $qType=PTR - serve the synth answer
func (t *server) serveReverse(wtr dns.ResponseWriter, req *request) serveResult {
	var (
		reverseIPStr string
		ip           net.IP
		err          error
		statsp       *qTypeStats
		truncated    bool
	)

	switch {
	case strings.HasSuffix(req.qName, dnsutil.V6Suffix):
		statsp = &req.stats.AAAAPtr
		statsp.queries++
		reverseIPStr = strings.TrimSuffix(req.qName, dnsutil.V6Suffix)
		ip, truncated, err = dnsutil.InvertPtrToIPv6(reverseIPStr)
		if truncated {
			req.stats.gen.truncatedV6++
		}

	case strings.HasSuffix(req.qName, dnsutil.V4Suffix):
		statsp = &req.stats.APtr
		statsp.queries++
		reverseIPStr = strings.TrimSuffix(req.qName, dnsutil.V4Suffix)
		ip, truncated, err = dnsutil.InvertPtrToIPv4(reverseIPStr)
		if truncated {
			req.stats.gen.truncatedV4++
		}

	default: // Unexpected suffix - Dispatcher should not have let this in
		log.Major("Danger:Dispatcher should never let in ", req.qName)
		req.addNote("bad Mux")
		return FormErr
	}

	if err != nil { // Case 1: qName contains uninvertible IP
		statsp.invertError++
		return NXDomain
	}

	if truncated { // Case 2: Well-formed, but incomplete - qname minimization?
		req.addNote("Trunc-qmin")
		statsp.truncated++
		return NoError
	}

	if req.question.Qtype != dns.TypePTR { // Case 3: Invertible, but not a PTR
		req.addNote("Not PTR")
		return NoError
	}

	req.addNote("Synth") // Case 4: Synthesize
	ptr := dnsutil.SynthesizePTR(req.qName, req.mutables.ptrSuffix, ip)
	req.response.SetReply(req.query)
	ptr.Hdr.Ttl = t.cfg.TTLAsSecs
	req.response.Answer = append(req.response.Answer, ptr)
	t.writeMsg(wtr, req)
	statsp.good++
	statsp.answers += len(req.response.Answer)

	return serveDone
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
