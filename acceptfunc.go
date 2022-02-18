package main

import (
	"github.com/miekg/dns"
)

/*

This is a clone of the miekg.defaultMsgAcceptFunc with the test for qdcount != 1
removed. This is to support queries for Server Cookies get thru to our handler. see RFC
7873 Section 5.4. Review periodically to ensure it still matches the original.

*/

// DefaultMsgAcceptFunc checks the request and will reject if:
//
// * isn't a request (don't respond in that case)
//
// * opcode isn't OpcodeQuery or OpcodeNotify
//
// * Zero bit isn't zero
//
// * does not have exactly 1 question in the question section
//
// * has more than 1 RR in the Answer section
//
// * has more than 0 RRs in the Authority section
//
// * has more than 2 RRs in the Additional section
//

const (
	// Header.Bits
	_QR = 1 << 15 // query/response (response=1)
)

func (t *server) customMsgAcceptFunc(dh dns.Header) dns.MsgAcceptAction {
	if isResponse := dh.Bits&_QR != 0; isResponse {
		t.addAcceptError()
		return dns.MsgIgnore
	}

	// Don't allow dynamic updates, because then the sections can contain a whole bunch of RRs.
	opcode := int(dh.Bits>>11) & 0xF
	if opcode != dns.OpcodeQuery && opcode != dns.OpcodeNotify {
		t.addAcceptError()
		return dns.MsgRejectNotImplemented
	}

	//////////////////////////////////////////////////////////////////////
	// if dh.Qdcount != 1 {
	//	return MsgReject
	// }
	//////////////////////////////////////////////////////////////////////

	// NOTIFY requests can have a SOA in the ANSWER section. See RFC 1996 Section 3.7 and 3.11.
	if dh.Ancount > 1 {
		t.addAcceptError()
		return dns.MsgReject
	}
	// IXFR request could have one SOA RR in the NS section. See RFC 1995, section 3.
	if dh.Nscount > 1 {
		t.addAcceptError()
		return dns.MsgReject
	}
	if dh.Arcount > 2 {
		t.addAcceptError()
		return dns.MsgReject
	}
	return dns.MsgAccept
}
