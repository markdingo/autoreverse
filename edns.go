package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"

	"github.com/dchest/siphash"
	"github.com/miekg/dns"
)

const (
	cCookieLength    = 8 // Client cookie is always exactly this long
	sCookieMinLength = 8 // If present, a server cookie must be in this range
	sCookieMaxLength = 32
	sCookieV1Length  = 16 // A version '1' cookie is exactly 128 bits
)

// findNSID searches the OPT RR for an NSID request. OPT is the Matryoshka dolls of
// Internet protocols. Return the NSID opt if found, otherwise nil.
func (t *request) findNSID() *dns.EDNS0_NSID {
	if t.opt == nil {
		return nil
	}

	for _, subopt := range t.opt.Option {
		if so, ok := subopt.(*dns.EDNS0_NSID); ok {
			return so
		}
	}

	return nil
}

// genOpt creates an OPT RR with all the required sub-opt values. Return the populated
// *dns.OPT if there is at least one sub-opt value, otherwise return nil.
func (t *request) genOpt() *dns.OPT {
	var returnOpt bool

	opt := new(dns.OPT) // Presume we'll need it so take the construction hit
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.Hdr.Ttl = 0 // extended RCODE and flags

	if t.maxSize > 0 {
		returnOpt = true
		opt.SetUDPSize(t.maxSize)
	}

	if len(t.nsidOut) > 0 {
		returnOpt = true
		e := new(dns.EDNS0_NSID)
		e.Code = dns.EDNS0NSID
		e.Nsid = t.nsidOut
		opt.Option = append(opt.Option, e)
	}

	if len(t.cookieOut) > 0 {
		returnOpt = true
		e := new(dns.EDNS0_COOKIE)
		e.Code = dns.EDNS0COOKIE
		e.Cookie = hex.EncodeToString(t.cookieOut) // Miekg wants it in hex
		opt.Option = append(opt.Option, e)
	}

	if returnOpt {
		return opt
	}

	return nil
}

// findCookies searches the OPT RR for rfc7873 cookies. It sets all the cookie-related
// variables in the request.
//
// Regardless of the validity of the cookie data, whatever cookie material is found, is
// set in the request as it may be of use for logging or debug purposes.
func (t *request) findCookies() {
	if t.opt == nil {
		return
	}

	var so *dns.EDNS0_COOKIE
	for _, subopt := range t.opt.Option {
		var ok bool
		if so, ok = subopt.(*dns.EDNS0_COOKIE); ok {
			break
		}
	}
	if so == nil {
		return
	}
	t.cookiesPresent = true

	if len(so.Cookie) == 0 { // If the sub-opt is present so should the client cookie
		return
	}

	if len(so.Cookie) < (2 * cCookieLength) { // If present, cannot be less than 8 bytes - 16 hex
		t.clientCookie, _ = hex.DecodeString(so.Cookie) // Potential logging material
		return
	}

	// Treat cookies as a binary set of bytes internally, even tho miekg stores them
	// in hex format. We don't bother checking the hex decode error return as a) it
	// should never occur and b) the failure mode is exactly what we'd do any way.
	t.clientCookie, _ = hex.DecodeString(so.Cookie[:cCookieLength*2])
	t.serverCookie, _ = hex.DecodeString(so.Cookie[cCookieLength*2:])

	t.cookieWellFormed = len(t.serverCookie) == 0 ||
		(len(t.serverCookie) >= sCookieMinLength &&
			len(t.serverCookie) <= sCookieMaxLength)

	return
}

const (
	wrapDistance = uint64(1<<31) - 1 // Assume wrap if gap is greater than this
	maxBehindGap = 60 * 60           // Timestamps older than this are ignored (seconds)
	maxAheadGap  = 60 * 5            // Timestamps ahead by more than this much are ignored
	reissueGap   = maxAheadGap / 2   // Reissue cookie if their clock is getting old
)

// validateOrGenerateCookie compares the client supplied server cookie with the one we
// expect it to have.
//
// A valid timestamp is in the range of now-maxBehindGap and now+maxAheadGap. That is, no
// more than an hour behind or five minutes ahead. The ahead isn't relevant to us as we
// don't share secrets with potential anycast peers, but it's a useful validation check in
// its own right.
//
// If their timestamp is behind by more than reissueGap, generate a new cookie for them
// otherwise send their current cookie back to them.
//
// The timestamp is Unix time stored in a uint32 so we have to worry about "serial number
// arithmetic". The way we deal with this is to get normalizeTimestamps() to convert them
// both to uint64 and add "SERIAL_BITS" to the "smaller" number. Then we just treat them
// as regular integers.
//
// Sets cookieValid if the server cookie is valid. Regardless of validity, cookieOut is
// always populated with the full cookie payload to send back to the client.
func (t *request) validateOrGenerateCookie(secrets [2]uint64, unixTime int64) {
	now := uint32(unixTime & 0xFFFFFFFF)
	var now64, ts64 uint64
	if len(t.serverCookie) == sCookieV1Length && // If it's a valid v1 cookie length
		t.serverCookie[0] == 1 && // with a valid v1 version
		t.serverCookie[1] == 0 && // and zero in the RFFU bytes
		t.serverCookie[2] == 0 &&
		t.serverCookie[3] == 0 {
		ts := binary.BigEndian.Uint32(t.serverCookie[4:8])
		now64, ts64 = normalizeTimestamps(now, ts)
		if (ts64+maxBehindGap > now64) && (now64+maxAheadGap) > ts64 { // in range?
			t.cookieOut = genV1Cookie(secrets, ts, t.src.String(), t.clientCookie)
			t.cookieValid = bytes.Compare(t.serverCookie[:sCookieV1Length],
				t.cookieOut[8:8+sCookieV1Length]) == 0
		}
	}

	// If invalid or getting old, reissue
	if !t.cookieValid || ts64+reissueGap < now64 {
		t.cookieOut = genV1Cookie(secrets, now, t.src.String(), t.clientCookie)
	}
}

// normalizeTimestamps converts "serial number arithmetic" uint32s into regular comparable
// uint64 integers. In essence this means adding the capacity of a uint32 to the lower
// number if is determined to have wrapped. The lower number is considered to have wrapped
// (and thus actually be higher) if the difference in absolute terms is greater than half
// the capacity of a uint32.
//
// In the context of DNS Cookies, this code has relevance once every 68 years for about an
// hour...
func normalizeTimestamps(a, b uint32) (A, B uint64) {
	A = uint64(a)
	B = uint64(b)
	if A > B && (A-B) > wrapDistance { // Is A is ahead by more than 1/2 a uint32
		B += wrapDistance + 1 // then presume B is ahead and wrapped
		return
	}

	if B > A && (B-A) > wrapDistance { // If B is ahead by more than 1/2 a uint32
		A += wrapDistance + 1 // then presume A is ahead and wrapped
	}

	return
}

// genV1Cookie generates a (version '1') full cookie to return to the client, including
// the 8-byte client cookie as the prefix.
//
// A version '1' server cookie is of the form:
//
// [0:1] Version - currently 0x1
// [1:4] Reserved - must be 0x0
// [4:8] Timestamp - serial number arithmetic unsigned unix time
// [8:16] Hash
//
// The recommended hash is SipHash-2-4 by good ol' DJB et al.
//
// The input into [SipHash-2-4]) MUST be either precisely 20 bytes in case of an IPv4
// Client-IP or precisely 32 bytes in case of an IPv6 Client-IP.
//
// Returned full cookie string that is ultimately return to the client
func genV1Cookie(secrets [2]uint64, clock uint32, clientIP string, clientCookie []byte) []byte {
	cookie := make([]byte, 8+32) // Largest size possible
	h, _, err := net.SplitHostPort(clientIP)
	if err != nil {
		return cookie // Caller has failed
	}
	ip := net.ParseIP(h) // Convert everything back to binary
	if ip == nil {
		return cookie // Caller has failed
	}

	// Hash = ( Client Cookie | Version | Reserved | Timestamp | Client-IP, Server Secret )
	//
	// The server cookie is partially constructed with the client-IP in the hash position
	// (and beyond) for the purposes of calculating the hash, then the first 4 bytes of the
	// Client-IP are overwritten with the calculated hash.

	copy(cookie, clientCookie[:8]) // findCookies assures us that this is exactly 8 bytes long
	cookie[8] = 1                  // Version 1
	binary.BigEndian.PutUint32(cookie[12:16], clock)

	ix := 16 // Start location of hash/IP
	if ipv4 := ip.To4(); ipv4 != nil {
		copy(cookie[ix:ix+4], ipv4[:4])
		ix += 4
	} else {
		ipv6 := ip.To16()
		copy(cookie[ix:ix+16], ipv6[:16])
		ix += 16
	}

	sum64 := siphash.Hash(secrets[0], secrets[1], cookie[:ix])

	// Stash hash on top of the first part of Client-IP

	binary.BigEndian.PutUint64(cookie[16:24], sum64)

	return cookie[:24] // 8 Client cookie + 16 Server cookie = 24 total
}
