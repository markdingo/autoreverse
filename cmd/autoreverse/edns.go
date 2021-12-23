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
// Regardless of the validity of the cookie data, whatever cookie material is set in the
// request as it may be of use for logging or debug purposes.
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
	moduloMask   = 0xFFFFF000 // 0xFFF seconds ~= 1.14 hours
	clockTick    = 0x1000     // How much the cookie clock increments each tick
	minimumClock = clockTick  // We only ever allow going back one tick
)

// validateOrGenerateCookie compares the client supplied server cookie with the one we
// expect it to have. This is a little tricker than a binary comparison due to the use of
// a slowly ticking timestamp in the cookie hash. This function also sets the server
// cookie to be returned to the client, which again may differ if the timestamp has ticked
// over since we last sent this client a cookie.
//
// In terms of trusting the client we only consider a server cookie if it's version '1',
// exactly 16 bytes long and contains a timestamp which is current or one tick behind.
//
// Returns true if the server cookie is valid. Regardless of validity, cookieOut is set
// with the full cookie payload to send back to the client.
func (t *request) validateOrGenerateCookie(secrets [2]uint64, unixTime int64) (valid bool) {
	ourClock := uint32(unixTime & moduloMask)
	if ourClock == 0 {
		ourClock = minimumClock // Avoid RFC1982 contortions
	}

	var haveCookieOut bool                       // If t.cookieOut is valid
	if len(t.serverCookie) == sCookieV1Length && // If it's a valid v1 cookie length
		t.serverCookie[0] == 1 && // with a valid v1 version
		t.serverCookie[1] == 0 && // and zero in the RFFU bytes
		t.serverCookie[2] == 0 &&
		t.serverCookie[3] == 0 {
		theirClock := binary.BigEndian.Uint32(t.serverCookie[4:8])
		if theirClock == ourClock || theirClock == (ourClock-clockTick) {
			t.cookieOut = genV1Cookie(secrets, theirClock, t.src.String(),
				t.clientCookie)
			haveCookieOut = theirClock == ourClock // Only true with current clock
			valid = bytes.Compare(t.serverCookie[:sCookieV1Length],
				t.cookieOut[8:8+sCookieV1Length]) == 0
		}
	}

	if !haveCookieOut {
		t.cookieOut = genV1Cookie(secrets, ourClock, t.src.String(), t.clientCookie)
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
