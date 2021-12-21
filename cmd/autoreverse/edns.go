package main

import (
	"encoding/hex"
	"net"
	"time"

	"github.com/dchest/siphash"
	"github.com/miekg/dns"
)

const (
	cCookieLength    = 8 * 2  // Cookie lengths and limits in terms of hex strings
	sCookieMinLength = 8 * 2  // as miekg presents and expects cookies that way.
	sCookieMaxLength = 32 * 2 // This has structure as of rfc9018
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

	if len(so.Cookie) < cCookieLength { // If present, must be exactly 8 bytes - 16 hex
		t.clientCookie = so.Cookie // Provide potential logging material
		return
	}

	t.clientCookie = so.Cookie[:cCookieLength]
	t.serverCookie = so.Cookie[cCookieLength:]

	if len(t.serverCookie) == 0 {
		t.cookiesValid = true
	} else if len(t.serverCookie) >= 16 && len(t.serverCookie) <= 64 {
		t.cookiesValid = true
	}

	return
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
		e.Cookie = t.cookieOut
	}

	if returnOpt {
		return opt
	}

	return nil
}

// genServerCookie generates the server cookie. Originally the cookie was just an
// arbitrary array of bytes, but as of rfc9018, a 128 bit server cookie has
// structure. This function always generates an rfc9018 128 bit server cookie as:
//
// [0:1] Version - current 0x1
// [1:4] Reserved - must be 0x0
// [4:8] Timestamp - serial number arithmetic unsigned unix time
// [8:16] Hash
//
// The recommended hash is SipHash-2-4 by good ol' DJB et al.
//
// The input into [SipHash-2-4]) MUST be either precisely 20 bytes in case of an IPv4
// Client-IP or precisely 32 bytes in case of an IPv6 Client-IP.
//
// Returned as a hex string, thus 32 bytes long.
func genServerCookie(secrets [2]uint64, clientIP, clientCookieHex string) string {
	h, _, _ := net.SplitHostPort(clientIP)
	ip := net.ParseIP(h)                     // Convert everything back to binary
	cCookie, _ := hex.DecodeString(clientCookieHex) // byte slices

	// Construct the first part of the server cookie as that's input to the hash
	sCookie := make([]byte, 16)
	sCookie[0] = 1
	now := time.Now().Unix()
	var now32 uint32
	now32 = uint32(now & 0xFFFFF000) // now32 rolls every 1.14 hours
	sCookie[4] = byte(now32 >> 24)
	sCookie[5] = byte(now32 & 0x00FF0000 >> 16)
	sCookie[6] = byte(now32 & 0x0000FF00 >> 8)
	sCookie[7] = byte(now32 & 0x000000FF)

	// Hash = ( Client Cookie | Version | Reserved | Timestamp | Client-IP, Server Secret )
	//
	// hashInput should end up being either 20 or 32 bytes long for ipv4 and ipv6
	//respectively.

	hashInput := cCookie                          // Client Cookie
	hashInput = append(hashInput, sCookie[:8]...) // Version | Reserved | Timestamp
	if ipv4 := ip.To4(); ipv4 != nil {
		hashInput = append(hashInput, ipv4[:4]...) // Client-IP
	} else {
		ipv6 := ip.To16()
		hashInput = append(hashInput, ipv6[:16]...) // Client-IP
	}

	sum64 := siphash.Hash(secrets[0], secrets[1], hashInput)

	// Complete construction of the server cookie

	for ix := 8; ix < 16; ix++ {
		sCookie[ix] = byte(sum64 & 0xFF)
		sum64 >>= 8
	}

	return hex.EncodeToString(sCookie)
}
