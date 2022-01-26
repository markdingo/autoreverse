package dnsutil

import (
	"fmt"
	"net"
	"strings"
)

// InvertPtrToIP extracts and inverts the purported IP address from a reverse qName. Like
// any name in the DNS, a reverse qName does not *have* to represent an IP address, but
// this code ignores all else. Return an error if an IP address cannot be extracted. The
// return bool is true if the IP address is as valid as far as it goes, but is truncated.
func InvertPtrToIP(qName string) (net.IP, bool, error) {
	if strings.HasSuffix(qName, V4Suffix) {
		return InvertPtrToIPv4(strings.TrimSuffix(qName, V4Suffix))
	}
	if strings.HasSuffix(qName, V6Suffix) {
		return InvertPtrToIPv6(strings.TrimSuffix(qName, V6Suffix))
	}

	return nil, false, fmt.Errorf("Unknown reverse suffix '%s'", qName)
}

// InvertPtrToIPv4 takes the first part of the reverse qName from the ipv4 zone and
// converts it back into an ipv4 Address, if possible. As a reminder, a dig -x 192.168.1.2
// results in a qName of 2.1.168.192.in-addr.arpa. The suffix is removed by the caller
// leaving just 2.1.168.192. There are of course no guarantees that this string is in
// reversed IP address format as a rogue query can come in directly with anything in
// qName, thus all the checking and potential error return if the string doesn't parse.
//
// The returned bool is true if the IP address is valid as far as it goes, but is
// truncated, e.g. 1.168.192.in-addr.arpa. The reason for converting truncated IPs is so
// that the caller can distinguish between a malformed address and a truncated one as the
// former results in an NXDomain and the latter results in a NoError.
func InvertPtrToIPv4(qName string) (net.IP, bool, error) {
	if len(qName) == 0 {
		return nil, false, fmt.Errorf("Empty reverse ipv4 address qName")
	}
	var octets [4]byte
	reverse := strings.SplitN(qName, ".", 4)
	ix := 4 - len(reverse)
	for _, octet := range reverse {
		v := convertDecimalOctet(octet)
		if v == -1 {
			return nil, false, fmt.Errorf("Malformed reverse ipv4 address '%s'", qName)
		}
		octets[ix] = byte(v)
		ix++
	}
	ip := net.IPv4(octets[3], octets[2], octets[1], octets[0])

	return ip, len(reverse) < 4, nil
}

// InvertPtrToIPv6 takes the first part of the reverse query name, and converts it back
// into an ipv6 address, if possible. Expected input looks something like:
// 3.f.6.d.4.d.3.b.c.4.3.0.1.3.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa less the
// "ip6.arpa" suffix.
//
// The returned bool is true if the IP address is valid as far as it goes, but is
// truncated, e.g. 0.8.e.f.ip6.arpa returns an ipv6 address of fe80::0 with
// truncated=true. See the discussion of InvertPtrToIPv4.
func InvertPtrToIPv6(qName string) (net.IP, bool, error) {
	if len(qName) == 0 {
		return nil, false, fmt.Errorf("Empty reverse ipv6 address qName")
	}
	var hex [32]byte
	reverse := strings.SplitN(qName, ".", 32)
	ix := 32 - len(reverse)
	for _, hStr := range reverse {
		if len(hStr) != 1 {
			return nil, false, fmt.Errorf("Malformed reverse ipv6 address '%s'", qName)
		}
		h := hStr[0]
		switch {
		case h >= '0' && h <= '9':
			hex[ix] = h - '0'
		case h >= 'a' && h <= 'f':
			hex[ix] = h - 'a' + 10
		case h >= 'A' && h <= 'F':
			hex[ix] = h - 'A' + 10
		default:
			return nil, false, fmt.Errorf("Malformed reverse ipv6 address '%s'", qName)
		}
		ix++
	}

	ip := make(net.IP, net.IPv6len) // Create an allocated net.IP
	ix = 15
	for rx := 0; rx < 32; rx += 2 {
		ip[ix] = hex[rx+1]<<4 + hex[rx]
		ix--
	}

	return ip, len(reverse) < 32, nil
}

// convertDecimalOctet strictly converts an ipv4 decimal octet to an int. Return -1 if
// conversion fails. Rules: no leading zeroes, numeric range 0-255, lenfth 1-3 bytes and
// no non-digit characters.
func convertDecimalOctet(s string) (ret int) {
	if len(s) == 0 || len(s) > 3 {
		return -1
	}
	if s[0] == '0' && len(s) > 1 { // Don't allow leading digits
		return -1
	}

	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		c -= '0'
		ret *= 10
		ret += int(c)
	}
	if ret > 255 {
		return -1
	}

	return
}
