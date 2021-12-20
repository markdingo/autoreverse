package dnsutil

import (
	"fmt"
	"net"
	"strings"
)

// InvertPtrToIP extracts and inverts the purported IP address from a reverse qName. Like
// any name in the DNS, a reverse qName does not *have* to represent an IP address, but
// this code ignores all else. Return an error if an IP address cannot be extracted.
func InvertPtrToIP(qName string) (net.IP, error) {
	if strings.HasSuffix(qName, V4Suffix) {
		return InvertPtrToIPv4(strings.TrimSuffix(qName, V4Suffix))
	}
	if strings.HasSuffix(qName, V6Suffix) {
		return InvertPtrToIPv6(strings.TrimSuffix(qName, V6Suffix))
	}

	return nil, fmt.Errorf("Unknown reverse suffix '%s'", qName)
}

// InvertPtrToIPv4 takes the first part of the reverse qName from the ipv4 zone and
// converts it back into an ipv4 Address, if possible. As a reminder, a dig -x 1.2.3.4
// results in a qName of 4.3.2.1.in-addr.arpa. The suffix is removed by the caller leaving
// just 4.3.2.1. There are of course no guarantees that this string is in reversed IP
// address format as a rogue query can come in directly with anything in qName, thus all
// the checking and potential error return if the string doesn't parse.
func InvertPtrToIPv4(qName string) (net.IP, error) {
	reverse := strings.SplitN(qName, ".", 4)
	if len(reverse) != 4 {
		return nil, fmt.Errorf("Malformed reverse ipv4 address '%s'", qName)
	}

	a := convertDecimalOctet(reverse[3])
	b := convertDecimalOctet(reverse[2])
	c := convertDecimalOctet(reverse[1])
	d := convertDecimalOctet(reverse[0])
	if a == -1 || b == -1 || c == -1 || d == -1 {
		return nil, fmt.Errorf("Malformed reverse ipv4 address '%s'", qName)
	}

	ip := net.IPv4(byte(a), byte(b), byte(c), byte(d))

	return ip, nil
}

// InvertPtrToIPv6 takes the first part of the reverse query name, and converts it back
// into an ipv6 Address, if possible. See discussion of InvertPtrToIPv4.
func InvertPtrToIPv6(qName string) (net.IP, error) {
	reverse := strings.SplitN(qName, ".", 32)
	if len(reverse) != 32 {
		return nil, fmt.Errorf("Malformed reverse ipv6 address '%s'", qName)
	}
	ip := make(net.IP, net.IPv6len) // Create an allocated net.IP
	ix := 15
	for rx := 0; rx < 32; rx += 2 {
		if len(reverse[rx]) != 1 || len(reverse[rx+1]) != 1 {
			return nil, fmt.Errorf("Malformed reverse ipv6 address '%s'", qName)
		}

		c2 := reverse[rx][0]
		c1 := reverse[rx+1][0]
		var i1, i2 byte
		switch {
		case c1 >= '0' && c1 <= '9':
			i1 = c1 - '0'
		case c1 >= 'a' && c1 <= 'f':
			i1 = c1 - 'a' + 10
		default:
			return nil, fmt.Errorf("Malformed reverse ipv6 address '%s'", qName)
		}

		switch {
		case c2 >= '0' && c2 <= '9':
			i2 = c2 - '0'
		case c2 >= 'a' && c2 <= 'f':
			i2 = c2 - 'a' + 10
		default:
			return nil, fmt.Errorf("Malformed reverse ipv6 address '%s'", qName)
		}

		ip[ix] = i1<<4 + i2
		ix--
	}

	return ip, nil
}

// convertDecimalOctet converts an ipv4 decimal octet to an int. But it's tough.  Return
// -1 if conversion fails. No leading zeroes, range 0-255, no non-digit characters,
// terminators or otherwise.
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
