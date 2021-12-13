package dnsutil

import (
	"fmt"
	"net"
	"strings"
)

// IPToReverseQName converts an IP address into the reverse string normally looked up in
// the reverse path. It includes the reverse suffix, is fully qualified and is ready for
// querying.
//
// An empty string is returned if the IP address cannot be parsed.
//
// This is not intended to be a high-speed function.
func IPToReverseQName(ip net.IP) string {
	if ip == nil { // Emulate net.ParseIP and be nice.
		return ""
	}
	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d%s", ip4[3], ip4[2], ip4[1], ip4[0], V4Suffix)
	}

	ip6 := ip.To16()
	if ip6 == nil {
		return ""
	}

	joiner := make([]string, 0, 16)
	for ix := 15; ix >= 0; ix-- {
		joiner = append(joiner, fmt.Sprintf("%x", ip6[ix]&0xf))
		joiner = append(joiner, fmt.Sprintf("%x", ip6[ix]&0xf0>>4))
	}

	return strings.Join(joiner, ".") + V6Suffix
}
