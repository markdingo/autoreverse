package dnsutil

const (
	V4Suffix = ".in-addr.arpa." // The leading '.' is important here as some callers
	V6Suffix = ".ip6.arpa."     // rely on strings.HasSuffix() to label match.

	TCPNetwork = "tcp" // Yeah, yea, a bit silly, but case is important
	UDPNetwork = "udp" // so having consts here avoids pernickety errors

	MaxUDPSize uint16 = 1232 // Generally suggested as universally safe in edns0
)
