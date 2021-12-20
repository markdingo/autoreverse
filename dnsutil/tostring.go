package dnsutil

import (
	"fmt"

	"github.com/miekg/dns"
)

// ClassToString converts an miekg class to a string, but if the resulting string is empty
// it's replaced with the numeric value.
func ClassToString(c dns.Class) (s string) {
	s = dns.ClassToString[uint16(c)]
	if len(s) == 0 {
		s = fmt.Sprintf("C-%d", c)
	}

	return
}

// TypeToString converts an miekg type to a string, but if the resulting string is empty
// it's replaced with the numeric value.
func TypeToString(t uint16) (s string) {
	s = dns.TypeToString[t]
	if len(s) == 0 {
		s = fmt.Sprintf("T-%d", t)
	}

	return
}

// RcodeToString converts an miekg rcode to a string, but if the resulting string is empty
// it's replaced with the numeric value.
func RcodeToString(r int) (s string) {
	s = dns.RcodeToString[r]
	if len(s) == 0 {
		s = fmt.Sprintf("r-%d", r)
	}

	return
}

// OpcodeToString converts an miekg opcode to a string, but if the resulting string is
// empty it's replaced with the numeric value.
func OpcodeToString(o int) (s string) {
	s = dns.OpcodeToString[o]
	if len(s) == 0 {
		s = fmt.Sprintf("o-%d", o)
	}

	return
}
