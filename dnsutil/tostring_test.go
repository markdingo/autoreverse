package dnsutil

import (
	"testing"

	"github.com/miekg/dns"
)

func TestClassToString(t *testing.T) {
	s := ClassToString(dns.ClassCHAOS)
	if s != "CH" {
		t.Error("Expected 'CH', not", s)
	}
	s = ClassToString(15000)
	if s != "C-15000" {
		t.Error("Expected C-15000, not", s)
	}
}

func TestTypeToString(t *testing.T) {
	s := TypeToString(dns.TypeTXT)
	if s != "TXT" {
		t.Error("Expected 'TXT', not", s)
	}
	s = TypeToString(15000)
	if s != "T-15000" {
		t.Error("Expected T-15000, not", s)
	}
}

func TestRcodeToString(t *testing.T) {
	s := RcodeToString(dns.RcodeRefused)
	if s != "REFUSED" {
		t.Error("Expected 'REFUSED', not", s)
	}
	s = RcodeToString(15000)
	if s != "r-15000" {
		t.Error("Expected r-15000, not", s)
	}
}

func TestOpcodeToString(t *testing.T) {
	s := OpcodeToString(dns.OpcodeIQuery)
	if s != "IQUERY" {
		t.Error("Expected 'IQUERY', not", s)
	}
	s = OpcodeToString(15000)
	if s != "o-15000" {
		t.Error("Expected o-15000, not", s)
	}
}
