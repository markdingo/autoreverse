package main

import (
	"strings"
	"testing"
	"time"

	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
)

func TestValidate1(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MajorLevel)

	ar := newAutoReverse(nil, nil)
	err := ar.ValidateCommandLineOptions()
	if err == nil {
		t.Error("Expected a TTL complaint")
	} else if !strings.Contains(err.Error(), "TTL must be at") {
		t.Error("Expected TTL complaint, not", err)
	}
	ar.cfg.TTL = time.Second * 2

	err = ar.ValidateCommandLineOptions()
	if err == nil {
		t.Error("Expected --forward complaint")
	} else if !strings.Contains(err.Error(), "Must supply one of --forward") {
		t.Error("Expected --forward complaint, not", err)
	}

	ar.cfg.delegatedForward = "autoreverse."
	err = ar.ValidateCommandLineOptions()
	if err == nil {
		t.Error("Expected Invalid domain name complaint")
	} else if !strings.Contains(err.Error(), "Invalid domain name") {
		t.Error("Expected 'Invalid domain name' complaint, not", err)
	}

	ar.cfg.delegatedForward = ""
	ar.cfg.localForward = "local"
	err = ar.ValidateCommandLineOptions()
	if err == nil {
		t.Error("Expected Invalid domain name complaint")
	} else if !strings.Contains(err.Error(), "Invalid domain name") {
		t.Error("Expected 'Invalid domain name' complaint, not", err)
	}

	ar.cfg.delegatedForward = "autoreverse.example.net"
	ar.cfg.localForward = "local.example.org"
	err = ar.ValidateCommandLineOptions()
	if err == nil {
		t.Error("Expected cannot have both complaint")
	} else if !strings.Contains(err.Error(), "Cannot have both") {
		t.Error("Expected have both complaint, not", err)
	}
	ar.cfg.localForward = ""

	err = ar.ValidateCommandLineOptions()
	if err == nil {
		t.Error("Expected --reverse complaint")
	} else if !strings.Contains(err.Error(), "Must supply one of --reverse") {
		t.Error("Expected --reverse complaint, not", err)
	}
	ar.cfg.delegatedReverse = []string{"192.0.2.0/24"}

	err = ar.ValidateCommandLineOptions()
	if err == nil {
		t.Error("Expected a report complaint")
	} else if !strings.Contains(err.Error(), "report must be at") {
		t.Error("Expected report complaint, not", err)
	}
	ar.cfg.reportInterval = time.Second * 2

	// All mandatory options are now present

	err = ar.ValidateCommandLineOptions()
	if err != nil {
		t.Error("Unexpected", err)
	}

	ar.cfg.localForward = ""
	ar.cfg.delegatedForward = "Example.Com"
	err = ar.ValidateCommandLineOptions()
	if err != nil {
		t.Error("Unexpected", err)
	}
	if ar.forward != "example.com." {
		t.Error("Canonicalization didn't")
	}

	ar.cfg.localForward = "example.NET"
	ar.cfg.delegatedForward = ""
	err = ar.ValidateCommandLineOptions()
	if err != nil {
		t.Error("Unexpected", err)
	}
	if ar.forward != "example.net." {
		t.Error("Canonicalization didn't")
	}

	ar.cfg.maxAnswers = -1
	err = ar.ValidateCommandLineOptions()
	if err == nil {
		t.Error("Expected max-answers complaint")
	} else if !strings.Contains(err.Error(), "max-answers") {
		t.Error("Expected 'max-answers' complaint, not", err)
	}
	ar.cfg.maxAnswers = 0

	ar.cfg.passthru = "127.0.0].0:53:54"
	err = ar.ValidateCommandLineOptions()
	if err == nil {
		t.Error("Expected passthru complaint")
	} else if !strings.Contains(err.Error(), "syntax") {
		t.Error("Expected passthru 'syntax' complaint, not", err)
	}
	ar.cfg.passthru = "cronan.example.org."
	err = ar.ValidateCommandLineOptions()
	if err == nil {
		t.Error("Expected passthru complaint")
	} else if !strings.Contains(err.Error(), "Lookup") {
		t.Error("Expected passthru 'Lookup' complaint, not", err)
	}
	ar.cfg.passthru = ""

	if ar.cfg.TTLAsSecs < 2 || ar.cfg.TTLAsSecs > 3 {
		t.Error("TTL Conversion wrong", ar.cfg.TTLAsSecs)
	}

	ag := ar.cfg.listen
	if len(ag) != 1 || ag[0] != defaultListen {
		t.Error("Default listen string not set")
	}

	ar.cfg.listen = []string{":domain", ":1053", "localhost"}
	ar.cfg.passthru = "example.net"
	err = ar.ValidateCommandLineOptions()
	if err != nil {
		t.Error("Unexpected", err)
	}
	ag = ar.cfg.listen
	if len(ag) != 3 || ag[0] != ":domain" || ag[2] != "localhost:domain" {
		t.Error("ListenStrings not normalized", ag)
	}
	if ar.cfg.passthru != "example.net:domain" {
		t.Error("passthru not normalized", ar.cfg.passthru)
	}

	ar.cfg.PTRDeduceURLs = []string{"httpz://www.example.net/example.org"}
	err = ar.ValidateCommandLineOptions()
	if err == nil {
		t.Error("Unexpected PTRDeduce success")
	} else if !strings.Contains(err.Error(), "not a supported scheme") {
		t.Error("Expected scheme complaint, not", err)
	}
	ar.cfg.PTRDeduceURLs = []string{"https://www.example.net"}
	err = ar.ValidateCommandLineOptions()

	if err == nil {
		t.Error("Unexpected PTRDeduce success")
	} else if !strings.Contains(err.Error(), "must contain a zone") {
		t.Error("Expected missing zone complaint, not", err)
	}
	ar.cfg.PTRDeduceURLs = []string{"https://www.example.net/example.org"}

	ar.cfg.localReverse = []string{"badcidr"}
	err = ar.ValidateCommandLineOptions()
	if err == nil {
		t.Error("Expected CIDR Error")
	} else {
		if !strings.Contains(err.Error(), "invalid CIDR") {
			t.Error("Expected invalid CIDR, not", err.Error())
		}
	}

	ar.cfg.localReverse = []string{"192.0.2.0/27"}
	err = ar.ValidateCommandLineOptions()
	if err == nil {
		t.Error("Expected ipv4 prefix error")
	} else {
		if !strings.Contains(err.Error(), "prefix length") {
			t.Error("Got wrong prefix length error", err.Error())
		}
	}
	ar.cfg.localReverse = []string{"2001:db8::/33"}
	err = ar.ValidateCommandLineOptions()
	if err == nil {
		t.Error("Expected ipv6 prefix error")
	} else {
		if !strings.Contains(err.Error(), "prefix length") {
			t.Error("Got wrong prefix length error", err.Error())
		}
	}

	ar.cfg.localReverse = []string{"2001:db8::/32", "192.0.2.0/24"}
	err = ar.ValidateCommandLineOptions()
	if err != nil {
		t.Error("Unexpected", err.Error())
	}
	if len(ar.localReverses) != 2 {
		t.Error("local net lost. Expected 2, got", len(ar.localReverses))
	}

	// Check logged output

	exp := `Warning: --local-reverse 2001:db8::/32 may be a Global Unicast CIDR
Warning: --local-reverse 192.0.2.0/24 may be a Global Unicast CIDR
`
	got := out.String()
	if exp != got {
		t.Error("Log mismatch. Exp", exp, "got", got)
	}
}

func TestNormalizeHostPort(t *testing.T) {
	testCases := []struct{ input, expect string }{
		{"1.2.3.4", "1.2.3.4:domain"},
		{"1.2.3.4:domain", "1.2.3.4:domain"},
		{"::1", "[::1]:domain"}, // Make sure ipv6 address is wrapped in []
		{"[::1]:domain", "[::1]:domain"},
		{"1.2.3", "1.2.3:domain"}, // Split thinks 1.2.3 is a host name since it's not an IP
		{"1.2.3:domain", "1.2.3:domain"},
		{"host.example.net", "host.example.net:domain"},
		{"host.example.net:domain", "host.example.net:domain"},
		{"1.2.3.4:53", "1.2.3.4:53"},
		{"[::1]:53", "[::1]:53"}, // Make sure ipv6 address is wrapped in []
		{"host.example.net:53", "host.example.net:53"},
	}

	for ix, tc := range testCases {
		got := normalizeHostPort(tc.input, "domain")
		if got != tc.expect {
			t.Error(ix, "Input", tc.input, "Expect", tc.expect, "Got", got)
		}
	}
}
