package main

import (
	"testing"

	"github.com/markdingo/rrl"
	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
)

// Meet the net.Addr interface so we can mock into the request struct
type mockNetAddr struct {
	net string
	str string
}

func (t *mockNetAddr) Network() string {
	return t.net
}

func (t *mockNetAddr) String() string {
	return t.str
}

func TestRequestLog(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)

	req := &request{}
	req.network = dnsutil.TCPNetwork
	req.compressed = true
	req.truncated = true
	req.response = new(dns.Msg)
	req.question = dns.Question{}
	req.src = &mockNetAddr{}
	req.log()

	got := out.String()
	exp := "ru=ne q=None/ s= id=0 h=Tzt sz=0/0 C=0/0/0\n"
	if exp != got {
		t.Error("Log wrong. Exp", exp, "Got", got)
	}

	out = &mock.IOWriter{}
	log.SetOut(out)
	req.rrlAction = rrl.Drop
	req.log()

	got = out.String()
	exp = "ru=ne/D q=None/ s= id=0 h=Tzt sz=0/0 C=0/0/0\n"
	if exp != got {
		t.Error("Log wrong. Exp", exp, "Got", got)
	}
}
