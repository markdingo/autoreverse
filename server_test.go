package main

import (
	"sort"
	"strings"
	"testing"

	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
)

func TestStartServersGood(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MajorLevel)
	ar := newAutoReverse(nil, nil)
	ar.cfg.listen = []string{"127.0.0.1:2056", "127.0.0.1:2057", "[::1]:2058", "[::1]:2059"}
	ar.startServers()
	ar.stopServers()
	exp := `Listen on: udp 127.0.0.1:2056
Listen on: udp 127.0.0.1:2057
Listen on: udp [::1]:2058
Listen on: udp [::1]:2059
Listen on: tcp 127.0.0.1:2056
Listen on: tcp 127.0.0.1:2057
Listen on: tcp [::1]:2058
Listen on: tcp [::1]:2059
`
	got := out.String()

	// The server start up order is effectively random as each listen interface is run
	// as a separate go-routine so sort the log lines to eliminate order issues when
	// comparing against expected.

	gar := strings.Split(got, "\n")
	ear := strings.Split(exp, "\n")
	sort.Strings(gar)
	sort.Strings(ear)
	nGot := strings.Join(gar, "\n")
	nExp := strings.Join(ear, "\n")

	if nGot != nExp {
		t.Error("Log mismatch. Exp", nExp, "\nGot", nGot)
	}
}

// Exercise the error path of starting a server
func TestStartServersBad(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MajorLevel)
	ar := newAutoReverse(nil, nil)
	srv := newServer(ar.cfg, ar.dbGetter, ar.resolver, nil, "udp", "127.0.0.1:xx")
	err := ar.startServer(srv)
	if err == nil {
		t.Error("Expected server to fail due to bogus port number")
	}
}
