package main

import (
	"net"
	"testing"

	"github.com/markdingo/autoreverse/database"
	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
	"github.com/markdingo/autoreverse/resolver"

	"github.com/miekg/dns"
)

const (
	ptServer = "127.0.0.1:21053"
)

func TestPassthru(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.SilentLevel)

	wtr := &mock.ResponseWriter{}

	res := resolver.NewResolver()
	cfg := &config{logQueriesFlag: true, passthru: ptServer}
	server := newServer(cfg, database.NewGetter(), res, "", "")

	// First query without anything listening - this will show in the logs
	query := setQuestion(dns.ClassINET, dns.TypeNS, "ns.example.net.")
	server.ServeDNS(wtr, query)
	resp := wtr.Get()
	if resp != nil {
		t.Fatal("Did not expect a response from passthru")
	}

	addr, err := net.ResolveUDPAddr("udp", ptServer)
	if err != nil {
		t.Fatal(err)
	}
	// Open socket here so we know it's opened before starting reply go-routine.
	sock, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go passReply(sock) // Ignores first message and replies to second msg
	server.ServeDNS(wtr, query)
	resp = wtr.Get()
	if resp != nil {
		t.Error("Did not expect response to first msg from passReply", resp)
	}

	server.ServeDNS(wtr, query)
	resp = wtr.Get()
	if resp == nil {
		t.Error("Expected a response to second msg from passReply")
	} else if resp.Rcode != dns.RcodeSuccess {
		t.Error("Expected RcodeSuccess, not", dns.RcodeToString[resp.Rcode])
	} else {
		if len(resp.Answer) != 1 && resp.Answer[0].Header().Rrtype != dns.TypeNS {
			t.Error("Wrong response", len(resp.Answer), resp.Answer[0].Header().Rrtype)
		}
	}

	// Check error logging
	exp := `ru=ok q=NS/ns.example.net. s=127.0.0.2 id=0 h=U sz=0/1232 C=0/0/0 passthru:Connection refused
ru=ok q=NS/ns.example.net. s=127.0.0.2 id=0 h=U sz=0/1232 C=0/0/0 passthru:Timeout
ru=ok q=NS/ns.example.net. s=127.0.0.2 id=1 h=U sz=76/1232 C=1/0/0 passthru
`
	got := out.String()
	if exp != got {
		t.Error("Passthru log mismatch got:\n", got, "\nexp:\n", exp)
	}
}

func passReply(conn *net.UDPConn) {
	defer conn.Close()
	b := make([]byte, 512)
	var addr *net.UDPAddr
	var err error
	_, _, err = conn.ReadFromUDP(b)
	if err != nil {
		return
	}

	_, addr, err = conn.ReadFromUDP(b)
	if err != nil {
		return
	}
	m := new(dns.Msg)
	err = m.Unpack(b)
	if err != nil {
		return
	}

	m.Answer = append(m.Answer, newRR("ns.example.net. IN NS a.ns.example.com."))
	out, err := m.Pack()
	if err != nil {
		return
	}
	_, err = conn.WriteToUDP(out, addr)
	if err != nil {
	}
}
