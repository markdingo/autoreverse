package resolver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
	mockDNS "github.com/markdingo/autoreverse/mock/dns"
)

func TestExchange(t *testing.T) {
	const serverAddr = "[::1]:53053"
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.DebugLevel)
	hUDP := &mockDNS.ExchangeServer{}
	srvUDP := mockDNS.StartServer("udp", serverAddr, hUDP)
	defer srvUDP.Shutdown()

	res := NewResolver()
	cfg := NewExchangeConfig()
	q := new(dns.Msg)
	q.SetQuestion("example.net.", dns.TypeAAAA) // Doesn't matter what the question is

	// RCode = ServerFailure.

	out.Reset()
	resp := &mockDNS.ExchangeResponse{Rcode: dns.RcodeServerFailure}
	hUDP.SetResponse(resp)
	r, _, err := res.SingleExchange(context.Background(), cfg, q, serverAddr, "TestLocalHost")
	if r.MsgHdr.Rcode != dns.RcodeServerFailure {
		t.Error("Expected RcodeServerFailure, got",
			r.MsgHdr.Rcode, dns.RcodeToString[r.MsgHdr.Rcode])
	}

	// Simple correct exchange

	out.Reset()
	ans := make([]dns.RR, 0)
	rr, _ := dns.NewRR("x.example.net. IN AAAA ::1")
	ans = append(ans, rr)
	hUDP.SetResponse(&mockDNS.ExchangeResponse{Rcode: dns.RcodeSuccess, Answer: ans})
	r, _, err = res.SingleExchange(context.Background(), cfg, q, serverAddr, "TestLocalHost")
	if r.MsgHdr.Rcode != dns.RcodeSuccess {
		t.Error("Expected RcodeSuccess, got",
			r.MsgHdr.Rcode, dns.RcodeToString[r.MsgHdr.Rcode])
	} else {
		if len(r.Answer) != 1 {
			t.Error("Expected one answer, not", len(r.Answer))
		}
	}

	// Check debug output as user may one day turn this on for debugging purposes
	got := out.String()
	exp := "Dbg:miekg Q:udp:TestLocalHost/[::1]:53053 q=IN/AAAA example.net"
	if !strings.Contains(got, exp) {
		t.Error("Log of good exchange differs. Exp", exp, "got", got)
	}

	// Should get the same result from FullExchange

	out.Reset()
	r, _, err = res.FullExchange(context.Background(), cfg, q.Question[0], serverAddr, "TestLocalHost")
	if r.MsgHdr.Rcode != dns.RcodeSuccess {
		t.Error("Expected RcodeSuccess, got",
			r.MsgHdr.Rcode, dns.RcodeToString[r.MsgHdr.Rcode])
	} else if len(r.Answer) != 1 {
		t.Error("Expected one answer, not", len(r.Answer))
	}

	got = out.String()
	if !strings.Contains(got, exp) {
		t.Error("Log of good exchange differs. Exp", exp, "got", got)
	}

	// Timeout SingleExchange

	resp = &mockDNS.ExchangeResponse{Ignore: true}
	hUDP.SetResponse(resp)
	start := time.Now()
	_, _, err = res.SingleExchange(context.Background(), cfg, q, serverAddr, "TestLocalHost")
	if err == nil {
		t.Error("Expected a timeout error return")
	} else {
		if !strings.Contains(err.Error(), "timeout") {
			t.Error("Expected timeout error, not", err)
		}
		end := time.Now()
		diff := end.Sub(start)
		if diff < defaultSingleExchangeTimeout {
			t.Error("SingleExchange t/o too short. Want",
				defaultSingleExchangeTimeout, "got", diff)
		}
	}

	// Timeout FullExchange

	start = time.Now()
	_, _, err = res.FullExchange(context.Background(), cfg, q.Question[0],
		serverAddr, "TestLocalHost")
	if err == nil {
		t.Error("Expected a timeout error return")
	} else {
		if !strings.Contains(err.Error(), "timeout") {
			t.Error("Expected timeout error, not", err)
		}
		end := time.Now()
		diff := end.Sub(start)
		if diff < defaultQueryTries*defaultSingleExchangeTimeout {
			t.Error("FullExchange t/o too short. Want",
				defaultfFullExchangeTimeout, "got", diff)
		}
	}

	// FullExchange fallback to TCP. UDP should return truncated bit
	// and TCP server should return AAAA

	hTCP := &mockDNS.ExchangeServer{}
	srvTCP := mockDNS.StartServer("tcp", serverAddr, hTCP)
	defer srvTCP.Shutdown()

	resp = &mockDNS.ExchangeResponse{Rcode: dns.RcodeSuccess, Truncated: true}
	hUDP.SetResponse(resp)

	ans = make([]dns.RR, 0)
	rr, _ = dns.NewRR("x.example.net. IN AAAA ::1")
	ans = append(ans, rr)
	resp = &mockDNS.ExchangeResponse{Rcode: dns.RcodeSuccess, Answer: ans}
	hTCP.SetResponse(resp)

	out.Reset()
	r, _, err = res.FullExchange(context.Background(), cfg, q.Question[0],
		serverAddr, "TestLocalHost")
	if r.MsgHdr.Rcode != dns.RcodeSuccess {
		t.Error("Expected RcodeSuccess, got",
			r.MsgHdr.Rcode, dns.RcodeToString[r.MsgHdr.Rcode])
	} else if len(r.Answer) != 1 {
		t.Error("Expected one answer, not", len(r.Answer))
	}

	resp = hUDP.GetResponse()
	if resp.QueryCount != 1 {
		t.Error("UDP Server should have seen one query, not", resp.QueryCount)
	}

	resp = hTCP.GetResponse()
	if resp.QueryCount != 1 {
		t.Error("TCP Server should have seen one query, not", resp.QueryCount)
	}

	got = out.String()
	for _, exp = range []string{
		"qr+tc NOERROR Q=1-AAAA Ans=0", // UDP Response with truncate flag
		"Q:tcp",                        // TCP query
		"qr NOERROR Q=1-AAAA",          // TCP response with one AAAA
	} {
		if !strings.Contains(got, exp) {
			t.Error("TCP Log does not contain", exp)
		}
	}
	t.Log(got) // Only written if errors
}

func TestExchangeDefaultService(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.DebugLevel)

	res := NewResolver()
	cfg := NewExchangeConfig()
	q := new(dns.Msg)
	q.SetQuestion("example.net.", dns.TypeAAAA) // Doesn't matter what the question is
	res.SingleExchange(context.Background(), cfg, q, "127.0.0.1", "Default")
	got := out.String()
	exp := "Dbg:miekg E:127.0.0.1:domain"
	if !strings.Contains(got, exp) {
		t.Error("Log not as expected for Default Service", got)
	}
}

func TestExchangeBadQuestion(t *testing.T) {
	res := NewResolver()
	cfg := NewExchangeConfig()
	q := new(dns.Msg) // No questions
	_, _, err := res.SingleExchange(context.Background(), cfg, q, "127.0.0.1", "Default")
	if err == nil {
		t.Fatal("Expected an error return")
	}
	if !strings.Contains(err.Error(), "expect one") {
		t.Error("Got an error, but doesn't match", err)
	}

	q.SetQuestion("example.net.", dns.TypeAAAA)    // Doesn't matter what the question is
	q.Question = append(q.Question, q.Question[0]) // Now have two

	_, _, err = res.SingleExchange(context.Background(), cfg, q, "127.0.0.1", "Default")
	if err == nil {
		t.Fatal("Expected an error return")
	}
	if !strings.Contains(err.Error(), "expect one") {
		t.Error("Got an error, but doesn't match", err)
	}
}
