package dns

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
)

type ExchangeResponse struct {
	Ignore    bool
	Truncated bool
	Rcode     int
	Ns        []dns.RR
	Answer    []dns.RR
	Extra     []dns.RR

	QueryCount int // Times mockDNSHandler served this mockExchangeResponse
}

// Designed for a single DNS exchange, a dumb server which copies response values into the
// reply message. It never checks the input or anything like that.
type ExchangeServer struct {
	mu   sync.Mutex
	resp *ExchangeResponse
}

// Set a new response for the next query
func (t *ExchangeServer) SetResponse(r *ExchangeResponse) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.resp = r
}

// Return the current response as set
func (t *ExchangeServer) GetResponse() *ExchangeResponse {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.resp
}

// Meets the interface definition for dns.Handler
func (t *ExchangeServer) ServeDNS(wtr dns.ResponseWriter, q *dns.Msg) {
	resp := t.GetResponse()
	if resp == nil {
		panic("resp == nil in mock exchange server")
	}
	resp.QueryCount++
	if resp.Ignore {
		return
	}

	m := new(dns.Msg)
	m.SetRcode(q, resp.Rcode)
	if resp.Truncated {
		m.MsgHdr.Truncated = true
	} else if resp.Rcode == dns.RcodeSuccess { // Only populate if rcode is good
		m.Ns = resp.Ns
		m.Answer = resp.Answer
		m.Extra = resp.Extra
	}

	err := wtr.WriteMsg(m)
	if err != nil {
		fmt.Println("Alert: WriteMsg error:", err)
	}
}
