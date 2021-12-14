package dns

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
)

// ExchangeResponse is set by the caller to inform the ExchangeServer what the next
// response should contain.
type ExchangeResponse struct {
	Ignore    bool
	Truncated bool
	Rcode     int
	Ns        []dns.RR
	Answer    []dns.RR
	Extra     []dns.RR

	QueryCount int // Times mockDNSHandler served this mockExchangeResponse
}

// ExchangeServer is a mock replacement for a miekg dns.Handler. Used only for tests. It's
// a dumb server which does nothing more than copies the ExchangeResponse values into the
// reply message. It never checks the input or anything like that.
type ExchangeServer struct {
	mu   sync.Mutex
	resp *ExchangeResponse
}

// SetResponse sets a new response for the next query
func (t *ExchangeServer) SetResponse(r *ExchangeResponse) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.resp = r
}

// GetResponse returns the current response as set
func (t *ExchangeServer) GetResponse() *ExchangeResponse {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.resp
}

// ServeDNS meets the interface definition for dns.Handler
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
