package dns

import (
	"os"
	"sync"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
)

// AXFRResponse is what is set with the AxfrServer to define what the response will be for
// its AXFR request.
type AXFRResponse struct {
	Rcode int
}

// AxfrServer is a mock server designed for a single DNS axfr request, a dumb server which
// loads the zone from a file and sends it back. It checks as little as possible to do the
// job.
type AxfrServer struct {
	Path string
	mu   sync.Mutex
	resp *AXFRResponse
}

// SetResponse sets a new response for the axfr query
func (t *AxfrServer) SetResponse(r *AXFRResponse) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.resp = r
}

// GetResponse returns the current response as set
func (t *AxfrServer) GetResponse() *AXFRResponse {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.resp
}

// ServeDNS meets the interface definition for dns.Handler
func (t *AxfrServer) ServeDNS(wtr dns.ResponseWriter, q *dns.Msg) {
	resp := t.GetResponse()
	if resp == nil {
		panic("resp == nil in mock axfr server")
	}

	if len(q.Question) != 1 {
		r := new(dns.Msg)
		r.SetRcodeFormatError(q)
		r.SetRcode(q, dns.RcodeFormatError)
		wtr.WriteMsg(r)
		return
	}
	question := q.Question[0]
	if question.Qclass != dns.ClassINET || question.Qtype != dns.TypeAXFR {
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeFormatError)
		wtr.WriteMsg(r)
		return
	}

	// Is a custome Rcode requested? If so, just reply with that.
	if resp.Rcode != -1 {
		r := new(dns.Msg)
		r.SetRcode(q, resp.Rcode)
		wtr.WriteMsg(r)
		return
	}

	// Ok, slurp up the zone from disk
	qName := dnsutil.ChompCanonicalName(question.Name)
	file := t.Path + qName + ".zone"
	f, err := os.Open(file)
	if err != nil {
		r := new(dns.Msg)
		r.SetRcode(q, dns.RcodeNameError)
		wtr.WriteMsg(r)
		return
	}
	defer f.Close()
	parser := dns.NewZoneParser(f, "", file)
	parser.SetIncludeAllowed(true)
	parser.SetDefaultTTL(60) // ZoneParser needs this in case $TTL is absent

	ch := make(chan *dns.Envelope)
	tr := new(dns.Transfer)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		tr.Out(wtr, q, ch)
		wg.Done()
	}()

	var soa dns.RR
	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		ch <- &dns.Envelope{RR: []dns.RR{rr}}
		if soa == nil {
			soa = rr
		}
	}

	if soa == nil {
		panic("Set up error: No SOA in " + file)
	}
	ch <- &dns.Envelope{RR: []dns.RR{soa}}

	wg.Wait() // wait until everything is written out
}
