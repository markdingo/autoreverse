package resolver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/resolver"
)

// mockResolver implements the resolver.Resolver interface by converting queries to
// file names and loading responses from those files. The convention is, if the file
// doesn't exist, the response is REFUSED or an error - depending on the interface. If the
// file exists, each line in the file is parsed with dns.NewRR.
//
// If the number of RRs parsed is zero, then rcode is NOERROR for functions which return
// an rcode.
//
// The filename convention for Lookup functions is: $dir/lookup/$Class/$Type/$qname and
// for Exchange is $dir/exchange/$net/$IP/$Class/$Type/$qname.
type mockResolver struct {
	dir string
}

// NewResolver creates a mock resolver which uses the supplied directory as the location
// of mock files to parse to produce dns lookup responses.
func NewResolver(dir string) *mockResolver {
	return &mockResolver{dir: dir}
}

func (t *mockResolver) LookupNS(ctx context.Context, name string) (ns []string, err error) {
	name = dnsutil.ChompCanonicalName(name)
	msg, path := t.loadLookupFile("IN", "NS", name)
	rCode := msg.MsgHdr.Rcode
	nsSet := make([]*net.NS, 0) // For logging purposes only
	if rCode == dns.RcodeSuccess {
		for _, rr := range msg.Answer { // Convert msg Answer RRs to strings
			if rrt, ok := rr.(*dns.NS); ok {
				ns = append(ns, rrt.Ns)
				nsSet = append(nsSet, &net.NS{Host: rrt.Ns})
			}
		}
	} else {
		err = fmt.Errorf("host not found")
	}

	resolver.LogNS(name, nsSet, path, err)

	return
}

func (t *mockResolver) LookupIPAddr(ctx context.Context, host string) (ips []net.IP, err error) {
	host = dnsutil.ChompCanonicalName(host)
	aMsg, aPath := t.loadLookupFile("IN", "A", host)
	aaaaMsg, aaaaPath := t.loadLookupFile("IN", "AAAA", host)
	aCode := aMsg.MsgHdr.Rcode
	aaaaCode := aaaaMsg.MsgHdr.Rcode

	addrs := make([]net.IPAddr, 0) // For logging purposes only

	// Convert msg answers to the returned slice of net.IPs
	if aCode == dns.RcodeSuccess {
		for _, rr := range aMsg.Answer {
			if rrt, ok := rr.(*dns.A); ok {
				ips = append(ips, rrt.A)
				addrs = append(addrs, net.IPAddr{IP: rrt.A})
			}
		}
	}

	if aaaaCode == dns.RcodeSuccess {
		for _, rr := range aaaaMsg.Answer {
			if rrt, ok := rr.(*dns.AAAA); ok {
				ips = append(ips, rrt.AAAA)
				addrs = append(addrs, net.IPAddr{IP: rrt.AAAA})
			}
		}
	}
	if len(addrs) == 0 { // A proxy for aCode and aaaaCode
		err = fmt.Errorf("no such host")
	}
	resolver.LogIP(host, addrs, aPath+","+aaaaPath, err)

	return

}

func (t *mockResolver) SingleExchange(ctx context.Context, c resolver.ExchangeConfig, q *dns.Msg,
	server, logName string) (out *dns.Msg, rtt time.Duration, err error) {
	if len(q.Question) != 1 {
		err = fmt.Errorf("SingleExchange Message contains %d Question(s), expect one",
			len(q.Question))
		return
	}

	question := q.Question[0]
	net := c.Net()
	if len(net) == 0 { // Set to specific value to ensure correct path generation
		net = "udp"
	}

	if log.IfDebug() {
		resolver.LogExchangeQ(net, logName, server, question)
	}
	r, _ := t.loadExchangeFile(net, server,
		dns.ClassToString[question.Qclass], dns.TypeToString[question.Qtype],
		dnsutil.ChompCanonicalName(question.Name))
	rcode := r.MsgHdr.Rcode
	r.SetRcode(q, rcode)
	if rcode == dns.RcodeServerFailure { // Return an error
		err = fmt.Errorf("Server Failed")
	}
	if log.IfDebug() {
		resolver.LogExchangeA(server, question, &r, err)
	}

	out = &r

	return
}

// Only need to do a single exchange here as the file system is a tad more stable than the
// DNS and can hold more than 512 bytes per file - hopefully!
func (t *mockResolver) FullExchange(ctx context.Context, c resolver.ExchangeConfig, q dns.Question,
	server, logName string) (r *dns.Msg, rtt time.Duration, err error) {
	query := new(dns.Msg)
	query.Question = append(query.Question, q)
	return t.SingleExchange(ctx, c, query, server, logName)
}
