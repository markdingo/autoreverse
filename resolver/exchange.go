package resolver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/log"
)

func (t *resolver) SingleExchange(ctx context.Context, c ExchangeConfig, q *dns.Msg,
	server, logName string) (r *dns.Msg, rtt time.Duration, err error) {
	if len(q.Question) != 1 {
		err = fmt.Errorf("SingleExchange Message contains %d Question(s), expect one",
			len(q.Question))
		return
	}

	question := q.Question[0]
	client := &dns.Client{Timeout: t.singleExchangeTimeout}
	client.Net = c.Net()
	client.UDPSize = c.UDPSize()
	_, _, e := net.SplitHostPort(server) // Coerce a service onto the name if
	if e != nil {                        // it hasn't got one
		server = net.JoinHostPort(server, "domain")
	}

	if log.IfDebug() {
		LogExchangeQ(client.Net, logName, server, question)
	}

	r, rtt, err = client.ExchangeContext(ctx, q, server)

	if log.IfDebug() {
		LogExchangeA(server, question, r, err)
	}

	return
}

func (t *resolver) FullExchange(ctx context.Context, c ExchangeConfig, question dns.Question,
	server, logName string) (r *dns.Msg, rtt time.Duration, err error) {
	query := new(dns.Msg)
	query.Id = dns.Id()
	query.RecursionDesired = false // Just to make it clear this is purposefully false
	query.SetEdns0(c.UDPSize(), false)
	query.Question = append(query.Question, question)

	// Set an overall timeout for the full exchange which includes all retries and
	// possible TCP tries. I'm not entirely sure this is honoured by miekg, but the
	// individual timeouts set by t.SingleExchange() protect us from an unbounded
	// stall, which is good enough.
	ctxWithTO, cancel := context.WithDeadline(ctx, time.Now().Add(t.fullExchangeTimeout))
	defer cancel()

	for tries := 0; tries < t.queryTries; tries++ {
		c.setNet(dnsutil.UDPNetwork)
		r, rtt, err = t.SingleExchange(ctxWithTO, c, query, server, logName)
		if err != nil {
			continue
		}

		// If truncated, try again with TCP
		if r.MsgHdr.Rcode == dns.RcodeSuccess && r.MsgHdr.Truncated {
			c.setNet(dnsutil.TCPNetwork)
			r, rtt, err = t.SingleExchange(ctxWithTO, c, query, server, logName)
			if err != nil {
				continue
			}
		}

		return
	}

	return // No valid response from any nameserver
}
