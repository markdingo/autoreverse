package main

import (
	"context"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/resolver"
)

// passthru proxies the query thru to the passthru server and sends the reply - if any -
// directly back to our querying client. The query and response are more or less
// transparently exchanged. No retry attempts are made not is there any transition to a
// TCP query if the response is truncated.
//
// At this stage, each exchange involves a new socket setup via SingleExchange, if
// passthru happens to become a popular feature that proxies a lot of traffic then it'll
// probably be worth holding on to a socket across passthru requests. That will require
// an extension to the resolver interface.
func (t *server) passthru(wtr dns.ResponseWriter, req *request) {
	req.addNote("passthru")
	req.stats.gen.passthruOut++
	response, _, err := t.resolver.SingleExchange(context.Background(),
		resolver.NewExchangeConfig(), req.query, t.cfg.passthru, "")
	if err != nil {
		req.logError = dnsutil.ShortenLookupError(err)
		return
	}

	req.response = response // Save for logging
	req.logQName = req.qName
	req.stats.gen.passthruIn++

	req.msgSize = req.response.Len() // Stats for reporting
	req.compressed = req.response.Compress
	req.truncated = req.response.MsgHdr.Truncated

	err = wtr.WriteMsg(response)
	if err != nil {
		req.logError = dnsutil.ShortenLookupError(err)
		return
	}
}
