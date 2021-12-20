package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/database"
	"github.com/markdingo/autoreverse/delegation"
	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/log"
)

// There is a whole bunch of info about a query and the response that is gradually
// extracted and accumulated as a request progresses and gets dispatched. Rather than pass
// this around as a fleet of function parameters it all gets accumulated into a request
// struct. The main purpose is readability and simplicity of adding variables as
// needed. The other main purpose is to accumulate values for log reporting. A request is
// only ever accessed by a single go-routine and only lives for the life of a DNS query.
type request struct {
	ptrDB         *database.Database
	query         *dns.Msg
	response      *dns.Msg
	question      dns.Question
	qName         string
	nsidRequested bool
	clientCookie  string
	serverCookie  string

	mutables // Copied from server under mutex protection

	auth *delegation.Authority // Match for current request

	src        net.Addr // From here on down is log data
	network    string
	logQName   string // Short but recognizable qName to keep log entries shorter
	logNote    string // Mixed in with log message, if set
	logError   error  // Append to log message, if set
	msgSize    int
	maxSize    uint16 // EDNS0 or zero which will cause dns.WriteMsg() to default
	compressed bool
	truncated  bool

	// To avoid holding a lock for the whole query, stats are accumulated in a
	// separate copy and added back into the aggregate server stats at the end. This
	// means that most of the dns query runs lock free, but it's at the expense of a
	// chunk of memory and a churn thru all the stats at the end of each request. I've
	// never found a statisfactory way of dealing with efficiently aggregating stats
	// in a concurrency safe way that doesn't involve heavy operations. Well, heavy
	// compared to just the ++ operation.

	stats serverStats
}

func (t *request) log() {
	var note []string
	if len(t.logNote) > 0 {
		note = append(note, t.logNote)
	}
	if t.logError != nil {
		note = append(note, t.logError.Error())
	}
	var noteStr string
	if len(note) > 0 {
		noteStr = " " + strings.Join(note, ":")
	}
	rcodeStr := "ok"
	if t.response.MsgHdr.Rcode != dns.RcodeSuccess {
		rcodeStr = dnsutil.RcodeToString(t.response.MsgHdr.Rcode)
	}

	hFlags := make([]byte, 0, 10) // 'h' = humongous?
	if t.network == dnsutil.TCPNetwork {
		hFlags = append(hFlags, 'T')
	} else {
		hFlags = append(hFlags, 'U') // Superfluous but ensures h= doesn't dangle
	}
	if len(t.clientCookie) > 0 {
		hFlags = append(hFlags, 'C')
	}
	if len(t.serverCookie) > 0 { // This should never happen since we don't send cookies...
		hFlags = append(hFlags, 'S')
	}
	if t.compressed {
		hFlags = append(hFlags, 'c')
	}
	if t.nsidRequested {
		hFlags = append(hFlags, 'n')
	}
	if t.truncated {
		hFlags = append(hFlags, 'Z')
	}

	fmt.Fprintf(log.Out(), "ru=%s q=%s/%s s=%s id=%d h=%s sz=%d/%d C=%d/%d/%d%s\n",
		rcodeStr, dnsutil.TypeToString(t.question.Qtype), t.logQName,
		t.src.String(),
		t.response.MsgHdr.Id, string(hFlags), t.msgSize, t.maxSize,
		len(t.response.Answer), len(t.response.Ns), len(t.response.Extra), noteStr)
}

// Sets the authority - if any - for the current request.
//
// Have to serially search as it's a suffix match rather than an exact match. Possibly
// could have some fancy suffix tree to mimic the DNS hierarchy, but in most cases the
// number of authorities is likely to be 2 or 3, so a serial search probably beats a fancy
// tree search any way.
//
// Authorities have already been sorted by longest to shortest prefix so if there are some
// zones more specific than others, they win.
func (t *request) setAuthority() {
	for _, auth := range t.authorities {
		if dnsutil.InBailiwick(t.qName, auth.Domain) {
			t.auth = auth
			return
		}
	}
}
