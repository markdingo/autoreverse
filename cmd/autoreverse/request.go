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

// request contains the DNS request, related material and accumulated response data which
// is gradually extracted as request processing progresses. Rather than pass all of this
// data around as a fleet of function parameters it all gets accumulated into this request
// struct. The main purpose is readability and simplicity of adding variables as
// needed. The other main purpose is to accumulate values for log reporting. A request is
// only ever accessed by a single go-routine and only lives for the life of a single DNS
// query.
type request struct {
	ptrDB    *database.Database
	query    *dns.Msg
	response *dns.Msg
	question dns.Question
	qName    string
	opt      *dns.OPT // Optionally present

	cookiesPresent   bool   // Cookie sub-option is present in opt
	cookieWellFormed bool   // Lengths are valid - only ever set if cookiesPresent is true
	clientCookie     []byte // Copied and hex decoded from OPT regardless of cookieWellFormed
	serverCookie     []byte // Ditto

	nsidOut   string // Output nsid if len > 0
	cookieOut []byte // If len > 0, this is the entire cookie to add to the out-going OPT

	mutables // Copied from server under mutex protection

	auth *delegation.Authority // Match for current request

	src        net.Addr // From here on down is log data
	network    string
	logQName   string   // Short but recognizable qName to keep log entries shorter
	logNote    []string // Mixed in with log message, if set
	logError   error    // Append to log message, if set
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

// newRequest is a nice-to-use constructor. The zero form works just fine.
func newRequest(query *dns.Msg, src net.Addr, network string) *request {
	return &request{query: query, response: new(dns.Msg), src: src, network: network}
}

// addNote does nothing more than append the supplied string to the note slice. That
// ultimately gets appended to line generated by log()
func (t *request) addNote(n string) {
	t.logNote = append(t.logNote, n)
}

// log is called for --log-queries. It produces a one-line summary of the request that is
// intended to be suited to both automated scanning as well as human viewing. It tries to
// succinctly convey as many details as possible in as small a log-line as possible.
func (t *request) log() {
	var note []string
	if len(t.logNote) > 0 {
		note = append(note, t.logNote...)
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
	if t.compressed {
		hFlags = append(hFlags, 'z')
	}
	if len(t.nsidOut) > 0 {
		hFlags = append(hFlags, 'n')
	}
	if t.truncated {
		hFlags = append(hFlags, 't')
	}
	if t.cookiesPresent {
		hFlags = append(hFlags, 'e')
	}
	if t.cookieWellFormed {
		hFlags = append(hFlags, 'E')
	}
	if len(t.serverCookie) > 0 {
		hFlags = append(hFlags, 's')
	}

	fmt.Fprintf(log.Out(), "ru=%s q=%s/%s s=%s id=%d h=%s sz=%d/%d C=%d/%d/%d%s\n",
		rcodeStr, dnsutil.TypeToString(t.question.Qtype), t.logQName,
		t.src.String(),
		t.response.MsgHdr.Id, string(hFlags), t.msgSize, t.maxSize,
		len(t.response.Answer), len(t.response.Ns), len(t.response.Extra), noteStr)
}

// setAuthority sets the authority - if any - for the current request.
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
