package resolver

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/log"
)

func (t *mockResolver) loadLookupFile(qClass, qType, qName string) (r dns.Msg, fname string) {
	fname = path.Join(t.dir, "lookup", strings.ToUpper(qClass), strings.ToUpper(qType), qName)
	return t.loadFile(fname), fname
}

func (t *mockResolver) loadExchangeFile(net, addr, qClass, qType, qName string) (r dns.Msg,
	fname string) {

	// addr is ipv4:service or [ipv6]:service - we want just the ip address to form
	// the path to the response RRs. Do a cheap&nasty extraction of the IP address.

	sx := 0
	var ex int
	if addr[0] == '[' {
		sx = 1
		ex = strings.Index(addr, "]")
	} else {
		ex = len(addr)
	}
	if ex == -1 {
		panic("Bogus IP Address:" + addr)
	}
	addr = addr[sx:ex]

	fname = path.Join(t.dir, "exchange", addr, strings.ToUpper(qClass), strings.ToUpper(qType), qName)
	return t.loadFile(fname), fname
}

// Attempt to open a mock file. If it doesn't exist, return REFUSED. If it does exist and
// is empty return NXDOMAIN. If it's not empty parse as a series of dns.NewRR() lines with
// a prefix indicating which section the RR belongs in:
//
// A:Answer
// N:NS
// E:Extra
// RCODE:miekg rcode string - must be uppercase - see miekg/msg.go lines 139 onwards.
// ;; Comment
// Blank lines ignored
// No spaces between the ":" separator
//
// If you set RCODE: then normally there should be no RRs in the message as no caller
// will look at them.
//
// If rCode is anything but NOERROR, the returned message has no reliable content.

func init() {
	path := os.Getenv("AUTOREVERSE_TRACE")
	if len(path) > 0 {
		var err error
		tracer, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
	}
}

var tracer *os.File

// It turns out that github and zip don't like filenames with colons, so we substitute
// with "_". This is all just test data so it has no impact on running code.
func (t *mockResolver) loadFile(fname string) (r dns.Msg) {
	fname = strings.ReplaceAll(fname, ":", "_")
	log.Debug("mock:Resolver:Open:", fname)
	file, err := os.Open(fname)
	if tracer != nil {
		_, e2 := fmt.Fprintf(tracer, "%s:%t\n", fname, err == nil)
		if e2 != nil {
			panic(e2)
		}
		tracer.Sync() // Because we never get a chance to close it
	}

	if err != nil { // Assume no exist
		r.MsgHdr.Rcode = dns.RcodeRefused
		return
	}
	defer file.Close()
	rcode := -1 // Means not set

	scanner := bufio.NewScanner(file)
	ln := 0
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSuffix(line, "\n")
		ln++
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(line, ";;") {
			continue
		}
		ar := strings.SplitN(line, ":", 2)
		if len(ar) != 2 { // Malformed is a setup error
			panic("Malformed loadfile " + fname)
		}

		if ar[0] == "RCODE" {
			rcode = dns.StringToRcode[ar[1]]
			log.Debugf("Mock:File:Rcode %d from '%s'\n", rcode, ar[1])
			continue
		}

		rr, err := dns.NewRR(ar[1])
		if err != nil {
			panic(err) // Parse failure is a setup error
		}

		switch ar[0] {
		case "A":
			r.Answer = append(r.Answer, rr)
		case "N":
			r.Ns = append(r.Ns, rr)
		case "E":
			r.Extra = append(r.Extra, rr)

		default:
			panic("filemock bad Section: " + ar[0])
		}
	}

	if rcode == -1 {
		if len(r.Answer) == 0 && len(r.Ns) == 0 && len(r.Extra) == 0 {
			rcode = dns.RcodeNameError // NXDOMAIN
		}
	}
	if rcode == -1 {
		rcode = dns.RcodeSuccess
	}
	r.MsgHdr.Rcode = rcode

	return
}
