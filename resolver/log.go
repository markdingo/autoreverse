package resolver

import (
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/log"
)

// LogNS logs results from LookupNS. Exported for mock resolver. Caller should test for
// log.IfDebug() prior to calling.
func LogNS(name string, ns []*net.NS, note string, err error) {
	var s [5]string
	s[0] = "res:NS"
	s[1] = name
	if err != nil {
		s[3] = err.Error()
	} else {
		var ar []string
		for _, n := range ns {
			ar = append(ar, n.Host)
		}
		s[2] = strings.Join(ar, ",")
	}
	s[4] = note
	log.Debug(strings.Join(s[:], "#"))
}

// LogIP logs results from LookupIPAddr. Exported for mock resolver. Caller should test
// for log.IfDebug() prior to calling.
func LogIP(host string, addrs []net.IPAddr, note string, err error) {
	var s [5]string
	s[0] = "res:IP"
	s[1] = host
	if err != nil {
		s[3] = err.Error()
	} else {
		var ar []string
		for _, a := range addrs {
			ar = append(ar, a.IP.String())
		}
		s[2] = strings.Join(ar, ",")
	}
	s[4] = note
	log.Debug(strings.Join(s[:], "#"))
}

// LogExchangeQ logs the question given to miekg.Exchange(). Exported for mock
// resolver. Caller should test for log.IfDebug() prior to calling.
func LogExchangeQ(net, logName, server string, q dns.Question) {
	log.Debugf("miekg Q:%s:%s/%s q=%s",
		net, logName, server, dnsutil.PrettyQuestion(q))
}

// LogExchangeA logs the answer returned by miekg.Exchange(). See above.
func LogExchangeA(server string, question dns.Question, r *dns.Msg, err error) {
	if err == nil {
		log.Debug("miekg A:", dnsutil.PrettyMsg1(r))
	} else {
		log.Debugf("miekg E:%s/%s/%s %s",
			server, dnsutil.ChompCanonicalName(question.Name),
			dns.TypeToString[question.Qtype],
			dnsutil.ShortenLookupError(err).Error())
	}
}
