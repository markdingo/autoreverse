package resolver

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
)

const (
	defaultSingleExchangeTimeout = 4 * time.Second // Also applies to Lookup* functions
	defaultfFullExchangeTimeout  = 3 * defaultSingleExchangeTimeout
	defaultQueryTries            = 2 // Total number of exchange attempts
)

// ExchangeConfig expresses settings which were previously passed to miekg via a
// Client struct. Only the ones relevant to autoreverse have been transferred across to
// ExchangeConfig. It's defined as an interface rather than a struct to enforce the use
// of NewExchangeConfig with sets default.
type ExchangeConfig interface {
	Net() string
	UDPSize() uint16
	setNet(s string)
}

type exchangeConfig struct {
	net     string // Not sure whether this is needed or the right place
	udpSize uint16
}

func (t *exchangeConfig) Net() string     { return t.net }
func (t *exchangeConfig) UDPSize() uint16 { return t.udpSize }
func (t *exchangeConfig) setNet(s string) { t.net = s }

func NewExchangeConfig() *exchangeConfig {
	return &exchangeConfig{net: dnsutil.UDPNetwork, udpSize: dnsutil.MaxUDPSize}
}

// Resolver represents the Frankenstein interface which supports *all* of the resolver
// functions used by autoreverse which reach out to the internet. All non-networking
// functions are still called directly by the application.
//
// Based on the claim that both net.Resolver and miekg.Client are concurrency safe, then
// implementations of this interface must also ensure concurrency safety.
//
// Arguably having the caller pass a context is bogus since all callers in this
// application pass in context.Background() so the Resolver functions could just refer to
// that directly. Nonetheless, context is the future, so we've left that complexity in
// place.
type Resolver interface {

	// LookupNS is similar to net.Resolver.LookupNS.
	//
	// LookupNS derives a WithDeadline context from the supplied context so there is
	// no need for the caller to worry about timeouts.
	LookupNS(context.Context, string) ([]string, error)

	// LookipIPAddr is similar to net.Resolver.LookupAddr.
	//
	// LookupIPAddr derives a WithDeadline context from the supplied context so there
	// is no need for the caller to worry about timeouts.
	LookupIPAddr(context.Context, string) ([]net.IP, error)

	// SingleExchange is a shim for the github.com/miekg/dns ExchangeContext function
	// which makes a single exchange attempt with the server; no retries, no fallback
	// to TCP. See FullExchange() for that capability.
	//
	// ExchangeConfig defines parameters which were originally passed thru to miekg
	// via the the miekg.Client struct but we want to reduce complexity where possible
	// to simplify alternative implementations of Resolver.
	//
	// SingleExchange sets the dns.Client.Timeout to singleExchangeTimeout so the
	// caller doesn't have to worry about timeouts via context, or whatever.
	//
	// The dns.Msg must be fully formed with all flags and Id set as needed by the
	// caller.
	//
	// logName is normally the domainName of server and is only used for logging
	// purposes to help identify the server (which is normally an ip address in the
	// autoreverse context).
	SingleExchange(ctx context.Context, c ExchangeConfig, q *dns.Msg,
		server, logName string) (r *dns.Msg, rtt time.Duration, err error)

	// FullExchange is a wrapper around SingleExchange which handles timeouts and
	// truncation. It also creates a fully-formed dns.Msg for SingleExchange.
	//
	// FullExchange derives a WithDeadline context from the supplied context to manage
	// timeouts so the caller doesn't have to do that themselves. This timeout applies
	// across the whole of FullExchange processing including retries and truncation
	// processing. The SingleExchange timeouts still apply across calls to it thus
	// there are in effect two timeouts active for exchanges initiated via
	// FullExchange.
	FullExchange(ctx context.Context, c ExchangeConfig, q dns.Question,
		server, logName string) (r *dns.Msg, rtt time.Duration, err error)
}
