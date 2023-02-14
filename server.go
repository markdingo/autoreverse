package main

import (
	"sync"

	"github.com/markdingo/rrl"
	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/database"
	"github.com/markdingo/autoreverse/delegation"
	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/resolver"
)

// mutables are set by the main go-routine during discovery and are read by the query
// processing code, thus they need mutex protection. The rule is that mutables must only
// ever be accessed by setMutable() and getMutable().
type mutables struct {
	ptrSuffix   string           // String to append to synthesized PTR names
	probe       delegation.Probe // Current probe if any
	authorities                  // Forward + all reverse zones of authority
}

// Set mutables under protection of a mutex. This is the only way they should be set.
func (t *server) setMutables(ps string, pr delegation.Probe, auths authorities) {
	t.mutablesMu.Lock()
	t.ptrSuffix = ps
	t.authorities = auths
	t.probe = pr
	t.mutablesMu.Unlock()
}

// Get a copy of mutables under protection of a mutex.
func (t *server) getMutables() mutables {
	t.mutablesMu.RLock()
	var ret mutables
	ret.ptrSuffix = t.ptrSuffix
	ret.probe = t.probe
	ret.authorities = t.authorities
	t.mutablesMu.RUnlock()

	return ret
}

// server is created for each listen address.
type server struct {
	cfg        *config
	resolver   resolver.Resolver
	dbGetter   *database.Getter
	rrlHandler *rrl.RRL // May be nil if not configured

	network string // Listen details
	address string

	miekg *dns.Server

	mutablesMu sync.RWMutex
	mutables   // Only ever access this via the mutables accessor functions

	statsMu sync.RWMutex
	stats   serverStats

	cookieSecrets [2]uint64
}

func newServer(cfg *config, dbGetter *database.Getter, r resolver.Resolver, rrlHandler *rrl.RRL, network, address string) *server {
	t := &server{
		cfg:        cfg,
		resolver:   r,
		dbGetter:   dbGetter,
		rrlHandler: rrlHandler,
		network:    network,
		address:    address,
	}

	if len(t.network) == 0 {
		t.network = dnsutil.UDPNetwork
	}

	t.miekg = &dns.Server{Net: t.network, Addr: t.address, ReusePort: true, Handler: t}

	// The miekg.defaultMsgAcceptFunc rejects Server Cookie queries (RFC7873#5.4) as
	// qdcount==0, so that function has been replaced with our own function with is
	// mostly a clone with the original qdcount != 1 commented out. We also take the
	// opportunity to gather stats on rejections as that wasn't previously possible.

	t.miekg.MsgAcceptFunc = func(dh dns.Header) dns.MsgAcceptAction {
		return t.customMsgAcceptFunc(dh)
	}

	return t
}

// Start starts accepting DNS queries by calling dns.ListenAndServe(). It waits until the
// service has actually started prior to returning to the caller by way of NotifyStartFunc.
//
// Returns error if the server fails to start or nil.
func (t *autoReverse) startServer(srv *server) error {
	t.wg.Add(1)

	hasStarted := make(chan error) // Make sure listener has started before returning
	srv.miekg.NotifyStartedFunc = func() {
		hasStarted <- nil
	}

	go func() {
		err := srv.miekg.ListenAndServe()
		t.wg.Done()
		if err != nil {
			hasStarted <- err
		}
		close(hasStarted)
	}()

	return <-hasStarted // Closed by t.miekg.NotifyStartedFunc

}

func (t *server) stop() {
	t.miekg.Shutdown()
}

func (t *server) addStats(from *serverStats) {
	t.statsMu.Lock()
	t.stats.add(from)
	t.statsMu.Unlock()
}

// Called from acceptFunc from within miekg when a query fails prior to our ServerDNS()
func (t *server) addAcceptError() {
	t.statsMu.Lock()
	t.stats.gen.badRequest++
	t.statsMu.Unlock()
}
