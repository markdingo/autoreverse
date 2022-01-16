package main

import (
	"crypto/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/database"
	"github.com/markdingo/autoreverse/delegation"
	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/osutil"
	"github.com/markdingo/autoreverse/resolver"
)

// The autoReverse container exists so that most of the "main" functionality can be
// delegated to support functions and help keep the flow of main() nice and clean.
type autoReverse struct {
	cfg *config

	done        chan struct{} // All collaborative go-routines should monitor - see Done()
	forceReload chan struct{} // Tell watcher to forcefully reload
	sig         chan os.Signal

	resolver resolver.Resolver
	dbGetter *database.Getter

	wg      sync.WaitGroup // For all servers started
	servers []*server

	startTime        time.Time
	statsTime        time.Time             // Last time stats were reset
	forward          string                // Canonical forward domain name
	forwardAuthority *delegation.Authority // Could be either delegated or local

	delegatedReverses []*net.IPNet
	localReverses     []*net.IPNet

	authorities []*delegation.Authority // Contains all authorities, including forward
}

func newAutoReverse(cfg *config, r resolver.Resolver) *autoReverse {
	t := &autoReverse{
		cfg:         cfg,
		done:        make(chan struct{}),
		forceReload: make(chan struct{}),
		sig:         make(chan os.Signal),
		resolver:    r,
		dbGetter:    database.NewGetter(),
	}
	if t.cfg == nil {
		t.cfg = newConfig()
	}
	if t.resolver == nil {
		t.resolver = resolver.NewResolver()
	}

	return t
}

// Done is the go idiomatic way to tell collaborative go-routines to exit. All such
// go-routines should include a "case <-autoreverse.Done(): return" in their select loop.
func (t *autoReverse) Done() <-chan struct{} {
	return t.done
}

// Return true if added. Return false if duplicate.
func (t *autoReverse) addAuthority(add *delegation.Authority) bool {
	for _, ta := range t.authorities {
		if add.Domain == ta.Domain {
			return false
		}
	}
	t.authorities = append(t.authorities, add)

	return true
}

// Open Listen sockets and start servers. Does not return until all servers have started
// or an error is detected.
//
// The server secrets for cookie generation are set here. Note that strictly the secret
// should be configurable so that anycast DNS servers can all generate the same cookie,
// but it's extremely unlikely that autoreverse will be used in that scenario, so for now,
// we just use a cryptographically strong random value.
func (t *autoReverse) startServers() {
	var cookieSecrets [2]uint64
	b := make([]byte, 16) // Effectively two uint64s
	rand.Read(b)          // as needed by siphash-2-4
	for ix := 0; ix < 16; ix = ix + 2 {
		cookieSecrets[0] <<= 8
		cookieSecrets[1] <<= 8
		cookieSecrets[0] |= uint64(b[ix])
		cookieSecrets[1] |= uint64(b[ix+1])
	}

	for _, network := range []string{dnsutil.UDPNetwork, dnsutil.TCPNetwork} {
		for _, addr := range t.cfg.listen {
			srv := newServer(t.cfg, t.dbGetter, t.resolver, network, addr)
			srv.cookieSecrets = cookieSecrets // All servers get the same secret
			err := t.startServer(srv)
			if err != nil {
				fatal(err)
			} else {
				t.servers = append(t.servers, srv)
				log.Major("Listen on: ", srv.network, " ", srv.address)
			}
		}
	}
}

// Stop all servers and only return when they have all exited
func (t *autoReverse) stopServers() {
	for _, srv := range t.servers {
		srv.stop()
	}
	t.wg.Wait() // Wait for them all to shutdown completely
}

// Constrain process via setuid, setgid and choot
//
// Security Note: Prior to go1.16.2 or thereabouts, osutil.Constrain() did not work
// properly on Linux due to syscall.Setsid()/syscall.Setgid() not being correctly applied
// to all threads in a process.
func (t *autoReverse) Constrain() {
	if len(t.cfg.user) > 0 || len(t.cfg.group) > 0 || len(t.cfg.chroot) > 0 {
		err := osutil.Constrain(t.cfg.user, t.cfg.group, t.cfg.chroot)
		if err != nil {
			fatal(err)
		}
		log.Major("Process Constraint: ", osutil.ConstraintReport(t.cfg.chroot))
	}
}

var soaTime = time.Now() // Set here so tests can over-ride

func (t *autoReverse) synthesizeSOA(auth *delegation.Authority, mboxDomain string) {
	auth.SOA.Hdr.Name = auth.Domain
	auth.SOA.Hdr.Class = dns.ClassINET
	auth.SOA.Hdr.Rrtype = dns.TypeSOA
	auth.SOA.Hdr.Ttl = t.cfg.TTLAsSecs
	if len(auth.NS) > 0 { // Zero is possible for locals
		auth.SOA.Ns = auth.NS[0].(*dns.NS).Ns
	} else {
		auth.SOA.Ns = auth.Domain
	}

	auth.SOA.Mbox = "hostmaster." + mboxDomain // Why not?
	auth.SOA.Serial = uint32(soaTime.Unix())

	auth.SOA.Refresh = 110040 // None of these timers really have much meaning
	auth.SOA.Retry = 110080   // but we have to populate them with something so give them
	auth.SOA.Expire = 28      // signature values which make "von Fastrand" proud.
	auth.SOA.Minttl = 9030    // Hit me up if you recognize all of these numbers.
}
