package main

import (
	"fmt"
	"runtime/debug"
	"time"

	"github.com/markdingo/rrl"
	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/resolver"
)

const (
	programName = "autoreverse"

	// Kinda subtle, but uppercase HTTPS implies BuildInfo was empty which in turn
	// implies a go1.16 compilation. That knowledge my be of some use to someone...
	defaultProjectURL = "HTTPS://github.com/markdingo/autoreverse"

	defaultService = "domain"
	defaultListen  = ":" + defaultService

	reloadInterval        = time.Minute * 10 // How often zone reloads are checked
	defaultReportInterval = time.Hour
)

var (
	defaultTTL = uint32(time.Hour.Seconds()) // One hour for synthetic PTRs
)

type loadScheme int

const (
	fileScheme loadScheme = iota
	httpScheme
	axfrScheme
)

// PTRZone manages the loading and reloading of PTR-deduce URLs.
type PTRZone struct {
	resolver                 resolver.Resolver // Convenience copy of system-wide resolver
	url                      string            // From command line option
	host, port, path, domain string            // Extracted from url.Parse()
	scheme                   loadScheme

	soa               dns.SOA   // Results of parsing
	dtm               time.Time // Last modified or last loaded
	loadTime          time.Time
	lines, added, oob int
}

// rrlConfigStrings separates out the RRL options from all the rest for easy management
// and identification.
type rrlConfigStrings struct {
	window       string // "--rrl-window"
	slipRatio    string // "--rrl-slip-ratio"
	maxTableSize string // "--rrl-max-table-size"

	ipv4PrefixLength string // "--rrl-ipv4-CIDR"
	ipv6PrefixLength string // "--rrl-ipv6-CIDR"

	responsesInterval string // "--rrl-responses-psec"
	nodataInterval    string // "--rrl-nodata-psec"
	nxdomainsInterval string // "--rrl-nxdomains-psec"
	referralsInterval string // "--rrl-referrals-psec"
	errorsInterval    string // "--rrl-errors-psec"
	requestsInterval  string // "--rrl-requests-psec"
}

// config defines the global configuration settings used by autoreverse. These setting
// apply across the whole program and all servers. Once set it should never be changed as
// it is shared amongst go-routines without an lock protections.
type config struct {
	projectURL string
	passthru   string // backend server to pass thru queries

	chaosFlag bool

	logMajorFlag   bool // Major events and on-going information such as periodic stats
	logMinorFlag   bool // Details associated with Major event
	logDebugFlag   bool // Developer flag
	logQueriesFlag bool // Each DNS Query exchanged

	synthesizeFlag bool

	TTL            time.Duration // TTLs for synthetic RRs
	TTLAsSecs      uint32        // Converted and rounded from TTL
	maxAnswers     int           // Maximum number of PTRs to place in Answers response
	reportInterval time.Duration // Statistics reporting interval. Zero means never.

	nsid      string  // Respond to EDNS NSID request with this string
	nsidAsHex string  // Encoding version
	nsidOpt   dns.OPT // Ready to send version

	user, group, chroot string // Privilege constraints

	delegatedForward string   // Forward zone to discover delegation
	localForward     string   // Forward zone with empty delegation
	delegatedReverse []string // Reverse CIDR to discover delegation
	localReverse     []string // Local reverses with empty delegation

	PTRDeduceURLs []string // Load zones from these URLs

	listen []string // All addresses to listen on

	PTRZones []*PTRZone // Populated from PTRDeduceURLs

	rrlOptions   rrlConfigStrings // Set by flags package
	rrlOptionSet bool             // True if at least one rrl option was set
	rrlDryRun    bool             // "--rrl-dryrun"
	rrlConfig    *rrl.Config      // Populated if RRL is active
}

func newConfig() *config {
	t := &config{projectURL: defaultProjectURL}
	info, ok := debug.ReadBuildInfo()
	if ok {
		t.projectURL = info.Main.Path // Override with embedded if present
	}

	t.rrlConfig = rrl.NewConfig() // This default config is a no-op

	return t
}

func (t *config) generateNSIDOpt() {
	// Prepopulate our NSID opt
	t.nsidOpt.Hdr.Name = "."
	t.nsidOpt.Hdr.Rrtype = dns.TypeOPT
	t.nsidOpt.Hdr.Ttl = 0 // extended RCODE and flags
	t.nsidOpt.SetUDPSize(dnsutil.MaxUDPSize)
	e := new(dns.EDNS0_NSID)
	e.Code = dns.EDNS0NSID
	e.Nsid = t.nsidAsHex
	t.nsidOpt.Option = append(t.nsidOpt.Option, e)
}

func (t *config) printVersion() {
	fmt.Fprintf(log.Out(), "Program:     %s %s (%s)\n",
		programName, Version, ReleaseDate)
	fmt.Fprintf(log.Out(), "Project:     %s\n", t.projectURL)
	fmt.Fprintf(log.Out(), "Inspiration: %s\n",
		"https://datatracker.ietf.org/doc/html/rfc8501#section-2.5")
}
