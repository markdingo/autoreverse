package main

import (
	"fmt"
	"strings"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/markdingo/autoreverse/log"
)

type parseResult int // This is a ternary variable
const (
	parseStop     parseResult = iota // No error, but don't continue
	parseContinue                    // No errors and continue
	parseFailed                      // Errors, do not continue
)

// Parsing command line options is an, er, interesting process as there is very little
// control over the formating and output that the various "flags" packages offer. They
// each have to their own style and if you don't like it, bad luck. In the follow code
// there have been a few liberties taken to get the output to look "nicer", IMO. In
// particular, some of the usage messages have a trailing \n to place a bit of white-space
// around dense option output. This can only be done with options that have no default
// value as otherwise the flag output puts the default message *after* the \n. So in some
// cases when a bit more whitespace is warranted, I couldn't do so due to the default
// message.
//
// Towards the end of this function you'll see the hoops need to disallow duplicate
// flags. It surprises me that most are happy to silently accept this ambiguity. Or am I
// missing some trivial setting regarding dupes?
//
// The usage output has generally been formated to fit within a 100 column terminal, tho
// the old school manpages are formated at 80 columns. Given how much space is burnt with
// the options, that limit would make the descriptions absurdly narrow. I guess the
// obvious answer is that flags packages should be terminal width aware and "do the right
// thing".
func (t *autoReverse) parseOptions(args []string) parseResult {
	var helpFlag, manpageFlag, versionFlag bool

	name := programName
	if len(args) > 0 {
		name = args[0]
	}

	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Consider '-h' for command-line usage")
	}

	fs.SetOutput(log.Out())

	// Non-config flags

	fs.BoolVarP(&helpFlag, "help", "h", false, "Print command-line usage")
	fs.BoolVar(&manpageFlag, "manpage", false,
		`Print complete mandoc - pipe into 'mandoc -a' to produce a
formatted manual page.
`)
	fs.BoolVarP(&versionFlag, "version", "v", false, "Print version and origin URL")

	// config flags

	fs.BoolVar(&t.cfg.chaosFlag, "CHAOS", true,
		`Answer CHAOS TXT queries for version.bind, version.server,
authors.bind, hostname.bind and id.server.`)

	fs.BoolVar(&t.cfg.logMajorFlag, "log-major", true, "Log major events to Stdout")
	fs.BoolVar(&t.cfg.logMinorFlag, "log-minor", false,
		"Log minor events to Stdout - this implies --log-major")
	fs.BoolVar(&t.cfg.logDebugFlag, "log-debug", false,
		"Log debug events to Stdout - this implies --log-minor")
	fs.BoolVar(&t.cfg.logQueriesFlag, "log-queries", true,
		`Log DNS queries to Stdout. This setting can be toggled with
SIGUSR2.`)
	fs.BoolVar(&t.cfg.synthesizeFlag, "synthesize", true,
		`Synthesize missing PTRs. If a PTR query cannot be satisfied from
-PTR-deduce zones then a synthetic response is generated based
on the forward zone. If unspecified "NXDomain" is returned
instead of a synthesized PTR.`)

	// config Durations

	fs.DurationVar(&t.cfg.TTL, "TTL", time.Second*time.Duration(defaultTTL),
		"TTL for synthetic responses (>= 1s)")
	fs.DurationVar(&t.cfg.reportInterval, "report", defaultReportInterval,
		"Interval between statistics reports (>= 1s)")

	// config ints

	fs.IntVar(&t.cfg.maxAnswers, "max-answers", 5,
		`Maximum PTRs to add to response - this helps limit response
sizes after max UDP size is taken into account.`)

	// config StringVars

	fs.StringVar(&t.cfg.chroot, "chroot", "",
		`Reduce privileges with chroot() after --listen.
`)
	fs.StringVar(&t.cfg.delegatedForward, "forward", "",
		`Forward zone to discover and serve. Delegation must be present
in the parent name servers. Cannot be used when --local-forward
is set.
`)
	fs.StringVar(&t.cfg.group, "group", "",
		"Reduce privileges with setgid() after --listen.")
	fs.StringVar(&t.cfg.localForward, "local-forward", "",
		`Local Forward zone to serve. No discovery is attempted and
the SOA is mostly empty. Cannot be used when --forward is set.
`)
	fs.StringVar(&t.cfg.nsid, "NSID", "",
		"Respond to EDNS NSID sub-opt with the specified string.")
	fs.StringVar(&t.cfg.passthru, "passthru", "",
		"DNS server to pass thru queries which are not in-domain.")
	fs.StringVar(&t.cfg.user, "user", "", "Reduce privileges with setuid() after --listen.")

	// config RRL StringVars - all RRL configs are set as strings so as to match the
	// interface provided by the rrl package. It does the actual conversion of numbers
	// and so forth and generates errors if they are invalid or out of range.

	fs.StringVar(&t.cfg.rrlOptions.window, "rrl-window", "",
		"Seconds during which response rates are tracked (default 15)")
	fs.StringVar(&t.cfg.rrlOptions.slipRatio, "rrl-slip-ratio", "",
		`Ratio of rate-limited responses given a truncated response over
a dropped response. A ratio of 0 disables slip processing and
thus all rate-limited responses are drop. A ratio of 1 means
every rate-limited response will be a truncated response and the
upper limit of 10 means 1 in every 10 rate-limited responses
will be a truncated with the remaining 9 being dropped (default
2).`)
	fs.StringVar(&t.cfg.rrlOptions.maxTableSize, "rrl-max-table-size", "",
		`Maximum number of responses to be tracked at one time. When
exceeded, rrl stops rate limiting new responses (default
100000).`)
	fs.BoolVar(&t.cfg.rrlDryRun, "rrl-dryrun", false,
		"Invoke RRL analysis but ignore recommended action")
	fs.StringVar(&t.cfg.rrlOptions.ipv4PrefixLength, "rrl-ipv4-CIDR", "",
		`The prefix length in bits to use for identifying a ipv4 client
CIDR (default 24).`)
	fs.StringVar(&t.cfg.rrlOptions.ipv6PrefixLength, "rrl-ipv6-CIDR", "",
		`The prefix length in bits to use for identifying a ipv6 client
CIDR (default 56).`)
	fs.StringVar(&t.cfg.rrlOptions.responsesInterval, "rrl-responses-psec", "",
		`The number of Answer responses allowed per second. An
allowance of 0 disables Answer rate limiting (default 0).`)
	fs.StringVar(&t.cfg.rrlOptions.nodataInterval, "rrl-nodata-psec", "",
		`The number of NoData responses allowed per second. An allowance
of 0 disables NoData rate limiting (defaults to
--rrl-responses-psec).`)
	fs.StringVar(&t.cfg.rrlOptions.nxdomainsInterval, "rrl-nxdomain-psec", "",
		`The number of NXDomain responses allowed per second. An
allowance of 0 disables NXDomain rate limiting (defaults to
--rrl-responses-psec).`)
	fs.StringVar(&t.cfg.rrlOptions.referralsInterval, "rrl-referrals-psec", "",
		`The number of Referral responses allowed per second. An
allowance of 0 disables Referral rate limiting (defaults to
--rrl-responses-psec).`)
	fs.StringVar(&t.cfg.rrlOptions.errorsInterval, "rrl-errors-psec", "",
		`The number of Error responses allowed per second (excluding
NXDomain). An allowance of 0 disables Error rate limiting
(defaults to --rrl-responses-psec).`)
	fs.StringVar(&t.cfg.rrlOptions.requestsInterval, "rrl-requests-psec", "",
		`The number requests allowed per second from a source IP.
An allowance of 0 disables rate limiting of requests. This
value applies solely to the claimed source IP of the query
(as masked by --rrl-*-CIDR) whereas all other settings apply to
response details (default 0).`)

	// config String Arrays

	fs.StringArrayVar(&t.cfg.PTRDeduceURLs, "PTR-deduce", []string{},
		"Load zone from URL and convert address records into PTRs")
	fs.StringArrayVar(&t.cfg.listen, "listen", []string{},
		`Address to listen on for DNS queries - accepts 'host:port',
':port', ':service', v4address:port or [v6address]:port syntax.
The default is ':domain'.
`)
	fs.StringArrayVar(&t.cfg.localReverse, "local-reverse", []string{},
		`CIDR of local reverse zone to serve. Intended for rfc1918 and
rfc4193 addresses (otherwise known as private addresses or
ULAs).

The CIDR represents a zone which is not expected to be visible
in the public DNS and is only visible locally where local
resolvers are configured to direct reverse queries to
autoreverse. How this is achieved varies greatly. See your
resolver documentation for details.
`)

	fs.StringArrayVar(&t.cfg.delegatedReverse, "reverse", []string{},
		`CIDR of reverse zone to discover and serve. Delegation must be
present in the parent name servers.
`)

	////////////////////////////////////////

	// Crazy as it is, but both the standard "flag" package and "spf13/pflag" allow
	// duplicate options without any warning to the user or the program. Importantly
	// it's impossible to detect with pflag unless you use all your own Value
	// implementations. At least with spf13 we can manage duplicates ourselves.

	dupes := make(map[string]bool) // True means dupes are ok

	dupes["help"] = true    // Documentation options that never run autoreverse
	dupes["version"] = true // can be duplicate because the user may be fumbling
	dupes["manpage"] = true // around trying to work it out.

	dupes["PTR-deduce"] = true // These are legitimately allowed multiple times and
	dupes["listen"] = true     // autoreverse honors all values.
	dupes["local"] = true
	dupes["local-reverse"] = true

	fs.SetInterspersed(false) // This GNU-ism breaks execute chaining, so turn it off!
	err := fs.ParseAll(args[1:],
		func(f *flag.Flag, v string) error {
			if tf, ok := dupes[f.Name]; ok {
				if tf {
					return fs.Set(f.Name, v)

				}
				return fmt.Errorf("Duplicate option '--%v %v' not allowed",
					f.Name, v)
			}
			dupes[f.Name] = false
			return fs.Set(f.Name, v)
		})

	if err != nil {
		fmt.Fprintln(log.Out(), "Error:", err.Error())
		return parseFailed
	}

	// Handle all documentation options locally

	if helpFlag {
		printUsage(t.cfg, fs)
		fmt.Println()
		t.cfg.printVersion()
		return parseStop
	}

	if versionFlag {
		t.cfg.printVersion()
		return parseStop
	}

	if manpageFlag {
		fmt.Fprint(log.Out(), string(Manpage))
		return parseStop
	}

	if fs.NArg() > 0 {
		fmt.Fprintf(log.Out(), "Error:Unexpected goop on command line: '%s'\n",
			strings.Join(fs.Args(), " "))
		return parseFailed
	}

	return t.parseRRLOptions()
}

// RRL options have to be treated specially because we're adhering to the interface of the
// imported rrl package which was inherited from the original rrl package. Not entirely
// sure that's a good idea, but we'll live with it for now.
//
// In essence, the rrl package does all the conversion to ints and floats then returns
// errors as necessary so at this level all values are accepted as strings without any
// validation.
//
// Since the rrl config starts life as a no-op config, at least one of the *psec values
// has to be set greater than zero otherwise rrl does nothing in the Debit() call. But
// this may not be obvious so as soon as any --rrl-* option is set we presume the callers
// wants a functional rrl so we also check that at least one *psec value is also set.
func (t *autoReverse) parseRRLOptions() parseResult {
	if !t.setRRLOption("window", t.cfg.rrlOptions.window) {
		return parseFailed
	}
	if !t.setRRLOption("slip-ratio", t.cfg.rrlOptions.slipRatio) {
		return parseFailed
	}
	if !t.setRRLOption("max-table-size", t.cfg.rrlOptions.maxTableSize) {
		return parseFailed
	}
	if !t.setRRLOption("ipv4-CIDR", t.cfg.rrlOptions.ipv4PrefixLength) {
		return parseFailed
	}
	if !t.setRRLOption("ipv6-CIDR", t.cfg.rrlOptions.ipv6PrefixLength) {
		return parseFailed
	}
	if !t.setRRLOption("responses-per-second", t.cfg.rrlOptions.responsesInterval) {
		return parseFailed
	}
	if !t.setRRLOption("nodata-per-second", t.cfg.rrlOptions.nodataInterval) {
		return parseFailed
	}
	if !t.setRRLOption("nxdomains-per-second", t.cfg.rrlOptions.nxdomainsInterval) {
		return parseFailed
	}
	if !t.setRRLOption("referrals-per-second", t.cfg.rrlOptions.referralsInterval) {
		return parseFailed
	}
	if !t.setRRLOption("errors-per-second", t.cfg.rrlOptions.errorsInterval) {
		return parseFailed
	}
	if !t.setRRLOption("requests-per-second", t.cfg.rrlOptions.requestsInterval) {
		return parseFailed
	}
	if !t.setRRLOption("requests-per-second", t.cfg.rrlOptions.requestsInterval) {
		return parseFailed
	}

	// Check that they haven't only set no-op rrl options
	if (t.cfg.rrlOptionSet || t.cfg.rrlDryRun) && !t.cfg.rrlConfig.IsActive() {
		fmt.Fprintln(log.Out(), "Error: RRL requires at least one -*psec option to activate")
		return parseFailed
	}

	return parseContinue
}

func (t *autoReverse) setRRLOption(name, value string) bool {
	if len(value) == 0 {
		return true
	}

	t.cfg.rrlOptionSet = true // Say at least one --rrl option is present
	err := t.cfg.rrlConfig.SetValue(name, value)
	if err != nil {
		fmt.Fprintln(log.Out(), "Error:", err.Error())
		return false
	}

	return true
}

// I trust all output devices can render UTF-8 these days otherwise the ellipses will look
// a bit odd.
func printUsage(cfg *config, fs *flag.FlagSet) {
	o := log.Out()
	fmt.Fprintln(o, "NAME")
	fmt.Fprintln(o, " ", programName, "-- a minimalist-configuration reverse DNS name server")
	fmt.Fprintln(o)
	fmt.Fprintln(o, "SYNOPSIS")
	fmt.Fprintln(o, "     autoreverse -h | --help | --manpage | -v | --version")
	fmt.Fprintln(o, "     autoreverse --forward zone-name | --local-forward zone-name")
	fmt.Fprintln(o, "                 --reverse CIDR\u2026 | --local-reverse CIDR\u2026")
	fmt.Fprintln(o, "                 [--listen listen-address]\u2026 [--PTR-deduce URL]\u2026")
	fmt.Fprintln(o, `                 [--passthru auth-server] [--synthesize=true]
                 [--CHAOS=true] [--NSID hostid] [--TTL time.Duration=1h]
                 [--user user-name] [--group group-name] [--chroot path]
                 [--log-major=true] [--log-minor] [--log-debug]
                 [--log-queries=true] [--report time.Duration=1h]
                 [--rrl-dryrun]
                 [--rrl-ipv4-CIDR length] [--rrl-ipv6-CIDR length]
                 [--rrl-max-table-size size] [--rrl-window size] [--rrl-slip-ratio ratio]
                 [--rrl-errors-psec seconds] [--rrl-nodata-psec seconds]
                 [--rrl-nxdomain-psec seconds] [--rrl-referrals-psec seconds]
                 [--rrl-requests-psec seconds] [--rrl-responses-psec seconds]`)

	fmt.Fprintln(o)
	fmt.Fprintln(o, "     Ellipses (\u2026) indicate options which can be specified multiple times.")
	fmt.Fprint(o, `
DESCRIPTION
     autoreverse is an authoritative DNS server with the goal of making it as
     easy as possible to auto-answer reverse queries for ipv4 and ipv6 with no
     need to ever manage reverse zone files.  autoreverse synthesizes reverse
     answers and automatically derives PTR answers from specified forward zones.

     Importantly, autoreverse automatically answers forward queries
     corresponding to the synthetic reverse answers which meets the requirements
     of many remote services which insist on matching forward/reverse names.

     autoreverse is designed to run on residential gateway routers and servers
     behind NATs which acquire ISP-assigned addresses via DHCP or SLAAC, but
     naturally autoreverse also runs on publicly accessible servers in static
     configuration environments.

     autoreverse normally runs with a pre-configured forward and reverse
     delegation in the global DNS but autoreverse also supports rfc1918 and
     rfc4193 addresses, otherwise known as private addresses or ULAs.

     On start-up, autoreverse extracts forward and reverse delegation details
     from the DNS to synthesize its own 'Zones of Authority'. This approach to
     gleaning information from the DNS represents an over-arching philosophy of
     autoreverse in that it never requires configuration which duplicates
     information already present in the DNS.

     See the manpage with the --manpage option for more details, but a typical
     invocation is:

           # autoreverse --forward autoreverse.example.net --reverse 2001:db8::/64

     Where ‘autoreverse.example.net’ and
     ‘0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.’ (the reverse zone for 2001:db8::/64)
     are delegated to the autoreverse listening interface(s).

     That's it! That's all that's needed to serve your reverse and matching
     forward queries.
`)
	fmt.Fprintln(o)
	fmt.Fprintln(o, "OPTIONS")
	op := fs.Output() // Save and restore - not sure this is a good idea
	fs.SetOutput(o)
	fs.PrintDefaults()
	fs.SetOutput(op)

	fmt.Fprint(o, `
NOTES
  1. --listen, --local-reverse, --reverse and --PTR-deduce can be repeated multiple times.
  2. RRL is only activated when at least one of the *-psec values is set above zero.

SIGNALS
  SIGHUP  - reload all -PTR-deduce urls
  SIGQUIT - Produce a stack dump and exit
  SIGTERM - initiate shutdown
  SIGINT  - initiate shutdown
  SIGUSR1 - generates an immediate stats report
  SIGUSR2 - toggles --log-queries
`)
}
