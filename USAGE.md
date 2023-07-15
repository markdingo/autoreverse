# autoreverse usage

The following documentation is auto-generated with `autoreverse -h` from @latest. It may
not reflect the most recent changes to @master.


```
NAME
  autoreverse -- a minimalist-configuration reverse DNS name server

SYNOPSIS
     autoreverse -h | --help | --manpage | -v | --version
     autoreverse --forward zone-name | --local-forward zone-name
                 --reverse CIDR… | --local-reverse CIDR…
                 [--listen listen-address]… [--PTR-deduce URL]…
                 [--passthru auth-server] [--synthesize=true]
                 [--CHAOS=true] [--NSID hostid] [--TTL time.Duration=1h]
                 [--user user-name] [--group group-name] [--chroot path]
                 [--log-major=true] [--log-minor] [--log-debug]
                 [--log-queries=true] [--report time.Duration=1h]
                 [--rrl-dryrun]
                 [--rrl-ipv4-CIDR length] [--rrl-ipv6-CIDR length]
                 [--rrl-max-table-size size] [--rrl-window size] [--rrl-slip-ratio ratio]
                 [--rrl-errors-psec seconds] [--rrl-nodata-psec seconds]
                 [--rrl-nxdomain-psec seconds] [--rrl-referrals-psec seconds]
                 [--rrl-requests-psec seconds] [--rrl-responses-psec seconds]

     Ellipses (…) indicate options which can be specified multiple times.

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

OPTIONS
      --CHAOS                       Answer CHAOS TXT queries for version.bind, version.server,
                                    authors.bind, hostname.bind and id.server. (default true)
      --NSID string                 Respond to EDNS NSID sub-opt with the specified string.
      --PTR-deduce stringArray      Load zone from URL and convert address records into PTRs
      --TTL duration                TTL for synthetic responses (>= 1s) (default 1h0m0s)
      --chroot string               Reduce privileges with chroot() after --listen.

      --forward string              Forward zone to discover and serve. Delegation must be present
                                    in the parent name servers. Cannot be used when --local-forward
                                    is set.

      --group string                Reduce privileges with setgid() after --listen.
  -h, --help                        Print command-line usage
      --listen stringArray          Address to listen on for DNS queries - accepts 'host:port',
                                    ':port', ':service', v4address:port or [v6address]:port syntax.
                                    The default is ':domain'.

      --local-forward string        Local Forward zone to serve. No discovery is attempted and
                                    the SOA is mostly empty. Cannot be used when --forward is set.

      --local-reverse stringArray   CIDR of local reverse zone to serve. Intended for rfc1918 and
                                    rfc4193 addresses (otherwise known as private addresses or
                                    ULAs).

                                    The CIDR represents a zone which is not expected to be visible
                                    in the public DNS and is only visible locally where local
                                    resolvers are configured to direct reverse queries to
                                    autoreverse. How this is achieved varies greatly. See your
                                    resolver documentation for details.

      --log-debug                   Log debug events to Stdout - this implies --log-minor
      --log-major                   Log major events to Stdout (default true)
      --log-minor                   Log minor events to Stdout - this implies --log-major
      --log-queries                 Log DNS queries to Stdout. This setting can be toggled with
                                    SIGUSR2. (default true)
      --manpage                     Print complete mandoc - pipe into 'mandoc -a' to produce a
                                    formatted manual page.

      --max-answers int             Maximum PTRs to add to response - this helps limit response
                                    sizes after max UDP size is taken into account. (default 5)
      --passthru string             DNS server to pass thru queries which are not in-domain.
      --report duration             Interval between statistics reports (>= 1s) (default 1h0m0s)
      --reverse stringArray         CIDR of reverse zone to discover and serve. Delegation must be
                                    present in the parent name servers.

      --rrl-dryrun                  Invoke RRL analysis but ignore recommended action
      --rrl-errors-psec string      The number of Error responses allowed per second (excluding
                                    NXDomain). An allowance of 0 disables Error rate limiting
                                    (defaults to --rrl-responses-psec).
      --rrl-ipv4-CIDR string        The prefix length in bits to use for identifying a ipv4 client
                                    CIDR (default 24).
      --rrl-ipv6-CIDR string        The prefix length in bits to use for identifying a ipv6 client
                                    CIDR (default 56).
      --rrl-max-table-size string   Maximum number of responses to be tracked at one time. When
                                    exceeded, rrl stops rate limiting new responses (default
                                    100000).
      --rrl-nodata-psec string      The number of NoData responses allowed per second. An allowance
                                    of 0 disables NoData rate limiting (defaults to
                                    --rrl-responses-psec).
      --rrl-nxdomain-psec string    The number of NXDomain responses allowed per second. An
                                    allowance of 0 disables NXDomain rate limiting (defaults to
                                    --rrl-responses-psec).
      --rrl-referrals-psec string   The number of Referral responses allowed per second. An
                                    allowance of 0 disables Referral rate limiting (defaults to
                                    --rrl-responses-psec).
      --rrl-requests-psec string    The number requests allowed per second from a source IP.
                                    An allowance of 0 disables rate limiting of requests. This
                                    value applies solely to the claimed source IP of the query
                                    (as masked by --rrl-*-CIDR) whereas all other settings apply to
                                    response details (default 0).
      --rrl-responses-psec string   The number of Answer responses allowed per second. An
                                    allowance of 0 disables Answer rate limiting (default 0).
      --rrl-slip-ratio string       Ratio of rate-limited responses given a truncated response over
                                    a dropped response. A ratio of 0 disables slip processing and
                                    thus all rate-limited responses are drop. A ratio of 1 means
                                    every rate-limited response will be a truncated response and the
                                    upper limit of 10 means 1 in every 10 rate-limited responses
                                    will be a truncated with the remaining 9 being dropped (default
                                    2).
      --rrl-window string           Seconds during which response rates are tracked (default 15)
      --synthesize                  Synthesize missing PTRs. If a PTR query cannot be satisfied from
                                    -PTR-deduce zones then a synthetic response is generated based
                                    on the forward zone. If unspecified "NXDomain" is returned
                                    instead of a synthesized PTR. (default true)
      --user string                 Reduce privileges with setuid() after --listen.
  -v, --version                     Print version and origin URL

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

Program:     autoreverse v1.4.0 (2023-02-14)
Project:     github.com/markdingo/autoreverse
Inspiration: https://datatracker.ietf.org/doc/html/rfc8501#section-2.5
```
