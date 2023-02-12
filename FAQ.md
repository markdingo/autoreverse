## autoreverse FAQ

### Table of Contents

1. [Why bother answering reverse DNS queries?](#why-bother-answering-reverse-dns-queries)
1. [What is the design philosophy behind autoreverse?](#what-is-the-design-philosophy-behind-autoreverse)
1. [What is DNS walking?](#what-is-dns-walking)
1. [What is DNS Probing?](#what-is-dns-Probing)
1. [My ISP insists that autoreverse runs first but autoreverse insists the ISP sets the delegation first - what do I do?](#my-isp-insists-that-autoreverse-runs-first-but-autoreverse-insists-the-isp-sets-the-delegation-first---what-do-i-do)
1. [Can autoreverse work behind a NAT?](#can-autoreverse-work-behind-a-nat)
1. [What is the recommended forward delegation snippet?](#what-is-the-recommended-forward-delegation-snippet)
1. [What is the recommended reverse delegation snippet?](#what-is-the-recommended-reverse-delegation-snippet)
1. [Can autoreverse serve ULAs - aka rfc1918 and rfc4193 addresses?](#can-autoreverse-serve-ulas---aka-rfc1918-and-rfc4193-addresses)
1. [Can autoreverse serve reverse ipv4 zones?](#can-autoreverse-serve-reverse-ipv4-zones)
1. [How does autoreverse go from knowing nothing to knowing everything?](#how-does-autoreverse-go-from-knowing-nothing-to-knowing-everything)
1. [How does passthru work?](#how-does-passthru-work)

### Why bother answering reverse DNS queries?

There are some within the DNS community who think reverse queries are a waste of time and
should be disbanded whereas others think they have value. It is certainly true that the
reverse DNS tree is very hit-and-miss in terms of valid and useful data. Perhaps that just
reflects the divergence of views?

The practical reality is that answering reverse DNS queries currently has value because
there are various processes, tools and services which rely on the reverse data for logging
or display purposes or which behave differently if the reverse data does not corroborate
with the forward data. The most obvious examples are tools like `traceroute`; services
like `sshd`, IMAP and POP mail servers, and processes such as Unix logins. Some mail servers
even use the results of reverse DNS lookups to influence their anti-spam systems.

From a general perspective, most network connections are logged at the server end. Often
it might just be the IP address but it's also common to log the reverse name or to analyze
the logs latter to render reverse names in preference to IP addresses.

So the short answer is that answering reverse queries means that logging entries offer
instant recognition over IP addresses - particularly ipv6 addresses. A good example
is `traceroute` which shows the reverse name of each hop, if available.

But there is another side-effect of missing reverse/forwards that is more noticeable and
inconvenient; namely the delays that the logging process incurs. Common examples are mail
servers and `sshd`.

When clients connect, these services not only query for the reverse data associated with
the client IP address, they also query the forward zone to check that the forward and
reverse names match.

The implications of no reverse answers or no forward/reverse matching are two-fold. First,
the log entries only offer the usual inscrutable ipv6 addresses, but depending on the
failure mode these services make repeated attempts to resolve the reverse/forward answers
and that involves significant delays while it waits for the resolver library to timeout.

The net result in the worst case is that client logins may be delayed by up to 25 seconds
while the resolver library attempts upto 5 retries (*RES_MAXRETRY*) with 5 second timeouts
(*RES_TIMEOUT*) to resolve the reverse entry.

This sort of delay typically occurs with a delegation to an un-responsive name server
which can occur with an ISP who has not bothered to establish a `wall` reverse DNS server
for their delegation. The best way to deal with this situation and eliminate those delays
is to have your assignment delegated to you, so you can ensure timely responses.

### What is the design philosophy behind autoreverse?

One of the peculiarities of the DNS is how much information is duplicated. For example,
most of the delegation details of a zone are present in both the parent zone and the child
zone. Similarly, PTR records in reverse zones are most often just replicas of A and AAAA
records in forward zones - albeit in a slightly different format.

Rather than continue the trend of insisting on configuration data with yet more
duplication, an over-arching philosophy of `autoreverse` is to avoid duplication whenever
possible by taking advantage of data already present in the DNS.

The most obvious example is where `autoreverse` deduces delegation and reverse information
by `walking` the DNS and issuing DNS Probes. Another example is where `autoreverse`
derives PTR values by loading forward zones.

### What is DNS walking?

While the DNS is hierarchical, not every label in the hierarchy is necessarily a
delegation. For example, the zone `example.net.` might exist as a delegation from `net.`,
but in `example.net.` there might be a delegation of `autoreverse.a.b.c.example.net.` with
no delegation of `a.b.c.example.net.`, `b.c.example.net.` or `c.example.net.`. One
real-life example is `sf.ca.us.` which is delegated directly from `us.` as there is no
`ca.us.` delegation. Another example are the name servers for `apple.com`. At the time of
writing they were `a.ns.apple.com.`, `b.ns.apple.com.`, `c.ns.apple.com.` and
`d.ns.apple.com.`. But there is no delegation for `ns.apple.com.`, those name server
entries exist in the `apple.com.` domain directly.

These delegation gaps mean that `autoreverse` cannot *discover* the delegation details of
a zone by simply removing one leading label and querying the DNS. Instead it has to keep
removing leading labels and query at each level until it gets a response or runs out of
labels. In other words it walks up the DNS tree towards the root until it gets a
delegation response. From there it can verify that the delegation points back to itself
with probing and then the delegation details can be used to populate a "Zone of
Authority".

DNS walking and DNS Probing combine to give `autoreverse` the ability to discover all the
delegation details it needs without requiring a replicated configuration. All it needs to
start the ball rolling is the domain name.

### What is DNS Probing?

After walking up the DNS to find a delegation, `autoreverse` collects the name server
names and their addresses for the delegated zone. The question to answer is, are any of
those name servers referring to the running instance of `autoreverse`?

The way `autoreverse` answers this question is to send a carefully crafted DNS query to
each name server address and see if the similarly carefully crafted response is returned.
Since each query and response contain a modestly unique "token", a returned response is
confirmation of the correlation between the delegated name server and the `autoreverse`
instance.

So, probing is simply sending a crafted DNS query to all relevant name servers and seeing
if any come back to the instance sending the query. If it does, `autoreverse` is said to
have "self-identified".

DNS walking and DNS Probing combine to give `autoreverse` the ability to discover all the
delegation details it needs to populate and serve a zone.

The main caveat to the success of DNS Probing is that the delegation details *must* be
in the DNS prior to the walk and probing.

### My ISP insists that autoreverse runs first but autoreverse insists the ISP sets the delegation first - what do I do?

Some ISPs insist on testing for a responding name server before they delegate reverse
zones to a customer's name server. The problem is that normally `autoreverse` won't start
without a valid reverse delegation. This is a "chicken and egg" problem as `autoreverse`
can't start because the ISP hasn't delegated and the ISP won't delegate until
`autoreverse` starts and answers.

The solution to this quandary is to temporarily use the `--local-reverse` option in place
of `--reverse` until the ISP completes the delegation. The `--local-reverse` setting
effectively means that `autoreverse` takes it on blind faith that it is the delegated name
server and will authoritatively answer any queries it can. This should satisfy the ISP
tests and they will then hopefully proceed with setting up your delegation.

Once your ISP configures the reverse delegation, simply restart `autoreverse` after
reverting `--local-reverse` back to `--reverse` and everyone should then be a happy
camper.

### Can autoreverse work behind a NAT?

Yes. DNS Probing may reach your router before being turned around (possibly due to a
hairpin NAT) and sent back to the `autoreverse` instance, but `self-identification` should
work in the presence of a NAT. In fact `autoreverse` expects to run behind a NAT which is
why it does DNS Probing rather than the simpler interface address matching.


### What is the recommended forward delegation snippet?

Assuming a deployment in a residential or small business environment where a single
reverse name server is sufficient, the snippet to add to your forward zone should look
something like this:

```sh
 $ORIGIN yourdomain.
 ;;
 autoreverse IN NS   autoreverse                 << Snippet to add
             IN AAAA 2001:db8:aa:bb::53          << Snippet to add
             IN A    192.0.2.53                  << Snippet to add
 ;;
```

which defines a single in-domain name server of `autoreverse.yourdomain` and makes
`autoreverse` authoritative for supplying that information.

If you prefer, the name server addresses need not be in-domain, as shown with this
snippet:


```sh
 $ORIGIN yourdomain.
 ;;
autoreverse  IN NS   outerns                     << Snippet to add
outerns      IN AAAA 2001:db8:aa:bb::53          << Snippet to add
             IN A    192.0.2.53                  << Snippet to add
 ;;
```

which works just as well. The main difference being that the parent zone is authoritative
for the name server address records rather than `autoreverse`.

The main reason for preferring the former snippet is that the `autoreverse` query log
provides more insight into who is making reverse queries.


### What is the recommended reverse delegation snippet?

That's an interesting question because normally the reverse delegation is managed by your
ISP or address provider. They will have some process (whether manual or online) which
merely asks for a name server name. If you've following the question above, then the
answer to their process is simply autoreverse.*yourdomain*.

Alternatively, if you control the parent zone then all you need to is a single delegation
line something like:

```sh
x.x.x.x.x.x.d.f.ip6.arpa. IN NS autoreverse.yourdomain.
```

### Can autoreverse serve ULAs - aka rfc1918 and rfc4193 addresses?

Absolutely; the `--local-reverse` and `--PTR-deduce` options are designed to support local
addresses.

For those unfamiliar, User Local Addresses (ULAs) specify ranges in both `ipv4` and `ipv6`
which are reserved for use on local networks and which are *never* routed on the global
internet. Almost everyone is familiar with the `192.168.0.0/16` and `10.0.0.0/8` `ipv4`
range but there is an even more extensive range set aside in `ipv6`. Specifically
`2001:db8::/32` is designated for use as ULAs. Furthermore, there is a bit more
organization behind `ipv6` ULAs to maximize uniqueness across different networks.

To quote from this [APNIC
blog](https://blog.apnic.net/2020/05/20/getting-ipv6-private-addressing-right/) "Several
ULA generator applications and websites are commonly available, and can easily be found
via an Internet search, or by looking in the smartphone application stores".

In short you use one of these generators to create your very own "unique" ULA range and
assign that range within your network. Then with `--local-reverse`, and possibly
`--PTR-deduce` to load deduced PTRs, `autoreverse` will serve this range.

Excepting there is one more step: telling your resolver infrastructure that the ULAs exist
and are resolved locally. How you do this varies greatly depending on your resolvers. If,
e.g., you use public resolvers such as `2001:4860:4860::8888` or `8.8.8.8`, or you use
your ISP's resolvers then there is no chance of resolving or using ULAs by name. This is
one of the big drawbacks to out-sourcing your resolvers to an ISP or a distant third-party
such as Google.

On the other hand, if you run your own resolver infrastructure then the process is
relatively straightforward, but again, it depends on exactly which resolver you are
using. In all cases you have to configure the local resolver to know that the
authoritative server for the ULA reverse range is the `autoreverse` instance.

To give an example with [unbound](https://nlnetlabs.nl/projects/unbound/about/), you use
the global `stub-zone` directive like this:

```sh
stub-zone:
        name: "x.x.x.x.x.x.x.x.x.x.x.2.d.f.ip6.arpa."
        stub-host: autoreverse.example.net.
        stub-prime: yes

```

and in the `server:` section, add the following line:

```sh
        local-zone: "d.f.ip6.arpa." nodefault
```

Yes, a bit fiddly.

### Can autoreverse serve reverse ipv4 zones?

Absolutely. `autoreverse` is ecumenical when it comes to `ipv4` and `ipv6`. The
`--reverse` and `--local-reverse` options both accept `ipv4` CIDRs.

### How does autoreverse go from knowing nothing to knowing everything?

During start-up, `autoreverse` performs the following auto-configuration and
self-identification steps:

1. Walk the forward DNS to find the `--forward` zone details and probe to self-identify.

1. Walk the reverse DNS to find `--reverse` zone details and probe to self-identify.

1. Synthesize SOAs from forward and reverse zones discovered in the previous steps.

1. Load all `--PTR-zone` sources to synthesize overlay PTR records.

1. Start responding to DNS queries.

### How does passthru work?

The `--passthru` option is experimental and time will tell whether it is useful or
not... The hope is that feature is useful to small sites which are only assigned a single
`ipv4 address by their ISP which is already in use by an existing name server.

What `--passthru` does, is make it possible to move the existing name server onto a
different listen address, whether that's on the same system or some other internal system,
then have `autoreverse` listen on port 53 of the external IP address previously in
use. You set `--passthru` to the listen address of the moved name server.

With `--passthru` set, `autoreverse` proxies all not in-domain (Class INET only) queries
thru to the existing name server and similarly proxies any response back to the original
client. The query and response are not modified in any way.

It is speculated that the potential risk with `--passthru` is that some resolvers which
track authoritative servers with cookies and maximum-packet sizes *may* get confused due
to two different types of responses originating from a single IP address. If this
speculation proves correct then it may mean reassessing the viability of this option.

***

