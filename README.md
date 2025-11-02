# autoreverse

`autoreverse` is a specialized authoritative DNS server whose goal is to make it as easy
as possible to auto-answer reverse queries without ever requiring reverse zone files.
`autoreverse` synthesizes reverse answers and automatically derives PTR answers from
forward zones.  Importantly, `autoreverse` automatically answers forward queries
corresponding to the synthetic reverse answers, meeting the requirements of many remote
services which insist on matching forward and reverse names.

`autoreverse` is designed to run on residential gateway routers and servers behind NATs
which acquire ISP-assigned addresses via DHCP or SLAAC, but it also runs on publicly
accessible servers with static network configurations.

`autoreverse` normally runs with a pre-configured forward and reverse delegation in the
global DNS but it also supports [rfc1918](https://datatracker.ietf.org/doc/html/rfc1918)
and [rfc4193](https://datatracker.ietf.org/doc/html/rfc4193) addresses - otherwise known
as private addresses or User Local Addresses in `ipv6` parlance.

On start-up, `autoreverse` extracts forward and reverse delegation details from the DNS to
synthesize its own "Zones of Authority". This approach to gleaning information from the
DNS represents an over-arching philosophy of `autoreverse` in that it never requires
configuration material which duplicates that already present in the DNS.

For more details consider the [Quick Start Guide](QUICKSTART.md), the
[FAQ](FAQ.md) or the [Command Line Usage](USAGE.md). Detailed
invocation documentation is provided by the [manpage](autoreverse.8)
rendered with `mandoc -a`.

### Project Status

[![Build Status](https://github.com/markdingo/autoreverse/actions/workflows/go.yml/badge.svg)](https://github.com/markdingo/autoreverse/actions/workflows/go.yml)
[![codecov](https://codecov.io/gh/markdingo/autoreverse/branch/main/graph/badge.svg?token=211OVOI2AV)](https://codecov.io/gh/markdingo/autoreverse)
[![CodeQL](https://github.com/markdingo/autoreverse/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/markdingo/autoreverse/actions/workflows/codeql-analysis.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/markdingo/autoreverse)](https://goreportcard.com/report/github.com/markdingo/autoreverse)
[![Go Reference](https://pkg.go.dev/badge/github.com/markdingo/autoreverse.svg)](https://pkg.go.dev/github.com/markdingo/autoreverse)

### Key Features

While `autoreverse` is a specialized reverse server, it does provide a number of
capabilities within that scope. Specifically it:


1. Synthesizes PTR responses in the reverse zone
1. Synthesizes matching/correlated A/AAAA responses in the forward zone
1. Auto-configures by deducing zone configuration with DNS Probing
2. Can load forward zones and derive corresponding PTR values from A, AAAA and CNAME RRs to intermingle with synthetic responses
4. Responds to zone specific queries such as NS, SOA and ANY
5. Is written in [go](https://golang.org) with resource efficiency in mind
6. Offers an experimental `--passtru` options which allows `autoreverse` to proxy queries to
a backend server - this could be useful in port-forwarding environments when port 53 is
already in use.


(For those new to DNS, a "reverse query" and "reverse lookup" are shorthand for a PTR
query in the "reverse DNS tree". These terms are used interchangeable in this document. If
you wish to know more, [Wikipedia](https://en.wikipedia.org/wiki/Reverse_DNS_lookup) has
details and [rfc8499](https://www.rfc-editor.org/rfc/rfc8499.html) is a great resource for
understanding and using correct DNS terminology.)

### Who should use autoreverse?

`autoreverse` is intended for small installations and home-gamers who want the reverse
lookup of their IP assignments to say something useful. Most often this occurs in
conjunction with ISPs who allow name server delegation of customer assigned
addresses. That's not to say `autoreverse` can't be deployed in other scenarios; after
all, you might be a sysadmin who wants all reverse queries directed to a zero-maintenance
system, in which case `autoreverse` can probably take care of that for you.


### What is meant by "auto-configures"?

`autoreverse` avoids redundant configuration and attempts to deduce just about everything
possible that's already present in the DNS. That means `autoreverse` can start up and
respond to PTR queries with the following invocation:

```sh
autoreverse --forward autoreverse.example.net --reverse 2001:db8::/64
```

Where `autoreverse.example.net` and `0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa`
are delegated to the listening addresses().


If you want to intermingle your own forward names from an existing zone into the PTR
answers, here is what the invocation might look like:

```sh
autoreverse --forward autoreverse.example.com --reverse 2001:db8::/64 \
            --listen 2001:db8::1                                      \
            --PTR-deduce file:///etc/nsd/example.net.zone             \
            --PTR-deduce axfr://a.ns.example.net/example.org
```

This invocation results in PTR queries returning matching A, AAAA and CNAME names from the
`--PTR-deduce` zones if present, otherwise a synthesized response is returned.

In all cases you should notice a complete absence of any tell-tale signs of reverse zone
files or PTR records.

## Getting Started

Since `autoreverse` relies on pre-existing forward and reverse delegation details to
deduce its own zone information, the first step is to add those delegation details into
the DNS. Here's an example of the recommended snippet for your forward zone:

```
  $ORIGIN yourdomain.
  ;;
  ;; Start of snippet
  ;;
  autoreverse IN NS   autoreverse
              IN AAAA 2001:db8:aa:bb::53
              IN A    192.0.2.53
  ;;
  ;; End of snippet
```

Reverse delegation is typically managed by your ISP or address assignment provider,
so normally you arrange with them to configure the reverse name server as
`autoreverse.yourdomain` to match the `NS` entry in the above snippet.

*And that's it!* That completes the setup needed to run `autoreverse`.

A likely invocation after this setup is something like:

```sh
autoreverse --forward autoreverse.yourdomain           \
            --listen 2001:db8::1 --listen 192.0.2.53   \
            --reverse 2001:db8:aa:bb::53/48
```

and `autoreverse` will figure out the rest and start answering PTR queries.

## Installation

Regardless of how you compile or install `autoreverse` you'll need a recent version of
[go](https://golang.org). 1.17 or later is recommended.

There are two ways to install `autoreverse`. The 'go' way and the 'Unix' way. While the
simplicity of installing the 'go' way has its merits, it doesn't install in traditional
Unix locations, nor does it install the manpage. The choice is up to you.

### Installation the 'go' way

```sh
go install github.com/markdingo/autoreverse@latest
```
or if you're after the leading edge, possibly:

```sh
go install github.com/markdingo/autoreverse@main
```

In either case, the end result should be an `autoreverse` executable in `$GOPATH/bin` or
`$HOME/go/bin`.


To test the installation, run the following command:

```sh
$GOPATH/bin/autoreverse -v
```

or possibly:

```sh
$HOME/go/bin/autoreverse -v
```

depending on your go setup.

All being well, you should see `autoreverse` print version details.

### Installation the 'Unix' way

To install `autoreverse` and its manpage the Unix way, the sources are downloaded then
built and installed via the `Makefile`.

```sh
git clone https://github.com/markdingo/autoreverse.git
cd autoreverse
make all
sudo make install
```

If `git clone` is unavailable to you, github offers a zip download function on the project
page.

To test the installation, run the following commands:

```sh
/usr/local/sbin/autoreverse -v
man autoreverse
```

All being well, you should see `autoreverse` print version details followed by the start
of the manpage.

### Target Systems and cross-compiling

`autoreverse` has been tested on various CPU architectures with FreeBSD, Linux and
macOS. The [Makefile](./Makefile) in the installation directory builds and installs
`autoreverse` into `/usr/local/sbin`. Modify as necessary.

`autoreverse` *may* compile and run on Windows but you can also cross-compile to Windows
on a Unix-like system. To assist in this the Makefile contains the `windowsamd64` and
`windows386` targets.

Perhaps of most interest to residential deployments is the possibility of installing
`autoreverse` on your gateway router. To that end, the Makefile has targets for a
few *prosumer* routers such as Ubiquiti Edge Routers and Mikrotik Router Boards. It should
be possible to target other platforms too! This project is very interested to hear of
attempts to install `autoreverse` on gateway routers so please provide feedback of
successes *and* failures.

### Community

If you have any problems using `autoreverse` or suggestions on how it can do a better job,
don't hesitate to create an [issue](https://github.com/markdingo/autoreverse/issues) on
the project home page. This package can only improve with your feedback.

### Copyright and License

`autoreverse` is Copyright :copyright: 2021, 2022, 2023 Mark Delany. This software is
licensed under the BSD 2-Clause "Simplified" License.
