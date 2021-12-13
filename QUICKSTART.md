## autoreverse Quick Start Guide

If you just want to get `autoreverse` running in a vanilla environment with no special
features, the steps are:

1. Create a forward delegation in your DNS
2. Request a reverse delegation from your ISP or address provider
3. Run `autoreverse`

#### 1. Create a forward delegation in your DNS

`autoreverse` needs a name space to append to synthetic PTR responses which it also uses
to respond to the forward queries on the synthetic names. The convention is to create a
sub-domain, or delegation called "autoreverse" with the following snippet added to your
zone file:

```sh
 $ORIGIN yourdomain.
 ;; Snippet starts
 autoreverse IN NS   autoreverse          ;; --forward name
             IN AAAA 2001:db8:aa:bb::53   ;; --listen address
             IN A    192.0.2.53           ;; --listen address
 ;; Snippet ends
```

(Obviously the **AAAA** and **A** addresses need tweaking to match the listen addresses
you've allocated for `autoreverse`.)


#### 2. Request a reverse delegation from your ISP or address provider

Normally you make a request to your ISP or address provider to arrange for the reverse
delegation to your `autoreverse` instance. Your provider will want to know that
`autoreverse.yourdomain` is the name server to add to the delegation. Unfortunately, some
providers insist that your reverse name server responds to queries *before* they'll act
on the delegation request. In this case read to the end of this guide, then revisit this
section. But the short answer is to run `autoreverse` with `--local-forward` while the ISP
verifies responsiveness.

#### 3. Run autoreverse

You need three pieces of information to run `autoreverse`: listen addresses; the forward
domain name created in the first step and the CIDR of your reverse assignment. Given those,
you start `autoreverse` with:

```sh
# autoreverse --listen ipv4-addr --listen ipv6-addr --forward autoreverse.yourdomain --reverse reverse-CIDR
```

That's it. You're done. If your delgations in the global DNS are correct, `autoreverse`
will find all the information it needs and start serving queries. To test this, perhaps
try a reverse query with `dig -x ip` where "ip" is in range of the `reverse-CIDR`?

---

#### That pesky special case

You may need to deal with the special case mentioned in [Step 2](#2. Request a reverse
delegation from your ISP or address provider) which is where your provider insists on
`autoreverse` running first before they will delegate. Since `autoreverse` requires the
`--forward` and `--reverse` delegations be in place before it starts, this requirement by
your provider creates a "chicken-and-egg" dilemma.

If this is your situation, simply invoke `autoreverse` with `--local-reverse` in place of
`--reverse` and `autoreverse` will run well enough for your provider to test the
delegation and proceed with their delegation process.

Once the delegation has completed, revert the `--local-reverse` back to `--reverse` and
`autoreverse` should pull in the "Zone of Authority" details from your ISP's delegation.

---
