/*

Package database provides a hierarchical DNS lookup mechanism. LookupRR() requires a
class, type and FQDN and returns a set of RRs or an NXDOMAIN indication.

Once the database has been handed to a Getter() only Lookup() calls can be made as there
is no internal concurrency protection.

Expected usage is:

    db := database.NewDatabase(config)
    for {
        db.AddRR(dns.RR)
    }

    fmt.Println("Size", db.Count())
    for {
        rrset, nxDomain := db.LookupRR(...)
    }

database.Getter exists to assist with switching databases atomically.

For compatibility purpose, the older ptr database interfaces are also supported in
compat.go. These are Add() to add a PTR and Lookup() to look up PTRs given just an ip
address. These functions will presumably disappear once autoreverse is fully migrated over
to the newer interfaces.

*/
package database
