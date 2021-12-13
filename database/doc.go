/*

Package database provides a rudimentary PTR database for looking up PTRs by IP address.

It only has sufficient functionality to support autoreverse and is not intended as a
general-purpose PTR database.

Expected usage is:

    db := database.NewDatabase(config)
    for {
        db.Add(dns.RR) // Where dns.RR should be an A/AAAA otherwise an error is returned
    }
    db.Count()
    for {
        db.Lookup(...)
    }

The Database should be fully populated then only used for read access as their is no
concurrency protection.

database.Getter exists to assist with switching databases atomically.

*/
package database
