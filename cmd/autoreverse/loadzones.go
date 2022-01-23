package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/markdingo/autoreverse/database"
	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/resolver"
)

func newPTRZoneFromURL(r resolver.Resolver, s string) (*PTRZone, error) {
	url, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	pz := &PTRZone{
		resolver: r,
		url:      s,
		host:     url.Hostname(),
		port:     url.Port(),
		path:     url.Path,
	}

	switch url.Scheme {
	case "file":
		pz.scheme = fileScheme
		if len(pz.path) == 0 {
			return nil, fmt.Errorf(url.Scheme + " URL must contain a file system path")
		}
		if len(url.Hostname()) > 0 || len(url.Port()) > 0 {
			return nil, fmt.Errorf(url.Scheme + " URL cannot contain a host or port")
		}

		// Special case mostly for tests. if path starts with "/./" remove the
		// leading "/" to make it relative. Otherwise there is no way to specify a
		// relative path in a file: URL as url.Path always starts at the first
		// byte past the hostname, which by definition has to be a "/".
		if strings.HasPrefix(pz.path, "/./") {
			pz.path = pz.path[1:]
		}

	case "http", "https":
		pz.scheme = httpScheme
		if len(pz.host) == 0 {
			return nil, fmt.Errorf(url.Scheme + " URL must contain a host name")
		}
		if len(pz.path) == 0 {
			return nil, fmt.Errorf(url.Scheme + " URL path must contain a zone name")
		}

	case "axfr":
		pz.scheme = axfrScheme
		if len(pz.host) == 0 {
			return nil, fmt.Errorf(url.Scheme + " URL host must contain a name server name")
		}
		if len(pz.path) > 0 && pz.path[0] == '/' { // Path is zone name - remove leading /
			pz.path = pz.path[1:]
		}
		if len(pz.path) == 0 {
			return nil, fmt.Errorf(url.Scheme + " URL path must contain a zone name")
		}
		pz.domain = dns.CanonicalName(pz.path)
		if len(pz.port) == 0 {
			pz.port = defaultService
		}

		// We could allow all other schemes thru and let http.Get() deal with
		// potentially new schemes as they come along, but that risks letting thru
		// a scheme that we want to do additional check on, so for now, disallow
		// all unknown schemes.
	default:
		return nil, fmt.Errorf(url.Scheme + " is not a supported scheme")
	}

	return pz, nil
}

func (t *PTRZone) loadFromHTTP(db *database.Database, defaultTTL uint32) error {
	resp, err := http.Get(t.url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}

	t.dtm = time.Now() // Fake out a DTM for tests mostly

	parser := dns.NewZoneParser(resp.Body, "", t.url)
	parser.SetIncludeAllowed(false)
	parser.SetDefaultTTL(defaultTTL) // ZoneParser needs this in case $TTL is absent

	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		t.addRR(db, rr)
	}

	return parser.Err() // Check for parser errors
}

// loadFromFile reads the zone from a file and populates the PTR database with deduced
// and actual PTRs.
func (t *PTRZone) loadFromFile(db *database.Database, defaultTTL uint32) error {
	f, err := os.Open(t.path)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	t.dtm = fi.ModTime()

	parser := dns.NewZoneParser(f, "", t.path)
	parser.SetIncludeAllowed(true)
	parser.SetDefaultTTL(defaultTTL) // ZoneParser needs this in case $TTL is absent

	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		t.addRR(db, rr)
	}

	return parser.Err() // Check for parser errors
}

// loadFromAXFR AXFRs the domain and populates the PTR database with deduced and
// actual PTRs.
func (t *PTRZone) loadFromAXFR(db *database.Database) error {
	transfer := &dns.Transfer{}
	req := new(dns.Msg)
	req.SetAxfr(t.domain)
	host := normalizeHostPort(t.host, t.port)
	channel, err := transfer.In(req, host)
	if err != nil {
		return fmt.Errorf("Failed to fetch '%s' from %s:%w", t.domain, host, err)
	}
	t.dtm = time.Now() // Fake out a DTM for tests mostly

	for env := range channel { // I think this only ever returns one env...
		err := env.Error
		if err != nil {
			return err
		}
		for _, rr := range env.RR {
			t.addRR(db, rr)
		}
	}

	return nil
}

// loadAllZones populates the database with all forward names and PTRs found in the
// external zones. Return the number of errors detected.
//
// No checking is made to ensure that the deduced PTRs are within any zones of authority
// so this may load more PTRs than is strictly should, but it's simpler code this way. The
// DNS query logic ensures that out-of-bailiwick queries never get to the point of a
// database lookup, so by serendipity, we're safe being simple.
//
// Return true if load was successful
func (t *autoReverse) loadAllZones(pzs []*PTRZone, trigger string) bool {
	newDB := database.NewDatabase()
	var errorCount int
	for _, pz := range pzs {
		pz.loadTime = time.Now()
		var err error
		switch pz.scheme {
		case fileScheme:
			err = pz.loadFromFile(newDB, t.cfg.TTLAsSecs)

		case httpScheme:
			err = pz.loadFromHTTP(newDB, t.cfg.TTLAsSecs)

		case axfrScheme:
			err = pz.loadFromAXFR(newDB)
		}

		if err != nil {
			errorCount++
			warning(fmt.Errorf("PTRZone load of %s failed: %w", pz.url, err))
			continue
		}

		log.Minorf("Loaded: %s Lines=%d Deduced PTRs=%d Serial=%d Refresh=%d",
			pz.path, pz.lines, pz.added, pz.soa.Serial, pz.soa.Refresh)
	}

	if errorCount > 0 {
		log.Major("LoadAllZones Errors: ", errorCount, " - load abandoned.")
	} else {
		log.Majorf("LoadAllZones Total Deduced PTRs: %d. Trigger: %s\n",
			newDB.Count(), trigger)
		t.dbGetter.Replace(newDB) // Only replace if no errors in any zone
	}

	return errorCount == 0
}

func (t *PTRZone) addRR(db *database.Database, rr dns.RR) {
	t.lines++
	switch rrt := rr.(type) {
	case *dns.SOA:
		if t.lines == 1 { // Only look for SOA on first line
			t.soa = *rrt
		}
	case *dns.A, *dns.AAAA, *dns.PTR:
		if db.Add(rr) {
			t.added++
		}
	case *dns.CNAME:
		t.resolveAndAddCNAME(db, rrt)
	}
}

// Resolve the CNAME and add the address records into the database using the original RR
// qName.
func (t *PTRZone) resolveAndAddCNAME(db *database.Database, cname *dns.CNAME) {
	ips, err := t.resolver.LookupIPAddr(context.Background(), cname.Target)
	if err != nil {
		return // To bad, so sad. A dud CNAME is not our problem.
	}

	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			var rr dns.A
			rr.Hdr.Name = cname.Hdr.Name
			rr.Hdr.Class = cname.Hdr.Class
			rr.Hdr.Rrtype = dns.TypeA
			rr.A = ip4
			db.Add(&rr)
			t.added++
		} else if ip6 := ip.To16(); ip6 != nil {
			var rr dns.AAAA
			rr.Hdr.Name = cname.Hdr.Name
			rr.Hdr.Class = cname.Hdr.Class
			rr.Hdr.Rrtype = dns.TypeAAAA
			rr.AAAA = ip6
			db.Add(&rr)
			t.added++
		}
	}
}

// Periodically check whether any of the PTR-deduce zones needs reloading. A reload of all
// zones occurs when any of the zones reach their minimum reload or any of the files DTM
// changes. Because it's not easy to be notified of DTM changes across platforms, this
// routine simply polls at a relatively low rate. This go-routine exits when
// autoReverse->Done() closes.
//
// One this function is given control, only it can
func (t *autoReverse) watchForZoneReloads(pzs []*PTRZone, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-t.Done():
			return

		case <-t.forceReload:
			t.loadAllZones(pzs, "force reload")

		case now := <-ticker.C:
			trigger := t.checkForReload(pzs, now)
			if len(trigger) > 0 {
				t.loadAllZones(pzs, trigger)
			}
		}
	}
}

// checkForReload returns a trigger reason if a reload should be attempted. As soon as one
// condition determines that a reload is necessary then return that fact. Don't bother to
// check any others.
func (t *autoReverse) checkForReload(pzs []*PTRZone, now time.Time) string {
	for _, pz := range pzs {
		switch pz.scheme {
		case fileScheme:
			fi, err := os.Stat(pz.path)
			if err != nil {
				warning(err, "Could not stat zone file:"+pz.path)
				continue
			}
			if fi.ModTime().After(pz.dtm) {
				log.Debug(pz.path, "DTM triggers reload")
				return pz.url
			}

		case axfrScheme, httpScheme:
			nextLoad := pz.loadTime.Add(time.Second * time.Duration(pz.soa.Refresh))
			if now.After(nextLoad) {
				log.Debug(pz.domain, "Expired Refresh triggers reload")
				return pz.url
			}
		}
	}

	return ""
}
