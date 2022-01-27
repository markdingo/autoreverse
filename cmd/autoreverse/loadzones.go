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
	"github.com/markdingo/autoreverse/dnsutil"
	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/pregen"
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

func (t *PTRZone) loadFromHTTP(db *database.Database, auths authorities, defaultTTL uint32) error {
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
		t.addRR(db, auths, rr)
	}

	return parser.Err() // Check for parser errors
}

// loadFromFile reads the zone from a file and populates the PTR database with deduced
// and actual PTRs.
func (t *PTRZone) loadFromFile(db *database.Database, auths authorities, defaultTTL uint32) error {
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
		t.addRR(db, auths, rr)
	}

	return parser.Err() // Check for parser errors
}

// loadFromAXFR AXFRs the domain and populates the PTR database with deduced and
// actual PTRs.
func (t *PTRZone) loadFromAXFR(db *database.Database, auths authorities) error {
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
			t.addRR(db, auths, rr)
		}
	}

	return nil
}

// Load in-bailiwick Zone Of Authority address RRs into the candidate database. All other
// RRs (SOA, NS) have specific handled in the dns dispatch code so they need not be
// added. Regardless, we always add in the SOA it it's set so as to force a NoError vs
// NXDomain for authority queries with non-matching qTypes.
func (t *autoReverse) loadFromAuthorities(db *database.Database) (count int) {
	for _, auth := range t.authorities.slice {
		if auth.SOA.Hdr.Rrtype == dns.TypeSOA {
			db.AddRR(&auth.SOA)
		}
		for _, rr := range auth.AAAA {
			if t.findInBailiwick(rr.Header().Name) != nil {
				db.AddRR(rr)
				count++
			}
		}
		for _, rr := range auth.A {
			if t.findInBailiwick(rr.Header().Name) != nil {
				db.AddRR(rr)
				count++
			}
		}
	}

	return
}

func newTxt(qName, txt string, ttl uint32) (rr *dns.TXT) {
	rr = new(dns.TXT)
	rr.Hdr.Name = qName
	rr.Hdr.Class = dns.ClassCHAOS
	rr.Hdr.Rrtype = dns.TypeTXT
	rr.Hdr.Ttl = ttl
	rr.Txt = append(rr.Txt, txt)
	return
}

var commonCHAOSPrefix = programName + " " + pregen.Version + " " + pregen.ReleaseDate

// Load CHAOS RRs into candidate database. Caller has determined that chaos is enabled.
func (t *autoReverse) loadFromChaos(db *database.Database) (count int) {
	common1 := commonCHAOSPrefix + " " + t.cfg.projectURL
	db.AddRR(newTxt("version.server.", common1, t.cfg.TTLAsSecs))
	db.AddRR(newTxt("version.bind.", common1, t.cfg.TTLAsSecs))
	db.AddRR(newTxt("authors.bind.", common1, t.cfg.TTLAsSecs))

	db.AddRR(newTxt("hostname.bind.", t.cfg.nsid, t.cfg.TTLAsSecs))
	db.AddRR(newTxt("id.server.", t.cfg.nsid, t.cfg.TTLAsSecs))

	return 5
}

// loadAllZones creates a new database and populates it from exteral zones, the Zones Of
// Authority and the CHAOS statics. If there are no errors, the new database replaces the
// current one and true is returned.
func (t *autoReverse) loadAllZones(pzs []*PTRZone, trigger string) bool {
	newDB := database.NewDatabase()
	var errorCount int
	for _, pz := range pzs {
		pz.loadTime = time.Now()
		var err error
		switch pz.scheme {
		case fileScheme:
			err = pz.loadFromFile(newDB, t.authorities, t.cfg.TTLAsSecs)

		case httpScheme:
			err = pz.loadFromHTTP(newDB, t.authorities, t.cfg.TTLAsSecs)

		case axfrScheme:
			err = pz.loadFromAXFR(newDB, t.authorities)
		}

		if err != nil {
			errorCount++
			warning(fmt.Errorf("PTRZone load of %s failed: %w", pz.url, err))
			continue
		}

		log.Minorf("Loaded: %s Lines=%d Deduced PTRs=%d OOB=%d Serial=%d Refresh=%d",
			pz.path, pz.lines, pz.added, pz.oob, pz.soa.Serial, pz.soa.Refresh)
	}

	// Errors can only come from external loads, so deal with them now
	if errorCount > 0 {
		log.Majorf("LoadAllZones Abandoned. Errors: %d. Trigger: %s\n",
			errorCount, trigger)
		return false
	}

	c := t.loadFromAuthorities(newDB)
	log.Minorf("Load Zones Of Authority: %d\n", c)
	if t.cfg.chaosFlag {
		c = t.loadFromChaos(newDB)
		log.Minorf("Load Chaos: %d\n", c)
	}

	log.Majorf("LoadAllZones Database Entries: %d. Trigger: %s\n", newDB.Count(), trigger)

	t.dbGetter.Replace(newDB) // Can replace since no errors occurred

	return true
}

func (t *PTRZone) addRR(db *database.Database, auths authorities, rr dns.RR) {
	t.lines++
	switch rrt := rr.(type) {
	case *dns.SOA:
		if t.lines == 1 { // Only look for SOA on first line
			t.soa = *rrt
		}
	case *dns.A, *dns.AAAA:
		ptr, _ := dnsutil.DeducePtr(rr)
		if ptr != nil {
			t.addPTR(db, auths, ptr)
		}
	case *dns.PTR:
		t.addPTR(db, auths, rrt)
	case *dns.CNAME:
		t.resolveAndAddCNAME(db, auths, rrt)
	}
}

// Add the PTR into the database iff it's in-bailiwick
func (t *PTRZone) addPTR(db *database.Database, auths authorities, ptr *dns.PTR) {
	if auths.findInBailiwick(ptr.Hdr.Name) != nil {
		if db.AddRR(ptr) {
			t.added++
		}
	} else {
		t.oob++
	}
}

// Resolve the CNAME and add the address records into the database using the original RR
// qName.
func (t *PTRZone) resolveAndAddCNAME(db *database.Database, auths authorities, cname *dns.CNAME) {
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
			ptr, _ := dnsutil.DeducePtr(&rr)
			if ptr != nil {
				t.addPTR(db, auths, ptr)
			}
		} else if ip6 := ip.To16(); ip6 != nil {
			var rr dns.AAAA
			rr.Hdr.Name = cname.Hdr.Name
			rr.Hdr.Class = cname.Hdr.Class
			rr.Hdr.Rrtype = dns.TypeAAAA
			rr.AAAA = ip6
			ptr, _ := dnsutil.DeducePtr(&rr)
			if ptr != nil {
				t.addPTR(db, auths, ptr)
			}
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
