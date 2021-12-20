package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/markdingo/autoreverse/database"
	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
	mockDNS "github.com/markdingo/autoreverse/mock/dns"
	"github.com/markdingo/autoreverse/resolver"
)

func TestNewPTRZoneFromURL(t *testing.T) {
	testCases := []struct{ url, host, path, contains string }{
		{"httpz://bogus.scheme.example.net/example.net.zone", "", "", "scheme"},
		{"file:///./testdata/example.net.zone", "", "./testdata/example.net.zone", ""},
		{"file://", "", "", "file system path"},
		{"file://host/./testdata/example.net.zone", "", "", "cannot contain"},
		{"file://:80/./testdata/example.net.zone", "", "", "cannot contain"},

		{"http://www.example.net/azone", "www.example.net", "/azone", ""},
		{"http:///azone", "", "", "must contain a host"},
		{"https://www.example.net", "", "", "must contain a zone"},

		{"axfr://ns.example.net/example.org", "ns.example.net", "example.org", ""},
		{"axfr://", "", "", "must contain a name"},
		{"axfr://ns.example.net", "", "", "must contain a zone"},

		{"ftp://ns.example.net", "", "", "not a supported scheme"},
		{"http:\n control char", "", "", "invalid control character"},
	}

	for ix, tc := range testCases {
		pz, err := newPTRZoneFromURL(resolver.NewResolver(), tc.url)
		if err != nil {
			if len(tc.contains) == 0 {
				t.Error(ix, "Unexpected error:", err.Error())
			} else if !strings.Contains(err.Error(), tc.contains) {
				t.Error(ix, "Wrong error returned. Exp:",
					tc.contains, "Got:", err.Error())
			}
			continue
		}
		if len(tc.contains) > 0 {
			t.Errorf("Expected error with '%s'", tc.contains)
		}
		if tc.host != pz.host {
			t.Error(ix, "hosts mismatch", tc.host, pz.host)
		}
		if tc.path != pz.path {
			t.Error(ix, "paths mismatch", tc.path, pz.path)
		}
	}
}

func TestLoadFromFile(t *testing.T) {
	log.SetOut(os.Stdout)
	log.SetLevel(log.SilentLevel)

	testCases := []struct {
		zone         string
		good         bool
		checkExample bool // example.net was loaded which has known, checkable values
		checkPtr     bool // the ULA reverse was loaded which has known, checkable values
		checkReload  bool // Test the checkForReload function
	}{
		{"example.net.zone", true, true, false, true},
		{"8.b.d.0.1.0.0.2.ip6.arpa.zone", true, false, true, true},
		{"bad.example.zone", false, false, false, false},
		{"noexist", false, false, false, false},
	}

	prefix := "file:///./testdata/loadzones/"
	for ix, tc := range testCases {
		ar := newAutoReverse(&config{TTLAsSecs: 61}, nil) // Needed by zone parser
		path := prefix + tc.zone
		pz, err := newPTRZoneFromURL(resolver.NewResolver(), path)
		if err != nil {
			t.Fatal(ix, "Setup error", err)
		}
		ar.cfg.PTRZones = append(ar.cfg.PTRZones, pz)
		good := ar.loadAllZones(ar.cfg.PTRZones, "TestLoadFromFile")
		if good && !tc.good {
			t.Error(ix, "Good return when expected fail", tc.zone)
			continue
		}
		if !good {
			if tc.good {
				t.Error(ix, "Expected good return, but got bad", tc.zone)
			}
			continue
		}

		if tc.checkExample {
			t.Run("file", func(t *testing.T) {
				checkExampleNet(t, tc.zone, ar.dbGetter.Current()) // Check zone loaded correctly
			})
		}

		if tc.checkPtr {
			t.Run("file", func(t *testing.T) {
				checkULAPtr(t, tc.zone, ar.dbGetter.Current()) // Check reverse loaded correctly
			})
		}

		if tc.checkReload {
			touch := func() {
				touch("testdata/loadzones/" + tc.zone)
			}

			t.Run("file", func(t *testing.T) {
				checkReload(t, ar, path, touch)
			})
		}

		// Check side-effects
		if pz.dtm.IsZero() {
			t.Error("loadZoneFromFile did not return a DTM", pz.dtm)
		}
		if pz.soa.Serial != 1636863624 {
			t.Error("Incorrect serial", pz.soa.Serial)
		}
	}
}

// Note that care must be taken with the test data as the axfr mock code sends it thru
// unfiltered and largely unchecked. This can cause the inbound axfr response to be
// bogus. For example, if you leave the @ or zone name off the SOA, that will still get
// sent, but will result in a very obscure header message error.
func TestLoadFromAXFR(t *testing.T) {
	log.SetOut(os.Stdout)
	log.SetLevel(log.SilentLevel)

	testCases := []struct {
		zone         string
		good         bool   // Should it load?
		checkExample bool   // example.net was loaded which has known, checkable values
		checkPtr     bool   // the ULA reverse was loaded which has known, checkable values
		checkReload  bool   // Test the checkForReload function
		ptrs         int    // Total address RRs turned into PTRs
		sampleIP     string // Confirm the load worked by checking the resulting
		sampleCount  int    // database with a sample IP to lookup
	}{
		{"example.net.", true, true, false, true, 9, "2001:db8::124", 1},
		{"8.b.d.0.1.0.0.2.ip6.arpa.", true, false, true, true, 2, "2001:db8::1", 1},
		{"example.com.", true, false, false, false, 0, "", 0},      // A purposely empty zone
		{"bad.example.zone", false, false, false, false, 0, "", 0}, // Zone format is bad
		{"noexist.zone", false, false, false, false, 0, "", 0},     // Zone does not exist
	}

	serverAddr := "127.0.0.1:6367"
	hTCP := &mockDNS.AxfrServer{Path: "./testdata/loadzones/"}
	mockDNS.StartServer("tcp", serverAddr, hTCP) // Doesn't return until up
	hTCP.SetResponse(&mockDNS.AXFRResponse{Rcode: -1})
	for ix, tc := range testCases {
		ar := newAutoReverse(&config{TTLAsSecs: 61}, nil) // Needed by zone parser
		url := fmt.Sprintf("axfr://%s/%s", serverAddr, tc.zone)
		pz, err := newPTRZoneFromURL(resolver.NewResolver(), url)
		if err != nil {
			t.Fatal("Setup error", err)
		}
		ar.cfg.PTRZones = append(ar.cfg.PTRZones, pz)

		good := ar.loadAllZones(ar.cfg.PTRZones, "TestLoadFromAXFR")
		if !good {
			if tc.good {
				t.Error(ix, url, "Expected good load from", url)
			}
			continue
		}
		if !tc.good {
			t.Error(ix, url, "Expected load to failed. But no error returned", url)
			continue
		}

		db := ar.dbGetter.Current() // Use PTR database to check results
		if tc.ptrs != db.Count() {
			t.Error(ix, url, "Expected", tc.ptrs, "PTRs, but loaded", db.Count())
		}

		// Check that the database matches what we expect. We're not testing the
		// database here, mere confirming, by way of a sample, that what was meant
		// to be loaded does appear to be the case.

		if len(tc.sampleIP) == 0 {
			continue
		}

		ptrs := db.Lookup(tc.sampleIP)
		if len(ptrs) != tc.sampleCount {
			t.Error(ix, url, "Load returned wrong sample count",
				tc.sampleIP, tc.sampleCount, len(ptrs))
		}

		if tc.checkExample {
			t.Run("axfr", func(t *testing.T) {
				checkExampleNet(t, url, ar.dbGetter.Current()) // Check zone loaded correctly
			})
		}

		if tc.checkPtr {
			t.Run("axfr", func(t *testing.T) {
				checkULAPtr(t, url, ar.dbGetter.Current()) // Check reverse loaded correctly
			})
		}

		if tc.checkReload {
			t.Run("axfr", func(t *testing.T) {
				checkReload(t, ar, url, nil)
			})
		}

		// Check side-effects
		if pz.dtm.IsZero() {
			t.Error(ix, url, "loadZoneFromFile did not return a DTM", pz.dtm)
		}
		if pz.soa.Serial != 1636863624 {
			t.Error(ix, url, "Incorrect serial", pz.soa.Serial)
		}
	}
}

// Odds and sods that don't fit anywhere elses
func TestOtherLoadErrors(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	ar := newAutoReverse(&config{TTLAsSecs: 61}, nil) // Needed by zone parser
	url := "axfr://127.0.0.1:6368/example.net."
	pz, err := newPTRZoneFromURL(resolver.NewResolver(), url)
	if err != nil {
		t.Fatal("Setup error", err)
	}
	ar.cfg.PTRZones = append(ar.cfg.PTRZones, pz)
	if ar.loadAllZones(ar.cfg.PTRZones, "TestOtherLoadErrors") {
		t.Fatal("Did not expect load to succeed")
	}

	got := out.String()
	exp := "Failed to fetch"
	if !strings.Contains(got, exp) {
		t.Error("dns.Transfer.In did not produce error. Want", exp, "got", got)
	}

	out.Reset()
	ar.cfg.PTRZones = make([]*PTRZone, 0)
	url = "http://127.0.0.1:6368/example.net."
	pz, err = newPTRZoneFromURL(resolver.NewResolver(), url)
	if err != nil {
		t.Fatal("Setup error", err)
	}
	ar.cfg.PTRZones = append(ar.cfg.PTRZones, pz)
	if ar.loadAllZones(ar.cfg.PTRZones, "TestOtherLoadErrors") {
		t.Fatal("Did not expect load to succeed")
	}

	got = out.String()
	exp = "connection refused"
	if !strings.Contains(got, exp) {
		t.Error("Get() fail did not produce error. Want", exp, "got", got)
	}
}

func TestLoadFromHTTP(t *testing.T) {
	log.SetOut(os.Stdout)
	log.SetLevel(log.SilentLevel)

	testCases := []struct {
		suffix       string
		good         bool   // Should it load?
		checkExample bool   // example.net was loaded which has known, checkable values
		checkPtr     bool   // the ULA reverse was loaded which has known, checkable values
		ptrs         int    // Total address RRs turned into PTRs
		sampleIP     string // Confirm the load worked by checking the resulting
		sampleCount  int    // database with a sample IP to lookup
	}{
		{"example.net.", true, true, false, 9, "2001:db8::124", 1},
		{"8.b.d.0.1.0.0.2.ip6.arpa.", true, false, true, 2, "2001:db8::1", 1},
		{"example.com.", true, false, false, 0, "", 0},      // A purposely empty zone
		{"bad.example.zone", false, false, false, 0, "", 0}, // Zone format is bad
		{"noexist.zone", false, false, false, 0, "", 0},     // Zone does not exist
	}

	// Create the listener inline so we know the socket is accepting
	// connections. Otherwise the tests may win the CPU before the server does.

	addr := "127.0.0.1:6380"
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal("Setup", err)
	}
	defer ln.Close()

	go func() {
		err := http.Serve(ln,
			http.FileServer(http.Dir("./testdata/loadzones")))
		if !strings.Contains(err.Error(), "use of closed network") {
			panic(err)
		}
	}()

	pList := []string{"http://" + addr + "/"}

	// Testing HTTPS with a loopback server is a bit of a pain so in my local test
	// environment I've "arranged" for a friendly public server to host the test files
	// behind HTTPS. If this arrangement is in place, the env variable
	// "autoreverse_https" will contain the appropriate prefix. If you want to do the
	// same, copy ./testfiles/loadzones/* to a location on your web server and run the
	// tests with:
	//
	// autoreverse_https=https://yourserver/somepath/ go test ...
	//
	// Include the trailing '/' in the autoreverse_https setting.

	httpsPrefix := os.Getenv("autoreverse_https")
	if len(httpsPrefix) > 0 {
		pList = append(pList, httpsPrefix)
	}

	for _, prefix := range pList {
		for ix, tc := range testCases {
			url := prefix + tc.suffix + "zone"
			ar := newAutoReverse(&config{TTLAsSecs: 61}, nil) // Needed by zone parser
			pz, err := newPTRZoneFromURL(resolver.NewResolver(), url)
			if err != nil {
				t.Fatal("Setup error: all urls are meant to be legit", err)
			}
			ar.cfg.PTRZones = append(ar.cfg.PTRZones, pz)
			good := ar.loadAllZones(ar.cfg.PTRZones, "TestLoadFromHTTP")
			if !good {
				if tc.good {
					t.Error(ix, "Expected good load from", url)
				}
				continue
			}
			if !tc.good {
				t.Error(ix, "Expected load to failed. But no error returned", url)
				continue
			}

			db := ar.dbGetter.Current() // Use PTR database to check results
			if tc.ptrs != db.Count() {
				t.Error("Expected", tc.ptrs, "PTRs, but loaded", db.Count())
			}

			// Check that the database matches what we expect. We're not testing the
			// database here, mere confirming, by way of a sample, that what was meant
			// to be loaded does appear to be the case.

			if len(tc.sampleIP) == 0 {
				continue
			}

			ptrs := db.Lookup(tc.sampleIP)
			if len(ptrs) != tc.sampleCount {
				t.Error(ix, "Load returned wrong sample count",
					tc.sampleIP, tc.sampleCount, len(ptrs))
			}

			if tc.checkExample {
				t.Run("http", func(t *testing.T) {
					checkExampleNet(t, url, ar.dbGetter.Current()) // Check zone loaded correctly
				})
			}

			if tc.checkPtr {
				t.Run("http", func(t *testing.T) {
					checkULAPtr(t, url, ar.dbGetter.Current()) // Check reverse loaded correctly
				})
			}

			// Check side-effects
			if pz.soa.Serial != 1636863624 {
				t.Error("Incorrect serial", pz.soa.Serial)
			}
		}
	}
}

func checkExampleNet(t *testing.T, src string, db *database.Database) {
	if db.Count() != 9 {
		t.Error(src, "did not load 9 PTRs, got", db.Count())
	}

	for _, ip := range []string{"192.0.2.123", "2001:db8::125",
		"8.8.8.8", "2001:4860:4860::8844"} {
		ptrs := db.Lookup(ip)
		if len(ptrs) != 1 {
			t.Error("Expected", ip, "to load one PTR from example.net.zone, not",
				len(ptrs))
		}
	}
}

func checkULAPtr(t *testing.T, src string, db *database.Database) {
	if db.Count() != 2 {
		t.Error(src, "did not load 2 PTRS, got", db.Count())
	}

	for _, ip := range []string{"2001:db8::1", "2001:db8::2"} {
		ptrs := db.Lookup(ip)
		if len(ptrs) != 1 {
			t.Error("Expected", ip,
				"to load one PTR from 8.b.d.0.1.0.0.2.ip6.arpa.zone, not",
				len(ptrs))
		}
	}
}

// This is a racy test as the watcher is meant to have complete ownership of the PTRZones,
// but we happen to know it's ok and it's only a test risk, rather than a production risk.
func checkReload(t *testing.T, ar *autoReverse, source string, trigger func()) {
	pz := ar.cfg.PTRZones[0] // Only called with a single PTRZone - must copy
	dtm := pz.dtm            // Note current value
	go ar.watchForZoneReloads(ar.cfg.PTRZones, time.Millisecond*100)
	if trigger != nil {
		trigger()
	} else {
		time.Sleep(time.Second * 5) // Rely on Refresh being < 5s
		ar.forceReload <- struct{}{}
	}
	time.Sleep(time.Second * 1) // make sure watcher has plenty of time
	if dtm == pz.dtm {
		t.Error("Watcher failed to reload", source)
	}
}

func touch(path string) {
	f, e := os.OpenFile(path, os.O_RDWR, 0)
	if e != nil {
		return
	}
	defer f.Close()

	buf := make([]byte, 1)
	l, e := f.ReadAt(buf, 0)
	if e != nil || l != 1 {
		return
	}
	f.WriteAt(buf, 0) // Should bump DTM
}
