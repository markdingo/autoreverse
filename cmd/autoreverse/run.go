package main

import (
	"fmt"
	"os"
	"time"

	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/osutil"
	"github.com/markdingo/autoreverse/pregen"
)

// Run the server loop checking for signals and stats reports events
func (t *autoReverse) Run() {
	t.startTime = time.Now()
	t.statsTime = t.startTime
	for _, srv := range t.servers {
		srv.setMutables(t.forward, nil, t.authorities)
	}

	var signal os.Signal
	osutil.SignalNotify(t.sig) // Register interest in signals

	for _, a := range t.authorities.slice {
		log.Major("Zone Authority: ", a.Domain)
	}

	pzs := t.cfg.PTRZones         // Transfer ownership to watcher (even if there are none)
	t.cfg.PTRZones = []*PTRZone{} // and make sure it sticks!
	go t.watchForZoneReloads(pzs, reloadInterval)

	fmt.Fprintln(log.Out(), programName, pregen.Version, "Ready")

	// Conditionally create the periodic report channel. Fortunately select purposely
	// doesn't mind a nil channel, which is very convenient.
	var reportChannel <-chan time.Time
	if t.cfg.reportInterval > 0 {
		reportTicker := time.NewTicker(t.cfg.reportInterval)
		reportChannel = reportTicker.C
		defer reportTicker.Stop()
	}

	// Wait for any of: a signal, a reporting channel ticker or a reload ticker.

	stopFlag := false
	for !stopFlag {
		select {
		case <-reportChannel:
			t.statsReport(true)

		case signal = <-t.sig:
			switch {
			case osutil.IsSignalTERM(signal), osutil.IsSignalINT(signal):
				stopFlag = true

			case osutil.IsSignalUSR1(signal): // USR1 produces a status report
				t.statsReport(false)

			case osutil.IsSignalUSR2(signal): // USR1 toggles --log-queries
				t.cfg.logQueriesFlag = !t.cfg.logQueriesFlag // Not race-safe, but oh well.
				log.Majorf("--log-queries=%t", t.cfg.logQueriesFlag)

			case osutil.IsSignalHUP(signal):
				log.Major("SIGHUP --PTR-deduce reload initiated")
				t.forceReload <- struct{}{}

			default:
				log.Majorf("Signal '%s' reserved for future use", signal)
			}
		}
	}

	log.Majorf("Signal '%s' initiates shutdown", signal)
	close(t.done)   // Tell companion go-routines
	t.stopServers() // Tell servers and wait until they exit
	log.Minor("All Listen servers stopped")
}

var zeroStats serverStats

// Writes summary stats to Stdout
func (t *autoReverse) statsReport(resetCounters bool) {
	var totals serverStats
	for _, srv := range t.servers {
		srv.statsMu.Lock() // Take writer lock in case resetCounters is true
		totals.add(&srv.stats)
		if resetCounters {
			srv.stats = zeroStats
		}
		srv.statsMu.Unlock()
	}

	now := time.Now()
	upDuration := now.Sub(t.startTime)
	statsDuration := now.Sub(t.statsTime)
	if resetCounters {
		t.statsTime = now
	}
	upDuration = upDuration.Round(time.Second)
	statsDuration = statsDuration.Round(time.Second)

	// Include version with uptime for stats parsers. The presumption is that stats
	// output will change over release as more is learnt about what's desired. Adding
	// version is a deterministic way for such parsers to know exactly what to expect.

	log.Major("Stats: Uptime ", upDuration,
		" Stats Time: ", statsDuration, " ", pregen.Version)
	log.Major("Stats: Total ", totals.gen.String())
	log.Major("Stats: A Ptr ", totals.APtr.String())
	log.Major("Stats: AAAA Ptr ", totals.AAAAPtr.String())
	log.Major("Stats: A Forward ", totals.AForward.String())
	log.Major("Stats: AAAA Forward ", totals.AAAAForward.String())
}
