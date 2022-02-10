package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/pregen"
)

func reportError(severity string, err error, messages ...string) {
	msg := severity
	if len(messages) > 0 {
		msg += ": " + strings.Join(messages, " ")
	}
	if err != nil {
		msg += ": " + err.Error()
	}
	fmt.Fprintln(log.Out(), msg)
}

func fatal(err error, messages ...string) {
	reportError("Fatal", err, messages...)
	os.Exit(1)
}

func warning(err error, messages ...string) {
	reportError("Warning", err, messages...)
}

//////////////////////////////////////////////////////////////////////

func main() {
	ar := newAutoReverse(nil, nil)
	switch ar.parseOptions(os.Args) {
	case parseStop:
		return
	case parseFailed:
		os.Exit(1)
	case parseContinue:
	}

	// Transfer logging options to the log package

	if ar.cfg.logMajorFlag {
		log.SetLevel(log.MajorLevel)
	}
	if ar.cfg.logMinorFlag {
		log.SetLevel(log.MinorLevel)
	}
	if ar.cfg.logDebugFlag {
		log.SetLevel(log.DebugLevel)
	}

	fmt.Fprintln(log.Out(),
		programName, pregen.Version, "Starting with Log Level:", log.Level())

	// Validate everything that is likely a typo or usage error
	err := ar.ValidateCommandLineOptions()
	if err != nil {
		fatal(err)
	}

	// Zone of Authority phase
	if len(ar.cfg.localForward) > 0 {
		ar.generateLocalForward(ar.cfg.localForward) // Synthesize local forward zone
	}

	ar.startServers() // Only returns if listens succeed

	err = ar.discover() // Discover all delegated zones
	if err != nil {
		fatal(err)
	}

	if len(ar.localReverses) > 0 { // Generate locals once forward is assured
		err = ar.generateLocalReverses()
		if err != nil {
			fatal(err)
		}
	}

	// Zones of Authority are set - ensure correct search order. This should rarely if
	// ever matter, but it's possible that one authority might legitimately be a
	// superset of another. The sort ensures that more specific zone comes first.
	ar.authorities.sort()

	ar.Constrain() // setuid/setgid/chroot

	if !ar.loadAllZones(ar.cfg.PTRZones, "Initial load") {
		fatal(nil, "Cannot continue due to failed -PTRZone load")
	}

	ar.Run()

	ar.statsReport(false) // Final stats - depending on log level

	fmt.Fprintln(log.Out(), programName, pregen.Version, "Exiting after",
		time.Now().Sub(ar.startTime).Round(time.Second))
}
