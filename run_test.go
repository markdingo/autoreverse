package main

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/markdingo/autoreverse/database"
	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
	"github.com/markdingo/autoreverse/resolver"
)

func TestRun(t *testing.T) {
	testCases := []string{
		"Local Forward Zone",
		"IN/SOA",
		"Zone Authority",
		"Load Zones Of Authority",
		"Load Chaos",
		programName,
		"Ready",
		"Stats: Uptime",
		"Stats: Total q=0",
		"Stats: A Ptr q=0",
		"Stats: AAAA Ptr q=0",
		"Stats: A Forward q=0",
		"Stats: AAAA Forward q=0",
		"Signal",
		"log-queries=true",
		"log-queries=false",
		"PTR-deduce reload",
		"LoadAllZones Database Entries",
		"initiates shutdown",
		"All Listen servers stopped",
	}

	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.MinorLevel)

	cfg := newConfig()
	cfg.TTLAsSecs = 60
	cfg.chaosFlag = true
	cfg.reportInterval = time.Second * 3
	ar := newAutoReverse(cfg, nil)
	ar.generateLocalForward("example.net.")
	srv := newServer(cfg, database.NewGetter(), resolver.NewResolver(), "UDP", "[::1]:3053")
	ar.servers = append(ar.servers, srv)
	ar.startServers()
	go ar.Run()
	time.Sleep(time.Second * 4) // Give stats report time to trigger

	// Send all non-terminating signals and toggle USR2 (--log-queries toggle)

	for _, sig := range []os.Signal{syscall.SIGUSR1, syscall.SIGHUP, syscall.SIGUSR2, syscall.SIGUSR2} {
		ar.sig <- sig
		time.Sleep(time.Millisecond * 100)
	}

	// Send shutdown and wait for co-routine channel to close
	ar.sig <- syscall.SIGTERM
	<-ar.Done()
	time.Sleep(time.Second)
	got := out.String()
	for _, s := range testCases {
		if !strings.Contains(got, s) {
			t.Error("Does not contain", s)
			t.Error(got)
		}
	}
}
