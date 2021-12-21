package main

import (
	"fmt"
)

type queryStats struct {
	queries   int // Type specific query count
	good      int // Good replies sent back to client
	answers   int // Total answers sent in all good replies
	malformed int // qname does not conform to reverse conventions
	noSynth   int // Not in DB and not asked to synthesize
}

func (t *queryStats) add(from *queryStats) {
	t.queries += from.queries
	t.good += from.good
	t.answers += from.answers
	t.malformed += from.malformed
	t.noSynth += from.noSynth
}

func (t *queryStats) String() string {
	return fmt.Sprintf("q=%d good=%d(%d) mal=%d nodb=%d",
		t.queries, t.good, t.answers, t.malformed, t.noSynth)
}

type generalStats struct {
	queries int // Total queries

	formatError int // Pre-Authority counters

	chaos  int // EDNS sub-opts
	nsid   int
	cookie int

	wrongCookie int // Server cookie mismatch
	wrongClass  int
	noAuthority int

	authZoneANY  int // Authority Zone Counters
	authZoneSOA  int
	authZoneNS   int
	authZoneA    int
	authZoneAAAA int

	nxDomain int

	passthruOut int
	passthruIn  int
}

func (t *generalStats) add(from *generalStats) {
	t.queries += from.queries

	t.formatError += from.formatError
	t.chaos += from.chaos
	t.nsid += from.nsid
	t.cookie += from.cookie
	t.wrongCookie += from.wrongCookie
	t.wrongClass += from.wrongClass
	t.noAuthority += from.noAuthority
	t.authZoneANY += from.authZoneANY
	t.authZoneSOA += from.authZoneSOA
	t.authZoneNS += from.authZoneNS
	t.authZoneA += from.authZoneA
	t.authZoneAAAA += from.authZoneAAAA
	t.nxDomain += from.nxDomain

	t.passthruOut += from.passthruOut
	t.passthruIn += from.passthruIn
}

func (t *generalStats) String() string {
	return fmt.Sprintf("q=%d fe=%d ch=%d nsid=%d cookie=%d/%d wc=%d noaz=%d az=%d/%d/%d/%d/%d nx=%d pass=%d/%d",
		t.queries, t.formatError, t.chaos, t.nsid, t.cookie, t.wrongCookie,
		t.wrongClass, t.noAuthority,
		t.authZoneANY, t.authZoneSOA, t.authZoneNS, t.authZoneA, t.authZoneAAAA,
		t.nxDomain, t.passthruOut, t.passthruIn)
}

type serverStats struct {
	gen         generalStats
	APtr        queryStats
	AAAAPtr     queryStats
	AForward    queryStats
	AAAAForward queryStats
}

func (t *serverStats) add(from *serverStats) {
	t.gen.add(&from.gen)
	t.APtr.add(&from.APtr)
	t.AAAAPtr.add(&from.AAAAPtr)
	t.AForward.add(&from.AForward)
	t.AAAAForward.add(&from.AAAAForward)
}

func (t *serverStats) String() string {
	return "Gen: " + t.gen.String() +
		" APtr: " + t.APtr.String() +
		" AAAAPtr: " + t.AAAAPtr.String() +
		" AForward: " + t.AForward.String() +
		" AAAAForward: " + t.AAAAForward.String()
}
