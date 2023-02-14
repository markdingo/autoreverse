package main

import (
	"fmt"
)

// qTypeStats is for high activity qTypes: A, AAAA, in-addr.arpa & ip6.arps PTR.
type qTypeStats struct {
	queries int // Type specific query count
	good    int // Good replies sent back to client
	answers int // Total RRs sent in all good replies

	truncated   int // Returns from InvertPtr*
	invertError int
}

func (t *qTypeStats) add(from *qTypeStats) {
	t.queries += from.queries
	t.good += from.good
	t.answers += from.answers
	t.truncated += from.truncated
	t.invertError += from.invertError
}

func (t *qTypeStats) String() string {
	return fmt.Sprintf("q=%d good=%d(%d) trunc=%d invErr=%d",
		t.queries, t.good, t.answers, t.truncated, t.invertError)
}

type generalStats struct {
	queries    int // Total queries
	badRequest int // No Question, wrong op-code

	chaos int
	nsid  int

	cookie          int
	cookieOnly      int
	wrongCookie     int // Server cookie mismatch
	malformedCookie int

	passthruOut int
	passthruIn  int

	chaosRefused int // Refused counters
	noAuthority  int
	wrongClass   int

	authZoneANY int // Authority Zone Counters
	authZoneSOA int
	authZoneNS  int

	truncatedV6 int
	truncatedV4 int

	dbDone     int
	dbNoError  int
	dbNXDomain int
	dbFormErr  int

	synthForward int
	synthReverse int
	noSynth      int

	synthDone     int
	synthNoError  int
	synthNXDomain int
	synthFormErr  int
}

func (t *generalStats) add(from *generalStats) {
	t.queries += from.queries
	t.badRequest += from.badRequest
	t.chaos += from.chaos
	t.nsid += from.nsid
	t.cookie += from.cookie
	t.cookieOnly += from.cookieOnly
	t.wrongCookie += from.wrongCookie
	t.malformedCookie += from.malformedCookie
	t.passthruOut += from.passthruOut
	t.passthruIn += from.passthruIn
	t.chaosRefused += from.chaosRefused
	t.noAuthority += from.noAuthority
	t.wrongClass += from.wrongClass
	t.authZoneANY += from.authZoneANY
	t.authZoneSOA += from.authZoneSOA
	t.authZoneNS += from.authZoneNS
	t.truncatedV6 += from.truncatedV6
	t.truncatedV4 += from.truncatedV4
	t.dbDone += from.dbDone
	t.dbNoError += from.dbNoError
	t.dbNXDomain += from.dbNXDomain
	t.dbFormErr += from.dbFormErr
	t.synthForward += from.synthForward
	t.synthReverse += from.synthReverse
	t.noSynth += from.noSynth
	t.synthDone += from.synthDone
	t.synthNoError += from.synthNoError
	t.synthNXDomain += from.synthNXDomain
	t.synthFormErr += from.synthFormErr
}

func (t *generalStats) String() string {
	return fmt.Sprintf("q=%d/%d/%d/%d C=%d/%d/%d/%d gen=%d/%d/%d/%d/%d auth=%d/%d/%d tc=%d/%d db=%d/%d/%d/%d synth=%d/%d/%d sr=%d/%d/%d/%d",
		t.queries, t.badRequest, t.chaos, t.nsid,
		t.cookie, t.cookieOnly, t.wrongCookie, t.malformedCookie,
		t.passthruOut, t.passthruIn, t.chaosRefused, t.noAuthority, t.wrongClass,
		t.authZoneANY, t.authZoneSOA, t.authZoneNS,
		t.truncatedV6, t.truncatedV4,
		t.dbDone, t.dbNoError, t.dbNXDomain, t.dbFormErr,
		t.synthForward, t.synthReverse, t.noSynth,
		t.synthDone, t.synthNoError, t.synthNXDomain, t.synthFormErr)
}

type serverStats struct {
	gen         generalStats
	APtr        qTypeStats
	AAAAPtr     qTypeStats
	AForward    qTypeStats
	AAAAForward qTypeStats
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
