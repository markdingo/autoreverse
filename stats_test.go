package main

import (
	"testing"
)

func TestStatsQuery(t *testing.T) {
	var qs1, qs2 qTypeStats
	qs1.good = 1
	qs2.good = 3
	qs1.add(&qs2)
	if qs1.good != 4 {
		t.Error("qTypeStats.add flawed", qs1, qs2)
	}
	qs3 := qTypeStats{1, 2, 12, 4, 5}
	qs1.add(&qs3)
	if qs1.queries != 1 || qs1.good != 6 || qs1.answers != 12 ||
		qs1.truncated != 4 || qs1.invertError != 5 {
		t.Errorf("qTypeStats.add flawed %+v %+v\n", qs1, qs3)
	}

	got := qs1.String()
	exp := "q=1 good=6(12) trunc=4 invErr=5"
	if got != exp {
		t.Error("qTypeStats.String \nExp:", exp, "\nGot:", got)
	}
}

func TestStatsGeneral(t *testing.T) {
	gs := generalStats{}
	setGeneralStats(&gs)
	gs.add(&gs) // Should double all counters
	if gs.queries != 1*2 ||
		gs.badRequest != 2*2 ||
		gs.chaos != 11*2 ||
		gs.nsid != 12*2 ||
		gs.cookie != 21*2 ||
		gs.cookieOnly != 22*2 ||
		gs.wrongCookie != 23*2 ||
		gs.malformedCookie != 24*2 ||
		gs.passthruOut != 31*2 ||
		gs.passthruIn != 32*2 ||
		gs.chaosRefused != 41*2 ||
		gs.noAuthority != 42*2 ||
		gs.wrongClass != 43*2 ||
		gs.authZoneANY != 51*2 ||
		gs.authZoneSOA != 52*2 ||
		gs.authZoneNS != 53*2 ||
		gs.truncatedV6 != 61*2 ||
		gs.truncatedV4 != 62*2 ||
		gs.dbDone != 71*2 ||
		gs.dbNoError != 72*2 ||
		gs.dbNXDomain != 73*2 ||
		gs.dbFormErr != 74*2 ||
		gs.synthForward != 81*2 ||
		gs.synthReverse != 82*2 ||
		gs.noSynth != 83*2 ||
		gs.synthDone != 91*2 ||
		gs.synthNoError != 92*2 ||
		gs.synthNXDomain != 93*2 ||
		gs.synthFormErr != 94*2 {
		t.Errorf("generalStats.Add flawed %+v\n", gs)
	}
}

func TestStatsServer(t *testing.T) {
	ss1 := serverStats{}
	ss2 := serverStats{}
	ss2.gen.passthruIn = 1  // Pick some random fields to populate
	ss2.gen.wrongCookie = 2 // All of these values should transfer to ss1
	ss2.gen.noAuthority = 3 // when added and thus show up uniquely in the
	ss2.APtr.good = 4       // String() output
	ss2.AAAAPtr.good = 5
	ss2.AForward.good = 6
	ss2.AAAAForward.good = 7
	ss1.add(&ss2)
	exp := "Gen: q=0/0/0/0 C=0/0/2/0 gen=0/1/0/3/0 auth=0/0/0 tc=0/0 db=0/0/0/0 synth=0/0/0 sr=0/0/0/0 APtr: q=0 good=4(0) trunc=0 invErr=0 AAAAPtr: q=0 good=5(0) trunc=0 invErr=0 AForward: q=0 good=6(0) trunc=0 invErr=0 AAAAForward: q=0 good=7(0) trunc=0 invErr=0"
	got := ss1.String()
	if exp != got {
		t.Error("serverStats wrong. \nExp:", exp, "\nGot", got)
	}
}

func setGeneralStats(gs *generalStats) {
	gs.queries = 1
	gs.badRequest = 2

	gs.chaos = 11
	gs.nsid = 12

	gs.cookie = 21
	gs.cookieOnly = 22
	gs.wrongCookie = 23
	gs.malformedCookie = 24

	gs.passthruOut = 31
	gs.passthruIn = 32

	gs.chaosRefused = 41
	gs.noAuthority = 42
	gs.wrongClass = 43

	gs.authZoneANY = 51
	gs.authZoneSOA = 52
	gs.authZoneNS = 53

	gs.truncatedV6 = 61
	gs.truncatedV4 = 62

	gs.dbDone = 71
	gs.dbNoError = 72
	gs.dbNXDomain = 73
	gs.dbFormErr = 74

	gs.synthForward = 81
	gs.synthReverse = 82
	gs.noSynth = 83

	gs.synthDone = 91
	gs.synthNoError = 92
	gs.synthNXDomain = 93
	gs.synthFormErr = 94
}
