package main

import (
	"testing"
)

func TestQueryStats(t *testing.T) {
	var qs1, qs2 queryStats
	qs1.good = 1
	qs2.good = 3
	qs1.add(&qs2)
	if qs1.good != 4 {
		t.Error("queryStats.add flawed", qs1, qs2)
	}
	qs3 := queryStats{1, 2, 3, 4, 5}
	qs1.add(&qs3)
	if qs1.queries != 1 || qs1.good != 6 || qs1.answers != 3 ||
		qs1.malformed != 4 || qs1.noSynth != 5 {
		t.Errorf("queryStats.add flawed %+v %+v\n", qs1, qs3)
	}

	s := qs1.String()
	if s != "q=1 good=6(3) mal=4 nodb=5" {
		t.Errorf("queryStats.String %s vs %+v\n", s, qs1)
	}
}

func TestGeneralStats(t *testing.T) {
	gs1 := generalStats{queries: 1, formatError: 2, chaos: 3, nsid: 4, wrongClass: 5,
		noAuthority: 6,
		authZoneANY: 7, authZoneSOA: 8, authZoneNS: 9, authZoneA: 10, authZoneAAAA: 11,
		nxDomain: 12, passthruOut: 13, passthruIn: 14,
		cookie: 15}
	gs1.add(&gs1) // Should double all counters
	if gs1.queries != 2 || gs1.formatError != 4 || gs1.chaos != 6 ||
		gs1.nsid != 8 || gs1.wrongClass != 10 || gs1.noAuthority != 12 ||
		gs1.authZoneANY != 14 || gs1.authZoneSOA != 16 || gs1.authZoneNS != 18 ||
		gs1.authZoneA != 20 || gs1.authZoneAAAA != 22 || gs1.nxDomain != 24 ||
		gs1.passthruOut != 26 || gs1.passthruIn != 28 || gs1.cookie != 30 {
		t.Errorf("generalStats.Add flawed %+v\n", gs1)
	}
}

func TestServerStats(t *testing.T) {
	ss1 := serverStats{}
	ss2 := serverStats{}
	ss2.gen.passthruIn = 1
	ss2.APtr.good = 2
	ss2.AAAAPtr.good = 3
	ss2.AForward.good = 4
	ss2.AAAAForward.good = 5
	ss1.add(&ss2)
	exp := "Gen: q=0 fe=0 ch=0 nsid=0 cookie=0 wc=0 noaz=0 az=0/0/0/0/0 nx=0 pass=0/1 APtr: q=0 good=2(0) mal=0 nodb=0 AAAAPtr: q=0 good=3(0) mal=0 nodb=0 AForward: q=0 good=4(0) mal=0 nodb=0 AAAAForward: q=0 good=5(0) mal=0 nodb=0"

	got := ss1.String()
	if exp != got {
		t.Error("serverStats wrong", exp, got)
	}
}
