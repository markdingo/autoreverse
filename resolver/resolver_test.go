package resolver

import (
	"context"
	"strings"
	"testing"

	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
)

func TestResolver(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	log.SetLevel(log.DebugLevel) // Turns on logging in resolver

	res := NewResolver()

	nss, err := res.LookupNS(context.Background(), "apple.com.")
	if err != nil {
		t.Fatal("apple.com no longer exists?", err)
	}
	nsc := 0
	ipc := 0
	for _, ns := range nss {
		if strings.Contains(ns, "apple") {
			nsc++
			ips, err := res.LookupIPAddr(context.Background(), ns)
			if err != nil {
				t.Error("IP lookup failed for", ns, err)
				continue
			}
			for _, ip := range ips {
				s := ip.String()
				if strings.Contains(s, "17.") || strings.Contains(s, "2620:149") {
					ipc++
				}
			}
		}
	}
	if nsc == 0 {
		t.Error("Apple.com has no in-bailiwick NSes?", nss)
	}

	if ipc == 0 {
		t.Error("No apple.com name servers are served in-house?")
	}

	nss, err = res.LookupNS(context.Background(), "broken name")
	if err == nil {
		t.Fatal("expected error return with borken name")
	}

	got := out.String()
	if !strings.Contains(got, "Dbg:res:NS#apple.com") {
		t.Error("Expected log to contain apple.com", got)
	}
	if !strings.Contains(got, "no such host") {
		t.Error("Expected log to contain no such host for broken name", got)
	}
}

func TestResolverBadHost(t *testing.T) {
	out := &mock.IOWriter{}
	log.SetOut(out)
	res := NewResolver()

	// We just need to make sure it's an error return
	_, err := res.LookupIPAddr(context.Background(), "Bad Host Name")
	if err == nil {
		t.Fatal("Expected an error return with a bad host name")
	}
}
