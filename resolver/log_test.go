package resolver

import (
	"context"
	"strings"
	"testing"

	"github.com/markdingo/autoreverse/log"
	"github.com/markdingo/autoreverse/mock"
)

func TestLogFunctions(t *testing.T) {
	var iow mock.IOWriter
	log.SetOut(&iow)
	log.SetLevel(log.DebugLevel)
	r := NewResolver()

	iow.Reset()
	r.LookupIPAddr(context.Background(), "www.apple.com")
	ll := iow.String()
	exp := "   Dbg:res:IP#www.apple.com#"
	if !strings.HasPrefix(ll, exp) {
		t.Error("IPAddr is wrong exp: >>" + exp + "<< got >>" + ll + "<<")
	}

	iow.Reset()
	r.LookupNS(context.Background(), "apple.com")
	ll = iow.String()
	exp = "   Dbg:res:NS#apple.com#"
	if !strings.HasPrefix(ll, exp) {
		t.Error("NS is wrong exp: >>" + exp + "<< got >>" + ll + "<<")
	}
}
