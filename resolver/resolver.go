package resolver

import (
	"context"
	"net"
	"time"

	"github.com/markdingo/autoreverse/log"
)

type resolver struct {
	netResolver net.Resolver

	// Currently these timeout and retry values cannot be changed from the defaults.
	// Let's see if there is ever any real need to change them prior to adding an
	// adjustment capability.
	singleExchangeTimeout, fullExchangeTimeout time.Duration

	queryTries int
}

// NewResolver creates a fully formed resolver which is ready to use.
func NewResolver() *resolver {
	t := &resolver{
		singleExchangeTimeout: defaultSingleExchangeTimeout,
		fullExchangeTimeout:   defaultfFullExchangeTimeout,
		queryTries:            defaultQueryTries,
	}

	return t
}

func (t *resolver) LookupNS(ctx context.Context, name string) ([]string, error) {
	ctxWithTO, cancel := context.WithDeadline(ctx, time.Now().Add(t.singleExchangeTimeout))
	defer cancel()
	nsSet, err := t.netResolver.LookupNS(ctxWithTO, name)
	if log.IfDebug() {
		LogNS(name, nsSet, "", err)
	}

	if err != nil {
		return []string{}, err
	}

	nss := make([]string, 0, len(nsSet))
	for _, n := range nsSet {
		nss = append(nss, n.Host)
	}

	return nss, nil
}

func (t *resolver) LookupIPAddr(ctx context.Context, host string) ([]net.IP, error) {
	ctxWithTO, cancel := context.WithDeadline(ctx, time.Now().Add(t.singleExchangeTimeout))
	defer cancel()
	addrs, err := t.netResolver.LookupIPAddr(ctxWithTO, host)
	if log.IfDebug() {
		LogIP(host, addrs, "", err)
	}
	if err != nil {
		return []net.IP{}, err
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}

	return ips, nil
}
