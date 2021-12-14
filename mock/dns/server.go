package dns

import (
	"github.com/miekg/dns"
)

// StartServer is a clone of the real  code to start up a miekg DNS server.
func StartServer(net, serverAddr string, h dns.Handler) *dns.Server {
	srv := &dns.Server{Net: net, Addr: serverAddr, Handler: h}
	hasStarted := make(chan struct{})
	srv.NotifyStartedFunc = func() {
		hasStarted <- struct{}{}
	}

	go func() {
		err := srv.ListenAndServe()
		defer close(hasStarted)
		if err != nil { // Shutdown or real error?
			panic("Setup of Server failed:" + err.Error())
		}
	}()

	<-hasStarted // Wait for server, one way of the other

	return srv
}
