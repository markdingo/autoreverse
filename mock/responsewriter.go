package mock

import (
	"net"

	"github.com/miekg/dns"
)

type addr struct {
	s string
}

func (t *addr) Network() string {
	return "udp"
}

func (t *addr) String() string {
	return t.s
}

var (
	local  = &addr{s: "127.0.0.1"}
	remote = &addr{s: "127.0.0.2"}
)

type ResponseWriter struct {
	m *dns.Msg // Saved by writeMsg
}

func (t *ResponseWriter) Reset() {
	t.m = nil
}

// Get returns the last response, if any then clears the response
func (t *ResponseWriter) Get() *dns.Msg {
	m := t.m
	t.m = nil
	return m
}

func (t *ResponseWriter) LocalAddr() (a net.Addr) {
	return local
}

func (t *ResponseWriter) RemoteAddr() (r net.Addr) {
	return remote
}
func (t *ResponseWriter) WriteMsg(m *dns.Msg) (e error) {
	t.m = m

	return
}
func (t *ResponseWriter) Write(b []byte) (l int, e error) {
	// l = len(b)
	// return

	panic("Don't expect Write() to be called")
}
func (t *ResponseWriter) Close() (e error) {
	return
}
func (t *ResponseWriter) TsigStatus() (e error) {
	return
}
func (t *ResponseWriter) TsigTimersOnly(bool) {
	return
}
func (t *ResponseWriter) Hijack() {
}
