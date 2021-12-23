package mock

import (
	"net"

	"github.com/miekg/dns"
)

var (
	local  = NewNetAddr("udp", "127.0.0.1:53")
	remote = NewNetAddr("udp", "127.0.0.2:4056")
)

// ResponseWriter is a mock replacement for the miekg dns.ResponseWriter. It's used for
// tests only. It contains a response message that is arbitrarily returned.
type ResponseWriter struct {
	m *dns.Msg // Saved by writeMsg
}

// Reset clears the response message
func (t *ResponseWriter) Reset() {
	t.m = nil
}

// Get returns the last response, if any then clears the response
func (t *ResponseWriter) Get() *dns.Msg {
	m := t.m
	t.m = nil
	return m
}

// LocalAddr helps meet the dns.ResponseWriter interface
func (t *ResponseWriter) LocalAddr() (a net.Addr) {
	return local
}

// RemoteAddr helps meet the dns.ResponseWriter interface
func (t *ResponseWriter) RemoteAddr() (r net.Addr) {
	return remote
}

// WriteMsg helps meet the dns.ResponseWriter interface
func (t *ResponseWriter) WriteMsg(m *dns.Msg) (e error) {
	t.m = m

	return
}

// Write helps meet the dns.ResponseWriter interface
func (t *ResponseWriter) Write(b []byte) (l int, e error) {
	// l = len(b)
	// return

	panic("Don't expect Write() to be called")
}

// Close helps meet the dns.ResponseWriter interface. It is a no-op.
func (t *ResponseWriter) Close() (e error) {
	return
}

// TsigStatus helps meet the dns.ResponseWriter interface. It is a no-op.
func (t *ResponseWriter) TsigStatus() (e error) {
	return
}

// TsigTimersOnly helps meet the dns.ResponseWriter interface. It is a no-op.
func (t *ResponseWriter) TsigTimersOnly(bool) {
	return
}

// Hijack helps meet the dns.ResponseWriter interface. It is a no-op.
func (t *ResponseWriter) Hijack() {
}
