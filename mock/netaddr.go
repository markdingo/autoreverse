package mock

// netAddr is a mock replacement for the net.Addr interface.
type netAddr struct {
	networkStr, stringStr string
}

// Network helps meet the net.Addr interface.
func (t *netAddr) Network() string {
	return t.networkStr
}

// String helps meet the net.Addr interface.
func (t *netAddr) String() string {
	return t.stringStr
}

// NewNetAddr creates a mock net.Addr with return values for Network() and String()
func NewNetAddr(networkStr, stringStr string) *netAddr {
	t := &netAddr{networkStr: networkStr, stringStr: stringStr}
	if len(t.networkStr) == 0 {
		t.networkStr = "udp"
	}

	return t
}
