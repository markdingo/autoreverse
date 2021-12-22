package mock

// netAddr is a mock replacement for the net.Addr interface.
type netAddr struct {
	networkStr, stringStr string
}

func (t *netAddr) Network() string {
	return t.networkStr
}

func (t *netAddr) String() string {
	return t.stringStr
}

func NewNetAddr(networkStr, stringStr string) *netAddr {
	t := &netAddr{networkStr: networkStr, stringStr: stringStr}
	if len(t.networkStr) == 0 {
		t.networkStr = "udp"
	}

	return t
}
