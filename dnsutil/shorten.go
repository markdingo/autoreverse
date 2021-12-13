package dnsutil

import (
	"fmt"
	"strings"
)

// ShortenLookupError turns a long unwieldy error return from net.Resolver into a succinct
// error in the common cases which don't require the extensive error normally returned.
func ShortenLookupError(err error) error {
	if err == nil {
		return err
	}
	m := err.Error() // Shorten up the error if we can
	switch {
	case strings.Contains(m, "i/o timeout"):
		err = fmt.Errorf("Timeout")
	case strings.Contains(m, "connection refused"):
		err = fmt.Errorf("Connection refused")
	}

	return err
}
