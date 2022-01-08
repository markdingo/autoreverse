package dnsutil

import (
	"strings"
)

// shortenedError is a wrapped error so the caller doesn't lose the original error
// context, if that is of interest to them.
type shortenedError struct {
	msg string
	err error
}

func (t *shortenedError) Error() string {
	return t.msg
}

func (t *shortenedError) Unwrap() error {
	return t.err
}

// ShortenLookupError turns a long unwieldy error return from net.Resolver into a succinct
// error in the common cases which don't require the extensive error normally returned.
func ShortenLookupError(err error) error {
	if err == nil {
		return err
	}
	m := err.Error() // Shorten up the error if we can
	switch {
	case strings.Contains(m, "i/o timeout"):
		err = &shortenedError{msg: "Timeout", err: err}
	case strings.Contains(m, "connection refused"):
		err = &shortenedError{msg: "Connection refused", err: err}
	}

	return err
}
