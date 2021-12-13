//go:build !go1.16 && !go1.17
// +build !go1.16,!go1.17

package pregen

var Manpage []byte = []byte(`
Unfortunately the manpage is not available as this package was built with an old
version of go. To include the manpage, please rebuild with go version 1.16 or later.

Alternatively, visit the project home page at: https://github.com/markdingo/autoreverse

`)
