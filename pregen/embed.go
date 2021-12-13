//go:build go1.16 || go1.17
// +build go1.16 go1.17

package pregen

import (
	_ "embed"
)

//go:embed autoreverse.8
var Manpage []byte
