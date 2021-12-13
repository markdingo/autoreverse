package main

import (
	"testing"

	"github.com/markdingo/autoreverse/delegation"
)

func TestAutoReverseAddA(t *testing.T) {
	ar := newAutoReverse(nil, nil)

	d1 := &delegation.Authority{Domain: "1.example.net."}
	d2 := &delegation.Authority{Domain: "2.example.com."}
	d3 := &delegation.Authority{Domain: "3.example.org."}
	if !ar.addAuthority(d1) {
		t.Error("Add of", d1, "should have succeeded")
	}
	if !ar.addAuthority(d2) {
		t.Error("Add of", d2, "should have succeeded")
	}
	if !ar.addAuthority(d3) {
		t.Error("Add of", d3, "should have succeeded")
	}

	if ar.addAuthority(d1) {
		t.Error("Add of", d1, "should have failed")
	}
	if ar.addAuthority(d2) {
		t.Error("Add of", d2, "should have failed")
	}
	if ar.addAuthority(d3) {
		t.Error("Add of", d3, "should have failed")
	}
}
