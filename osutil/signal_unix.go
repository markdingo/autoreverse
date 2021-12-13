//go:build !windows
// +build !windows

package osutil

import (
	"os"
	"os/signal"
	"syscall"
)

// SignalNotify asks OS to send all the main Unix signals to the supplied channel.
func SignalNotify(c chan os.Signal) {
	signal.Notify(c, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2)
}

// IsSignalUSR1 returns true if the supplied signal is SIGUSR1. A noop on Windows.
func IsSignalUSR1(s os.Signal) bool {
	return s == syscall.SIGUSR1
}

// IsSignalUSR2 returns true if the supplied signal is SIGUSR2. A noop on Windows.
func IsSignalUSR2(s os.Signal) bool {
	return s == syscall.SIGUSR2
}

// IsSignalTERM returns true if the supplied signal is SIGTERM. A noop on Windows.
func IsSignalTERM(s os.Signal) bool {
	return s == syscall.SIGTERM
}

// IsSignalINT returns true if the supplied signal is SIGINT. A noop on Windows.
func IsSignalINT(s os.Signal) bool {
	return s == os.Interrupt
}

// IsSignalHUP returns true if the supplied signal is SIGHUP. A noop on Windows.
func IsSignalHUP(s os.Signal) bool {
	return s == syscall.SIGHUP
}
