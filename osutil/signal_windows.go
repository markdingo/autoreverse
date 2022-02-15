package osutil

import (
	"os"
	"os/signal"
)

func SignalNotify(c chan os.Signal) {
	signal.Notify(c, os.Interrupt)
}

func IsSignalUSR1(s os.Signal) bool {
	return false
}

func IsSignalUSR2(s os.Signal) bool {
	return false
}

func IsSignalTERM(s os.Signal) bool {
	return false
}

func IsSignalINT(s os.Signal) bool {
	return s == os.Interrupt
}

func IsSignalHUP(s os.Signal) bool {
	return false
}
