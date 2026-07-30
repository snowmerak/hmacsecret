//go:build cgo && !windows

package hmacsecret

import (
	libfido2 "github.com/keys-pub/go-libfido2"
)

func isWindowsHello(path string) bool {
	return false
}

func platformLocationAllowed(_ *libfido2.DeviceLocation, _ bool) bool {
	return true
}

func platformNoSelectableDeviceError() error {
	return ErrNoSelectableDevice
}
