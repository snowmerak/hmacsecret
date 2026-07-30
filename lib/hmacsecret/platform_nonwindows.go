//go:build cgo && !windows && (linux || hmacsecret_libfido2)

package hmacsecret

import (
	libfido2 "github.com/snowmerak/hmacsecret/third_party/go-libfido2"
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
