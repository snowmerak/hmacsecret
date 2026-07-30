//go:build cgo && windows && hmacsecret_libfido2

package hmacsecret

import (
	"strings"

	libfido2 "github.com/snowmerak/hmacsecret/third_party/go-libfido2"
)

const windowsHelloPath = "windows://hello"

func isWindowsHello(path string) bool {
	return strings.EqualFold(strings.TrimSpace(path), windowsHelloPath)
}

// platformLocationAllowed filters locations.
// WebAuthn (windows://hello) is included unless excludeWindowsWebAuthn is set.
func platformLocationAllowed(location *libfido2.DeviceLocation, excludeWindowsWebAuthn bool) bool {
	if isWindowsHello(location.Path) && excludeWindowsWebAuthn {
		return false
	}
	return true
}

func platformNoSelectableDeviceError() error {
	return ErrNoSelectableDevice
}
