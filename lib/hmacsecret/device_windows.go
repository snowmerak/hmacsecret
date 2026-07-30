//go:build windows && !hmacsecret_libfido2

package hmacsecret

import (
	"fmt"
	"strings"

	winwebauthn "github.com/snowmerak/hmacsecret/internal/webauthn"
)

const windowsHelloPath = "windows://hello"

// Device is a handle to the Windows WebAuthn broker.
type Device struct {
	path string
	api  *winwebauthn.API
}

func isWindowsHello(path string) bool {
	return strings.EqualFold(strings.TrimSpace(path), windowsHelloPath)
}

// ListDevices exposes the Windows WebAuthn broker. Windows Security UI selects
// the concrete external authenticator during create/assert operations.
func ListDevices(opts ListOptions) ([]DeviceInfo, error) {
	if _, err := winwebauthn.Load(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDeviceSearch, err)
	}
	if opts.ExcludeWindowsWebAuthn {
		return nil, ErrNoSelectableDevice
	}
	return []DeviceInfo{{
		Index:        0,
		Path:         windowsHelloPath,
		Product:      "Windows Hello",
		Manufacturer: "Microsoft Corporation",
		ProductID:    0x0001,
		VendorID:     0x045e,
		WindowsHello: true,
	}}, nil
}

// Open opens the virtual Windows WebAuthn broker.
func Open(path string) (*Device, error) {
	if !isWindowsHello(path) {
		return nil, fmt.Errorf("%w: unsupported Windows device path %q", ErrOpenDevice, path)
	}
	api, err := winwebauthn.Load()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOpenDevice, err)
	}
	return &Device{path: windowsHelloPath, api: api}, nil
}

// OpenIndex lists devices and opens the device at index.
func OpenIndex(index int, opts ListOptions) (*Device, error) {
	devices, err := ListDevices(opts)
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= len(devices) {
		return nil, fmt.Errorf("%w: device index %d out of range (count=%d)", ErrInvalidArgument, index, len(devices))
	}
	return Open(devices[index].Path)
}

// Path returns the virtual broker path.
func (d *Device) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}

// IsFIDO2 reports whether the Windows WebAuthn API supports PRF operations.
func (d *Device) IsFIDO2() (bool, error) {
	if d == nil || d.api == nil {
		return false, ErrInvalidArgument
	}
	return d.api.Version() >= winwebauthn.APIVersionPRF, nil
}

// WindowsHello reports whether this handle is the Windows WebAuthn broker.
func (d *Device) WindowsHello() bool {
	return d != nil && isWindowsHello(d.path)
}
