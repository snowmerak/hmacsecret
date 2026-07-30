//go:build cgo && (linux || hmacsecret_libfido2)

package hmacsecret

import (
	"fmt"

	libfido2 "github.com/snowmerak/hmacsecret/third_party/go-libfido2"
)

// Device is an open handle to a FIDO2 authenticator path.
type Device struct {
	path   string
	device *libfido2.Device
}

// ListDevices enumerates connected authenticators after platform filtering.
// On Windows, windows://hello is included by default and sorted first.
func ListDevices(opts ListOptions) ([]DeviceInfo, error) {
	locations, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDeviceSearch, err)
	}
	if len(locations) == 0 {
		return nil, ErrNoDevice
	}

	out := make([]DeviceInfo, 0, len(locations))
	for _, location := range locations {
		if !platformLocationAllowed(location, opts.ExcludeWindowsWebAuthn) {
			continue
		}
		info := DeviceInfo{
			Index:        len(out),
			Path:         location.Path,
			Product:      location.Product,
			Manufacturer: location.Manufacturer,
			ProductID:    location.ProductID,
			VendorID:     location.VendorID,
			WindowsHello: isWindowsHello(location.Path),
		}
		out = append(out, info)
	}
	if len(out) == 0 {
		return nil, platformNoSelectableDeviceError()
	}

	// Prefer Windows WebAuthn broker as index 0 when present.
	for i := range out {
		if !out[i].WindowsHello {
			continue
		}
		if i > 0 {
			hello := out[i]
			copy(out[1:i+1], out[0:i])
			out[0] = hello
		}
		break
	}
	for i := range out {
		out[i].Index = i
	}
	return out, nil
}

// Open opens the authenticator at path.
func Open(path string) (*Device, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty device path", ErrInvalidArgument)
	}
	dev, err := libfido2.NewDevice(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOpenDevice, err)
	}
	return &Device{path: path, device: dev}, nil
}

// OpenIndex lists devices with opts and opens the device at index.
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

// Path returns the device path.
func (d *Device) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}

// IsFIDO2 reports whether the device supports FIDO2/CTAP2.
func (d *Device) IsFIDO2() (bool, error) {
	if d == nil || d.device == nil {
		return false, ErrInvalidArgument
	}
	ok, err := d.device.IsFIDO2()
	if err != nil {
		return false, fmt.Errorf("check FIDO2 support: %w", err)
	}
	return ok, nil
}

// WindowsHello reports whether this handle is the Windows WebAuthn broker.
func (d *Device) WindowsHello() bool {
	if d == nil {
		return false
	}
	return isWindowsHello(d.path)
}
