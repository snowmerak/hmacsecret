//go:build !windows && (!cgo || (!darwin && !linux && !hmacsecret_libfido2))

package hmacsecret

import "fmt"

// Device is unavailable without a platform backend.
type Device struct {
	path string
}

func unsupported(op string) error {
	return fmt.Errorf("%w: %s", ErrUnsupportedBuild, op)
}

func isWindowsHello(string) bool { return false }

// ListDevices is unavailable without CGO outside Windows.
func ListDevices(ListOptions) ([]DeviceInfo, error) { return nil, unsupported("ListDevices") }

// Open is unavailable without CGO outside Windows.
func Open(string) (*Device, error) { return nil, unsupported("Open") }

// OpenIndex is unavailable without CGO outside Windows.
func OpenIndex(int, ListOptions) (*Device, error) { return nil, unsupported("OpenIndex") }

// Path returns the device path.
func (d *Device) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}

// IsFIDO2 is unavailable without CGO outside Windows.
func (d *Device) IsFIDO2() (bool, error) { return false, unsupported("IsFIDO2") }

// WindowsHello reports false outside Windows.
func (d *Device) WindowsHello() bool { return false }

// CreateCredential is unavailable without CGO outside Windows.
func (d *Device) CreateCredential(CreateOptions) (*Credential, error) {
	return nil, unsupported("CreateCredential")
}

// Derive is unavailable without CGO outside Windows.
func (d *Device) Derive(DeriveOptions) (*Secret, error) {
	return nil, unsupported("Derive")
}

// CreateAndDerive is unavailable without CGO outside Windows.
func (d *Device) CreateAndDerive(CreateOptions, []byte, string) (*Secret, error) {
	return nil, unsupported("CreateAndDerive")
}
