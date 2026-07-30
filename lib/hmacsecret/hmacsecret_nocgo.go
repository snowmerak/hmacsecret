//go:build !cgo

package hmacsecret

import (
	"errors"
	"fmt"
	"io"
)

// SaltSize is the hmac-secret salt length required by CTAP2.
const SaltSize = 32

// Sentinel errors for callers.
var (
	ErrInvalidArgument    = errors.New("invalid argument")
	ErrNoDevice           = errors.New("no FIDO2 device found")
	ErrNoSelectableDevice = errors.New("no selectable FIDO2 device")
	ErrDeviceSearch       = errors.New("FIDO2 device search failed")
	ErrOpenDevice         = errors.New("open FIDO2 device failed")
	ErrNotFIDO2           = errors.New("device does not support FIDO2/CTAP2")
	ErrEmptyHMACSecret    = errors.New("authenticator returned empty hmac-secret")
	ErrUnsupportedBuild   = errors.New("hmacsecret requires CGO and native libfido2")
)

// DeviceInfo describes a discovered FIDO2 authenticator.
type DeviceInfo struct {
	Index        int
	Path         string
	Product      string
	Manufacturer string
	ProductID    int16
	VendorID     int16
	WindowsHello bool
}

// ListOptions controls device discovery.
type ListOptions struct {
	ExcludeWindowsWebAuthn bool
}

// Device is an open handle to a FIDO2 authenticator path.
type Device struct {
	path string
}

// CreateOptions configures non-discoverable hmac-secret credential creation.
type CreateOptions struct {
	RPID            string
	RPName          string
	UserName        string
	UserDisplayName string
	UserID          []byte
	PIN             string
	ClientDataJSON  []byte
}

// DeriveOptions configures hmac-secret derivation from an existing credential.
type DeriveOptions struct {
	RPID            string
	CredentialID    []byte
	Salt            []byte
	PIN             string
	UserPresence    bool
	UserPresenceSet bool
	ClientDataJSON  []byte
}

// Credential is a created hmac-secret-enabled credential.
type Credential struct {
	ID     []byte
	RPID   string
	PubKey []byte
}

// Secret is a derived hmac-secret value plus the inputs needed to reproduce it.
type Secret struct {
	CredentialID []byte
	Salt         []byte
	HMACSecret   []byte
}

func unsupported(op string) error {
	return fmt.Errorf("%w: %s", ErrUnsupportedBuild, op)
}

// ParseSalt is unavailable without CGO.
func ParseSalt(string) ([]byte, bool, error) { return nil, false, unsupported("ParseSalt") }

// MakeClientDataJSON is unavailable without CGO.
func MakeClientDataJSON(string, []byte, string) ([]byte, error) {
	return nil, unsupported("MakeClientDataJSON")
}

// ReadTerminalPIN is unavailable without CGO.
func ReadTerminalPIN(io.Writer) (string, error) { return "", unsupported("ReadTerminalPIN") }

// NeedsTerminalPIN is unavailable without CGO.
func NeedsTerminalPIN(string) bool { return false }

// ListDevices is unavailable without CGO.
func ListDevices(ListOptions) ([]DeviceInfo, error) { return nil, unsupported("ListDevices") }

// Open is unavailable without CGO.
func Open(string) (*Device, error) { return nil, unsupported("Open") }

// OpenIndex is unavailable without CGO.
func OpenIndex(int, ListOptions) (*Device, error) { return nil, unsupported("OpenIndex") }

// Path returns the device path.
func (d *Device) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}

// IsFIDO2 is unavailable without CGO.
func (d *Device) IsFIDO2() (bool, error) { return false, unsupported("IsFIDO2") }

// WindowsHello is unavailable without CGO.
func (d *Device) WindowsHello() bool { return false }

// CreateCredential is unavailable without CGO.
func (d *Device) CreateCredential(CreateOptions) (*Credential, error) {
	return nil, unsupported("CreateCredential")
}

// Derive is unavailable without CGO.
func (d *Device) Derive(DeriveOptions) (*Secret, error) { return nil, unsupported("Derive") }

// CreateAndDerive is unavailable without CGO.
func (d *Device) CreateAndDerive(CreateOptions, []byte, string) (*Secret, error) {
	return nil, unsupported("CreateAndDerive")
}
