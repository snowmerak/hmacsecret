// Package secrets defines DeviceSelector and PINProvider contracts used by
// the high-level secrets service (pkg/secrets).
package secrets

import (
	"context"

	"github.com/snowmerak/hmacsecret/lib/hmacsecret"
)

// Operation identifies why an authenticator interaction is requested.
type Operation string

const (
	OpCreate Operation = "create"
	OpDerive Operation = "derive"
)

// DeviceSelector chooses one device from a freshly listed set.
// Implementations return DeviceInfo only; the caller opens the path.
type DeviceSelector interface {
	Select(ctx context.Context, devices []hmacsecret.DeviceInfo) (hmacsecret.DeviceInfo, error)
}

// DeviceSelectorFunc adapts a function to DeviceSelector.
type DeviceSelectorFunc func(ctx context.Context, devices []hmacsecret.DeviceInfo) (hmacsecret.DeviceInfo, error)

// Select implements DeviceSelector.
func (f DeviceSelectorFunc) Select(ctx context.Context, devices []hmacsecret.DeviceInfo) (hmacsecret.DeviceInfo, error) {
	return f(ctx, devices)
}

// PINProvider returns a PIN for the selected device and operation.
// Return "" when the platform collects PIN/UV itself (e.g. Windows WebAuthn).
type PINProvider interface {
	Provide(ctx context.Context, op Operation, device hmacsecret.DeviceInfo) (string, error)
}

// PINProviderFunc adapts a function to PINProvider.
type PINProviderFunc func(ctx context.Context, op Operation, device hmacsecret.DeviceInfo) (string, error)

// Provide implements PINProvider.
func (f PINProviderFunc) Provide(ctx context.Context, op Operation, device hmacsecret.DeviceInfo) (string, error) {
	return f(ctx, op, device)
}
