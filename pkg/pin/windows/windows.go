// Package windows provides a PINProvider for the Windows WebAuthn path.
// PIN/UV are collected by Windows Security UI, so Provide always returns "".
package windows

import (
	"context"

	"github.com/snowmerak/hmacsecret/lib/hmacsecret"
	libsecrets "github.com/snowmerak/hmacsecret/lib/secrets"
)

// Provider never prompts; OS Security UI handles PIN/touch.
type Provider struct{}

// New returns a Windows WebAuthn PIN provider.
func New() *Provider { return &Provider{} }

// Provide implements lib/secrets.PINProvider.
func (Provider) Provide(context.Context, libsecrets.Operation, hmacsecret.DeviceInfo) (string, error) {
	return "", nil
}
