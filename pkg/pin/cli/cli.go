// Package cli provides a console PINProvider for Linux/macOS (and raw HID).
package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/snowmerak/hmacsecret/lib/hmacsecret"
	libsecrets "github.com/snowmerak/hmacsecret/lib/secrets"
)

// Provider reads a hidden PIN from the terminal when the device needs one.
type Provider struct {
	// Out receives prompts. Defaults to os.Stderr.
	Out io.Writer
}

// New returns a CLI PIN provider.
func New() *Provider {
	return &Provider{Out: os.Stderr}
}

// Provide implements lib/secrets.PINProvider.
func (p *Provider) Provide(_ context.Context, _ libsecrets.Operation, device hmacsecret.DeviceInfo) (string, error) {
	if !hmacsecret.NeedsTerminalPIN(device.Path) {
		return "", nil
	}
	out := p.Out
	if out == nil {
		out = os.Stderr
	}
	fmt.Fprintf(out, "device %s PIN (empty if unset): ", device.Path)
	return hmacsecret.ReadTerminalPIN(out)
}
