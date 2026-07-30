// Package cli provides an interactive DeviceSelector for terminal apps.
package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/snowmerak/hmacsecret/lib/hmacsecret"
)

// Selector prompts on a TTY to pick a device from the current listing.
type Selector struct {
	// In reads the chosen index. Defaults to os.Stdin.
	In io.Reader
	// Out prints the device list and prompt. Defaults to os.Stderr.
	Out io.Writer
	// AutoSingle, when true (default), skips the prompt if len(devices)==1.
	AutoSingle bool
}

// New returns a CLI device selector.
func New() *Selector {
	return &Selector{
		In:         os.Stdin,
		Out:        os.Stderr,
		AutoSingle: true,
	}
}

// Select implements lib/secrets.DeviceSelector.
func (s *Selector) Select(_ context.Context, devices []hmacsecret.DeviceInfo) (hmacsecret.DeviceInfo, error) {
	if len(devices) == 0 {
		return hmacsecret.DeviceInfo{}, fmt.Errorf("no authenticator devices")
	}
	out := s.Out
	if out == nil {
		out = os.Stderr
	}
	in := s.In
	if in == nil {
		in = os.Stdin
	}

	for _, d := range devices {
		fmt.Fprintf(out, "[%d] %s / %s (%s)\n", d.Index, d.Product, d.Manufacturer, d.Path)
	}
	if s.AutoSingle && len(devices) == 1 {
		return devices[0], nil
	}

	fmt.Fprintf(out, "device index [0-%d]: ", len(devices)-1)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil {
		return hmacsecret.DeviceInfo{}, fmt.Errorf("read device index: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return devices[0], nil
	}
	idx, err := strconv.Atoi(line)
	if err != nil || idx < 0 || idx >= len(devices) {
		return hmacsecret.DeviceInfo{}, fmt.Errorf("invalid device index %q", line)
	}
	return devices[idx], nil
}
