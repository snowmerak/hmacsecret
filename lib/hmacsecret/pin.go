package hmacsecret

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// ReadTerminalPIN reads a hidden PIN from stdin.
// Empty input (Enter only) is valid for devices without a PIN.
func ReadTerminalPIN(promptWriter io.Writer) (string, error) {
	if promptWriter == nil {
		promptWriter = io.Discard
	}
	fmt.Fprint(promptWriter, "PIN (empty if unset): ")
	pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(promptWriter)
	if err != nil {
		return "", fmt.Errorf("read hidden PIN: %w", err)
	}
	pin := string(pinBytes)
	for i := range pinBytes {
		pinBytes[i] = 0
	}
	return pin, nil
}

// NeedsTerminalPIN reports whether the device path expects a console PIN.
// Windows WebAuthn broker handles PIN/touch in Security UI, so false there.
func NeedsTerminalPIN(path string) bool {
	return !isWindowsHello(path)
}
