package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/snowmerak/hmacsecret/lib/hmacsecret"
)

func main() {
	if err := run(os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(stdout, stderr io.Writer) error {
	var (
		deviceIndex       int
		rpID              string
		userName          string
		saltHex           string
		credentialIDHex   string
		listOnly          bool
		noWindowsWebAuthn bool
	)

	flag.IntVar(&deviceIndex, "device", 0, "device index (0-based)")
	flag.StringVar(&rpID, "rp-id", "hmac-secret.example", "relying party id")
	flag.StringVar(&userName, "user", "hmac-secret-demo", "credential user name")
	flag.StringVar(&saltHex, "salt", "", "32-byte salt as 64 hex chars (random if empty)")
	flag.StringVar(&credentialIDHex, "credential-id", "", "existing credential id hex (skip create when set)")
	flag.BoolVar(&listOnly, "list", false, "list devices and exit")
	flag.BoolVar(&noWindowsWebAuthn, "no-windows-webauthn", false, "exclude Windows WebAuthn broker (windows://hello)")
	flag.Parse()

	if deviceIndex < 0 {
		return errors.New("-device must be >= 0")
	}
	if strings.TrimSpace(rpID) == "" {
		return errors.New("-rp-id must not be empty")
	}
	if strings.TrimSpace(userName) == "" {
		return errors.New("-user must not be empty")
	}

	devices, err := hmacsecret.ListDevices(hmacsecret.ListOptions{
		ExcludeWindowsWebAuthn: noWindowsWebAuthn,
	})
	if err != nil {
		return err
	}
	for _, d := range devices {
		fmt.Fprintf(stderr, "[%d] %s / %s (%s)\n", d.Index, d.Product, d.Manufacturer, d.Path)
	}
	if listOnly {
		return nil
	}
	if deviceIndex >= len(devices) {
		return fmt.Errorf("device index %d out of range (count=%d)", deviceIndex, len(devices))
	}

	info := devices[deviceIndex]
	var pin string
	if hmacsecret.NeedsTerminalPIN(info.Path) {
		pin, err = hmacsecret.ReadTerminalPIN(stderr)
		if err != nil {
			return err
		}
	} else {
		fmt.Fprintf(stderr, "using device [%d]. PIN/touch via Windows Security UI (external key selectable there).\n", deviceIndex)
	}

	dev, err := hmacsecret.Open(info.Path)
	if err != nil {
		return err
	}

	var credentialID []byte
	if strings.TrimSpace(credentialIDHex) != "" {
		if strings.TrimSpace(saltHex) == "" {
			return errors.New("reusing a credential requires -salt")
		}
		credentialID, err = hex.DecodeString(strings.TrimSpace(credentialIDHex))
		if err != nil {
			return fmt.Errorf("-credential-id must be valid hex: %w", err)
		}
		if len(credentialID) == 0 {
			return errors.New("-credential-id must not be empty")
		}
		fmt.Fprintln(stderr, "reusing stored non-discoverable credential")
	} else {
		fmt.Fprintln(stderr, "creating credential; approve in Windows Security UI / touch key...")
		cred, createErr := dev.CreateCredential(hmacsecret.CreateOptions{
			RPID:     rpID,
			RPName:   "hmacsecret",
			UserName: userName,
			PIN:      pin,
		})
		if createErr != nil {
			return createErr
		}
		credentialID = cred.ID
	}

	salt, generated, err := hmacsecret.ParseSalt(strings.TrimSpace(saltHex))
	if err != nil {
		return err
	}

	fmt.Fprintln(stderr, "requesting hmac-secret; approve in Windows Security UI / touch key...")
	secret, err := dev.Derive(hmacsecret.DeriveOptions{
		RPID:         rpID,
		CredentialID: credentialID,
		Salt:         salt,
		PIN:          pin,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "credential_id=%s\n", hex.EncodeToString(secret.CredentialID))
	fmt.Fprintf(stdout, "salt=%s\n", hex.EncodeToString(secret.Salt))
	fmt.Fprintf(stdout, "hmac_secret=%s\n", hex.EncodeToString(secret.HMACSecret))
	if generated {
		fmt.Fprintln(stderr, "generated random salt; store credential_id+salt to reproduce")
	}
	return nil
}
