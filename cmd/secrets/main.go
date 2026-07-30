// Command secrets is a thin CLI over pkg/secrets with pluggable store/PIN/device.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/awnumar/memguard"

	"github.com/snowmerak/hmacsecret/lib/hmacsecret"
	libsecrets "github.com/snowmerak/hmacsecret/lib/secrets"
	"github.com/snowmerak/hmacsecret/lib/store"
	devicecli "github.com/snowmerak/hmacsecret/pkg/device/cli"
	pincli "github.com/snowmerak/hmacsecret/pkg/pin/cli"
	pinwindows "github.com/snowmerak/hmacsecret/pkg/pin/windows"
	"github.com/snowmerak/hmacsecret/pkg/secrets"
	"github.com/snowmerak/hmacsecret/pkg/store/pebble"
	"github.com/snowmerak/hmacsecret/pkg/store/sqlite"
)

func main() {
	memguard.CatchInterrupt()
	exitCode := 0
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		exitCode = 1
	}
	memguard.Purge()
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("secrets", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		backend    string
		dbPath     string
		rpID       string
		userName   string
		noWebAuthn bool
	)

	fs.StringVar(&backend, "backend", "pebble", "store backend: pebble|sqlite")
	fs.StringVar(&dbPath, "db", "", "store path (default: ./data/secrets.pebble or ./data/secrets.sqlite)")
	fs.StringVar(&rpID, "rp-id", "hmac-secret.example", "relying party id for create")
	fs.StringVar(&userName, "user", "hmac-secret", "credential user name for create")
	fs.BoolVar(&noWebAuthn, "no-windows-webauthn", false, "exclude Windows WebAuthn broker")

	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 1 {
		return errors.New("usage: secrets <create|derive|list|delete|has> [alias]")
	}
	cmd := rest[0]
	alias := ""
	if len(rest) > 1 {
		alias = rest[1]
	}

	if dbPath == "" {
		switch strings.ToLower(backend) {
		case "sqlite":
			dbPath = filepath.Join("data", "secrets.sqlite")
		default:
			dbPath = filepath.Join("data", "secrets.pebble")
		}
	}
	if dir := filepath.Dir(dbPath); dir != "." && dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}

	st, err := openStore(backend, dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	svc, err := secrets.New(secrets.Options{
		Store:  st,
		Select: devicecli.New(),
		PIN:    defaultPINProvider(),
		ListOptions: hmacsecret.ListOptions{
			ExcludeWindowsWebAuthn: noWebAuthn,
		},
		RPID:     rpID,
		UserName: userName,
	})
	if err != nil {
		return err
	}

	ctx := context.Background()
	switch cmd {
	case "create":
		if alias == "" {
			return errors.New("create requires alias")
		}
		secret, err := svc.Create(ctx, alias)
		if err != nil {
			return err
		}
		fmt.Printf("alias=%s\n", alias)
		return writeEnclaveHex(os.Stdout, "hmac_secret=", secret)
	case "derive", "get":
		if alias == "" {
			return errors.New("derive requires alias")
		}
		secret, err := svc.Derive(ctx, alias)
		if err != nil {
			return err
		}
		fmt.Printf("alias=%s\n", alias)
		return writeEnclaveHex(os.Stdout, "hmac_secret=", secret)
	case "delete", "rm":
		if alias == "" {
			return errors.New("delete requires alias")
		}
		return svc.Delete(ctx, alias)
	case "has":
		if alias == "" {
			return errors.New("has requires alias")
		}
		ok, err := svc.Has(ctx, alias)
		if err != nil {
			return err
		}
		fmt.Println(ok)
		return nil
	case "list":
		aliases, err := svc.List(ctx)
		if err != nil {
			return err
		}
		for _, a := range aliases {
			fmt.Println(a)
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func writeEnclaveHex(w io.Writer, prefix string, enclave *memguard.Enclave) error {
	if enclave == nil {
		return hmacsecret.ErrEmptyHMACSecret
	}
	secret, err := enclave.Open()
	if err != nil {
		return fmt.Errorf("open hmac-secret enclave: %w", err)
	}
	defer secret.Destroy()

	if _, err := io.WriteString(w, prefix); err != nil {
		return fmt.Errorf("write hmac-secret prefix: %w", err)
	}
	if _, err := hex.NewEncoder(w).Write(secret.Bytes()); err != nil {
		return fmt.Errorf("write hmac-secret: %w", err)
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return fmt.Errorf("write hmac-secret newline: %w", err)
	}
	return nil
}

func openStore(backend, path string) (store.Store, error) {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "pebble", "":
		return pebble.Open(path)
	case "sqlite":
		return sqlite.Open(path)
	default:
		return nil, fmt.Errorf("unknown backend %q", backend)
	}
}

func defaultPINProvider() libsecrets.PINProvider {
	if runtime.GOOS == "windows" {
		return pinwindows.New()
	}
	return pincli.New()
}
