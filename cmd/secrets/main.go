// Command secrets is a thin CLI over pkg/secrets with a pluggable store backend.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/snowmerak/hmacsecret/lib/hmacsecret"
	"github.com/snowmerak/hmacsecret/lib/store"
	"github.com/snowmerak/hmacsecret/pkg/secrets"
	"github.com/snowmerak/hmacsecret/pkg/store/pebble"
	"github.com/snowmerak/hmacsecret/pkg/store/sqlite"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
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
		device     string // empty=interactive/first, index N, or path
		noWebAuthn bool
	)

	fs.StringVar(&backend, "backend", "pebble", "store backend: pebble|sqlite")
	fs.StringVar(&dbPath, "db", "", "store path (default: ./data/secrets.pebble or ./data/secrets.sqlite)")
	fs.StringVar(&rpID, "rp-id", "hmac-secret.example", "relying party id for create")
	fs.StringVar(&userName, "user", "hmac-secret", "credential user name for create")
	fs.StringVar(&device, "device", "", "device selector: empty=prompt/first, integer index, or device path")
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
		Store: st,
		Select: cliDeviceSelector(device),
		PIN:    secrets.TerminalPIN(),
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
		fmt.Printf("hmac_secret=%s\n", hex.EncodeToString(secret))
		return nil
	case "derive", "get":
		if alias == "" {
			return errors.New("derive requires alias")
		}
		secret, err := svc.Derive(ctx, alias)
		if err != nil {
			return err
		}
		fmt.Printf("alias=%s\n", alias)
		fmt.Printf("hmac_secret=%s\n", hex.EncodeToString(secret))
		return nil
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

func cliDeviceSelector(spec string) secrets.DeviceSelector {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return secrets.DeviceSelectorFunc(func(_ context.Context, devices []hmacsecret.DeviceInfo) (hmacsecret.DeviceInfo, error) {
			if len(devices) == 0 {
				return hmacsecret.DeviceInfo{}, secrets.ErrNoDevice
			}
			for _, d := range devices {
				fmt.Fprintf(os.Stderr, "[%d] %s / %s (%s)\n", d.Index, d.Product, d.Manufacturer, d.Path)
			}
			if len(devices) == 1 {
				return devices[0], nil
			}
			fmt.Fprintf(os.Stderr, "device index [0-%d]: ", len(devices)-1)
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil {
				return hmacsecret.DeviceInfo{}, err
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
		})
	}
	if idx, err := strconv.Atoi(spec); err == nil {
		return secrets.DeviceByIndex(idx)
	}
	return secrets.DeviceByPath(spec)
}
