---
name: use-hmacsecret
description: Integrate this repository's Go packages for FIDO2 WebAuthn PRF / CTAP2 hmac-secret into applications. Use when adding hmacsecret as a library dependency, choosing between the alias-based secrets service and the low-level authenticator API, implementing device/PIN/store providers, persisting recoverable credential metadata, handling library errors, or accounting for Windows, macOS, Linux, and WSL behavior. Treat the bundled CLIs as optional diagnostics rather than the primary integration surface.
---

# Integrate hmacsecret as a Go Library

Use `github.com/snowmerak/hmacsecret` as a library for deriving deterministic secrets from a FIDO2 authenticator. Keep application integration separate from the repository's example and operational CLIs.

Do not build, install, attach USB devices, or run authenticator operations unless the user explicitly asks. Inspect code and tests when answering API or behavior questions.

## Choose the Integration Level

Prefer `github.com/snowmerak/hmacsecret/pkg/secrets` for application code that needs named aliases, persistent credential metadata, device selection, and PIN handling.

Use `github.com/snowmerak/hmacsecret/lib/hmacsecret` directly only when the application needs custom credential lifecycle management, storage, device policy, or authenticator flow.

Use these supporting contracts and implementations as needed:

- `lib/secrets`: `DeviceSelector` and `PINProvider` interfaces.
- `lib/store`: persistent metadata `Store` interface and validation helpers.
- `pkg/store/pebble` or `pkg/store/sqlite`: ready-made persistent stores.
- `pkg/device/cli`: interactive terminal device selector.
- `pkg/pin/cli`: hidden terminal PIN input.
- `pkg/pin/windows`: empty PIN provider for the Windows WebAuthn UI.

Do not couple a server, GUI, or reusable package to the CLI providers. Implement the small interfaces with application-native UI, configuration, or policy instead.

## Prefer the Alias-Based Service

Construct `pkg/secrets.Secrets` once and reuse it. Supply a store, selector, PIN provider, and a stable relying-party ID:

```go
metadata, err := pebble.Open("data/hmacsecret")
if err != nil {
	return err
}
defer metadata.Close()

service, err := secrets.New(secrets.Options{
	Store:    metadata,
	Select:   selector,
	PIN:      pinProvider,
	RPID:     "secrets.example.com",
	RPName:   "Example secrets",
	UserName: "secret-service",
})
if err != nil {
	return err
}

secret, err := service.Derive(ctx, "database")
if errors.Is(err, secrets.ErrNotFound) {
	secret, err = service.Create(ctx, "database")
}
if err != nil {
	return err
}
defer zero(secret)
```

Import the packages explicitly:

```go
import (
	"errors"

	"github.com/snowmerak/hmacsecret/pkg/secrets"
	"github.com/snowmerak/hmacsecret/pkg/store/pebble"
)
```

Adapt the example to the application's error handling and secret-consumption API. Define `zero` locally if overwriting the returned byte slice is appropriate for the application.

Use the service methods according to their contracts:

- `Create(ctx, alias)` creates a non-discoverable credential, persists its metadata, and derives the first secret.
- `Derive(ctx, alias)` derives the same secret using stored metadata and the same authenticator.
- `Has`, `List`, and `Delete` manage aliases and metadata.
- `Delete` removes local metadata only. It does not modify the authenticator.

Treat aliases as application identifiers. Validate and authorize them before allowing create, derive, or delete operations.

## Handle Creation Recovery Correctly

`Create` persists the new record before its initial derivation. If credential creation and persistence succeed but derivation fails, the alias can already exist.

On a retry after such a failure:

1. Check `Has` or handle `ErrExists`.
2. Call `Derive` for the existing alias.
3. Do not create another credential automatically.

The service serializes creates only within one `Secrets` instance. Coordinate separately if multiple processes or service instances share a store.

Do not depend on alias listing order. Store implementations may differ.

## Use the Low-Level API Deliberately

When using `lib/hmacsecret`, own the complete metadata lifecycle:

```go
device, err := hmacsecret.OpenIndex(0, hmacsecret.ListOptions{})
if err != nil {
	return err
}

credential, err := device.CreateCredential(hmacsecret.CreateOptions{
	RPID:     "secrets.example.com",
	RPName:   "Example secrets",
	UserName: "secret-service",
	PIN:      pin,
})
if err != nil {
	return err
}

salt, _, err := hmacsecret.ParseSalt("")
if err != nil {
	return err
}

derived, err := device.Derive(hmacsecret.DeriveOptions{
	RPID:         credential.RPID,
	CredentialID: credential.ID,
	Salt:         salt,
	PIN:          pin,
})
if err != nil {
	return err
}
defer zero(derived.HMACSecret)
```

Persist the credential ID, 32-byte salt, and RP ID. The same authenticator and all three values are required to reproduce the secret. Do not persist the derived secret unless the application's threat model explicitly requires it.

Credentials created by this library are non-discoverable. Switching authenticators does not preserve derivability merely because the same RP ID, alias, or salt is used.

Use `ListDevices`, `Open`, or `OpenIndex` according to the application's device-selection policy. Avoid silently selecting index zero when multiple authenticators may be present.

## Design for Dependency Injection

Use `secrets.Options.Devices` and `secrets.Options.Open` to replace hardware discovery and device opening in tests or in applications with custom transports.

Implement:

- `lib/secrets.DeviceSelector` to choose from discovered devices.
- `lib/secrets.PINProvider` to obtain authorization for create and derive operations.
- `lib/store.Store` when Pebble or SQLite does not match the application's persistence model.

Preserve sentinel errors with `%w` when adding context so callers can use `errors.Is`. Map `pkg/secrets` errors such as `ErrInvalidAlias`, `ErrExists`, `ErrNotFound`, and `ErrNoDevice` at the application boundary.

Do not promise that context cancellation interrupts an authenticator operation already handed to an OS or hardware API. Apply timeouts and cancellation at the surrounding workflow boundary.

## Protect Sensitive Values

- Never log or serialize PINs or derived secret bytes.
- Avoid converting secrets to immutable strings.
- Keep secret byte slices scoped to their immediate consumer and overwrite owned copies when no longer needed.
- Store only alias, credential ID, salt, and RP ID for normal recovery.
- Keep the RP ID stable for the lifetime of an alias.
- Avoid automated PIN retries; authenticators may enforce retry counters or lockout behavior.
- Require explicit authorization before deleting metadata, because deletion can make the deterministic secret unrecoverable.

## Account for Platform Behavior

- Windows uses the native WebAuthn API and its security UI. Supply the Windows PIN provider, which returns an empty PIN to the library.
- macOS and Linux use system `libfido2` through CGO in normal builds.
- macOS and Linux builds with CGO disabled use the unsupported implementation and cannot access authenticators.
- WSL behaves as Linux and additionally requires the USB authenticator to be attached to the distribution and its HID device to be readable.

Do not add a custom `hmacsecret_libfido2` build tag for normal macOS or Linux consumers.

## Use CLIs Only for Diagnosis

Use `cmd/secrets` or `cmd/hmac-secret` only when the user explicitly wants to inspect device visibility, validate a platform setup, or operate the repository manually. Do not shell out to these commands from application code when the Go APIs can be called directly.
