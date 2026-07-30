# hmacsecret

`hmacsecret` creates non-discoverable FIDO2 credentials and derives
deterministic 32-byte secrets with the WebAuthn PRF / CTAP2 `hmac-secret`
extension.

## Windows

Windows is implemented in pure Go through the system `webauthn.dll`.
The default build:

- supports Windows ARM64 and AMD64;
- works with `CGO_ENABLED=0`;
- does not require MSYS2, Clang, libfido2, OpenSSL, libcbor, or copied runtime
  DLLs;
- uses Windows Security UI to select and authenticate an external FIDO2 key.

The Windows WebAuthn API must be version 6 or newer.

```powershell
$env:CGO_ENABLED = "0"
go run ./cmd/secrets list
go run ./cmd/secrets create my-secret
go run ./cmd/secrets derive my-secret
```

Credential IDs, salts, and RP IDs are stored by the CLI. The derived secret is
not stored.

## Linux

Linux uses the system libfido2 automatically when CGO is enabled. No custom
build tag is required.

On Debian/Ubuntu:

```bash
sudo apt-get install build-essential libfido2-dev
CGO_ENABLED=1 go build -trimpath -o hmac-secret ./cmd/hmac-secret
CGO_ENABLED=1 go build -trimpath -o secrets ./cmd/secrets
CGO_ENABLED=1 go run ./cmd/hmac-secret -list
CGO_ENABLED=1 go run ./cmd/secrets list
```

With `CGO_ENABLED=0`, Linux builds use the unsupported-platform stub and cannot
access an authenticator.

## macOS

macOS uses Homebrew libfido2 automatically when CGO is enabled. Both Apple
Silicon and Intel Homebrew installations are supported, and no custom build
tag is required.

```bash
brew install pkg-config libfido2
CGO_ENABLED=1 go build -trimpath -o hmac-secret ./cmd/hmac-secret
CGO_ENABLED=1 go build -trimpath -o secrets ./cmd/secrets
CGO_ENABLED=1 go run ./cmd/hmac-secret -list
CGO_ENABLED=1 go run ./cmd/secrets list
```

With `CGO_ENABLED=0`, macOS builds use the unsupported-platform stub and cannot
access an authenticator.

## Windows cross-build

```powershell
go build -trimpath -o hmac-secret.exe ./cmd/hmac-secret
go build -trimpath -o secrets.exe ./cmd/secrets
```

To cross-compile for Windows ARM64:

```powershell
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "arm64"
go build -trimpath -o hmac-secret-arm64.exe ./cmd/hmac-secret
```

## Go API

The low-level API is in `lib/hmacsecret`. The higher-level alias and storage
service is in `pkg/secrets`.

Derived HMAC secrets are copied directly from native FIDO/WebAuthn-owned memory
into a `memguard.LockedBuffer`, sealed, and returned as `*memguard.Enclave`.
Open an enclave only when the plaintext is needed, and destroy the returned
locked buffer immediately after use:

```go
secret, err := service.Derive(ctx, "my-secret")
if err != nil {
	return err
}
plaintext, err := secret.Open()
if err != nil {
	return err
}
defer plaintext.Destroy()
// Use plaintext.Bytes() without copying it into an ordinary Go allocation.
```

### Encrypted store

`pkg/store/encrypted` implements `lib/store.EncryptedStore` over either the
Pebble or SQLite backend. Its public header stores the KEK credential ID, salt,
and RP ID needed to re-derive the KEK. A random 32-byte store DEK is wrapped by
that KEK, and complete per-alias credential records are authenticated and
encrypted by the store DEK with XChaCha20-Poly1305.

Aliases, format metadata, and the KEK reference remain public. Credential IDs,
salts, and RP IDs for stored aliases are encrypted. `Has` and `List` therefore
work while the store is locked; `Put`, `Get`, and `Delete` require an unlocked
store.

```go
backend, err := pebble.Open("data/secrets.pebble")
if err != nil {
	return err
}
encryptedStore, err := encrypted.New(backend)
if err != nil {
	return err
}
defer encryptedStore.Close()

// kek is a sealed 32-byte value derived from the public KEKReference.
err = encryptedStore.Initialize(ctx, store.KEKReference{
	CredentialID: kekCredentialID,
	Salt:         kekSalt,
	RPID:         kekRPID,
}, kek)
```

For an existing store, read `encryptedStore.Header()`, derive the KEK from its
public `KEK` reference, and pass the resulting enclave to
`encryptedStore.Unlock()`. `RotateKEK` rewraps only the store DEK; record
ciphertext is not rewritten.

Normal macOS and Linux CGO builds use the bundled patched Go bindings and link
against the system libfido2. The bundled native libfido2 sources are retained
only for the explicit Windows compatibility/reference backend; that non-default
backend still uses the `hmacsecret_libfido2` build tag and requires its native
toolchain.
