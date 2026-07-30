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

## Build

```powershell
.\scripts\build-windows-arm64.ps1
.\scripts\build-windows-amd64.ps1

# Build the alias-based CLI instead.
.\scripts\build-windows-arm64.ps1 `
    -Package ./cmd/secrets `
    -Output secrets-arm64.exe
```

The scripts always set `CGO_ENABLED=0`.

## Go API

The low-level API is in `lib/hmacsecret`. The higher-level alias and storage
service is in `pkg/secrets`.

The bundled patched libfido2 implementation is retained only as an explicit
compatibility/reference backend. It is excluded from normal builds and tests.
Enable it with the `hmacsecret_libfido2` build tag only in an environment with
its native toolchain and libraries installed.
