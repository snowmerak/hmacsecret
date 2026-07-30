# Bundled go-libfido2

Upstream: https://github.com/keys-pub/go-libfido2

- Version: `v1.5.3`
- Commit: `2399f32e9077b2b1f651bb675505c8d6e654b833`
- License: MIT (`LICENSE`)

Local changes:

- Add `ClientDataJSON` to credential and assertion options.
- Pass raw WebAuthn client data to libfido2 when supplied.
- Link normal macOS CGO builds against Homebrew libfido2 through pkg-config.
- Compile the bundled patched libfido2 1.17.0 Windows sources directly with
  cgo instead of linking a separate libfido2 library.
- Support the same Windows source set on ARM64 and AMD64.

This directory is part of the parent Go module and intentionally has no
separate `go.mod` or `go.sum`.
