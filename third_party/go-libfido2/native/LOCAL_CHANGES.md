# Bundled libfido2

Upstream: https://github.com/Yubico/libfido2

- Tag: `1.17.0`
- Commit: `b974e7cf2ee7392134cc12c08b76a068cf250dd8`
- License: BSD-2-Clause (`LICENSE`)

Local Windows changes:

- Map CTAP `hmac-secret` credential creation to the WebAuthn PRF extension.
- Require a cross-platform authenticator for credential creation and assertion.
- Use a strict `void` prototype for `WebAuthNGetApiVersionNumber`.
- Use `strerror_s` with the MinGW/Windows toolchain.

The native sources are compiled directly by cgo. They are not built or loaded
as a separate libfido2 shared library.
