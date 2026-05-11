# otp-migration-tool

[![CI](https://github.com/mshegolev/otp-migration-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/mshegolev/otp-migration-tool/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mshegolev/otp-migration-tool.svg)](https://pkg.go.dev/github.com/mshegolev/otp-migration-tool)
[![Go Report Card](https://goreportcard.com/badge/github.com/mshegolev/otp-migration-tool)](https://goreportcard.com/report/github.com/mshegolev/otp-migration-tool)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Decode **Google Authenticator** `Export accounts` QR codes into plain `otpauth://`
URIs, base32 secrets, and (optionally) current TOTP codes — from a single, static
Go binary, with **no external dependencies** at runtime (no `zbarimg`, no Python).

## What it does

When you tap *Export accounts* in Google Authenticator, the app produces one or
more QR codes that encode `otpauth-migration://offline?data=…`. The `data`
payload is a base64-encoded protobuf containing every TOTP/HOTP secret you
selected. `otp-migration-tool` reads such a QR (or the URI directly) and prints
each account back as a standards-compliant `otpauth://` URI you can paste into
any other authenticator, plus the raw base32 secret.

Useful when you switch phones, set up a hardware key, or back up your TOTP
secrets offline.

## Install

### From source

```bash
go install github.com/mshegolev/otp-migration-tool/cmd/otp-migrate@latest
```

### Build locally

```bash
git clone https://github.com/mshegolev/otp-migration-tool
cd otp-migration-tool
go build ./cmd/otp-migrate
./otp-migrate -h
```

## Usage

```text
otp-migrate qr  <image>          decode a QR image file (PNG or JPEG)
otp-migrate url <uri>            decode an otpauth-migration:// URI directly

Options:
  --json        emit accounts as a JSON array (machine readable)
  --totp        also print the current TOTP code for every TOTP account
  --reveal      include the base32 secret in plain-text output (default: redacted)
```

### Decode a QR image

```bash
otp-migrate qr ./export.png
```

Output:

```
[1] Acme — alice@example.com
    type:      TOTP
    algorithm: SHA1
    digits:    6
    secret:    [redacted; pass --reveal to print]
    url:       otpauth://totp/Acme:alice@example.com?algorithm=SHA1&digits=6&issuer=Acme&period=30&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
```

### Print the current TOTP code

```bash
otp-migrate qr ./export.png --totp --reveal
```

### Machine-readable JSON for scripting

```bash
otp-migrate qr ./export.png --json --reveal | jq '.[] | .otpauth_url'
```

### Demo (safe to run on your machine)

This repo ships a `examples/demo-qr.png` built with **publicly known fake
secrets** (RFC 6238 reference test vectors) — never use them for real accounts.

```bash
otp-migrate qr examples/demo-qr.png --totp --reveal
```

## Security notes

- **Your `data` payload is sensitive.** Anyone who reads it can clone your TOTP
  accounts. Treat the QR like a password.
- By default the base32 secret is **redacted** from the plain-text output. Use
  `--reveal` only when you actually need to copy it.
- The repository's `.gitignore` blocks `*.png/*.jpg/*.jpeg/*.url` at the project
  root specifically to prevent accidentally committing a real export QR.
- The binary is pure-Go and statically linked — no `zbarimg`, `libzbar`, Python
  or other system libraries are loaded at runtime. Less code, smaller attack
  surface.

## How it works (one paragraph)

`otp-migrate qr` reads a PNG/JPEG and decodes the QR with the pure-Go
[`gozxing`](https://github.com/makiuchi-d/gozxing) reader; the resulting string
is parsed as a URL, the `data` query is base64-decoded (4 padding variants are
tried for robustness), and the bytes are unmarshalled as a `MigrationPayload`
protobuf (see [`proto/otp_migration.proto`](proto/otp_migration.proto)). Each
`OtpParameters` entry is converted into a friendly `Account` struct that knows
how to re-emit itself as an `otpauth://` URI. TOTP generation follows
[RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) on top of an in-tree
HMAC-based HOTP implementation ([RFC 4226](https://www.rfc-editor.org/rfc/rfc4226)
§5.3); the test suite verifies the RFC's reference vectors verbatim.

## Project layout

```
.
├── cmd/otp-migrate/         CLI entry point
├── internal/
│   ├── migration/           protobuf decoding & otpauth:// URL building
│   ├── migration/pb/        generated Go from proto/
│   ├── qr/                  pure-Go QR image decoder
│   └── totp/                RFC 6238 / 4226 OTP generation
├── proto/                   .proto schema (Google Auth migration payload)
├── examples/                demo QR with fake secrets
└── .github/workflows/       CI
```

### Re-generate Go from proto

```bash
brew install protobuf
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
protoc --go_out=. --go_opt=module=github.com/mshegolev/otp-migration-tool \
  -I proto proto/otp_migration.proto
```

## Tests

```bash
go test ./...
```

Includes the six RFC 6238 reference vectors (SHA1, T = 59, 1111111109,
1111111111, 1234567890, 2000000000, 20000000000).

## Acknowledgements

- The protobuf schema is the original
  [Chris van Marle (2020)](https://github.com/dim13/otpauth) reverse-engineering
  of Google Authenticator's export format.
- QR decoding is provided by
  [`makiuchi-d/gozxing`](https://github.com/makiuchi-d/gozxing), a Go port of
  ZXing.

## License

[MIT](LICENSE)
