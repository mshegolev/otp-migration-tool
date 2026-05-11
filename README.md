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

### Pre-built binaries

Each tagged release publishes static binaries for Linux, macOS, and Windows
(amd64 + arm64) on the [releases page](https://github.com/mshegolev/otp-migration-tool/releases).
Download the archive for your platform, extract, and run.

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

## Get the QR code out of Google Authenticator

`otp-migrate` does not talk to your phone — it just reads the QR image (or the
`otpauth-migration://` URI) that Google Authenticator already shows you on the
*Export accounts* screen. The hard part is usually getting that image onto
your computer.

### 1. Open the export screen in Authenticator

1. Open **Google Authenticator** on your phone.
2. Tap the menu (`⋮` top-right, or your account avatar) → **Transfer
   accounts** → **Export accounts**.
3. Authenticate (FaceID / fingerprint / PIN).
4. Select the accounts you want to migrate → **Next**.
5. Authenticator now shows one or more QR codes ("**1 of N**" in the top-right
   if there is more than one). Each QR encodes an
   `otpauth-migration://offline?data=…` URI with a chunk of your accounts.

> ⚠️ **Treat that screen like a password.** Anyone who photographs it gets
> every selected TOTP secret. Don't post it in chat, don't sync it to the
> cloud, don't paste it into web tools.

### 2. Get the QR image onto your computer

**iPhone / iPad**
1. While the QR is on screen, take a **screenshot** (Side button + Volume Up).
2. AirDrop / email / copy the screenshot to your Mac or Linux/Windows box.

**Android**
Google Authenticator on Android marks its export screen with `FLAG_SECURE`,
which **blocks screenshots** — you will get a black image or "Can't take
screenshot due to security policy". Workarounds:

- Easiest: use a **second device** (another phone or a webcam) to photograph
  the QR on screen, then move the JPG/PNG to your computer.
- Developer route: with ADB enabled,
  `adb exec-out screencap -p > export.png` bypasses `FLAG_SECURE` on most
  builds.
- If you have multiple QR codes, swipe through them and capture each one in
  turn — `otp-migrate` will merge them.

### 3. Decode

```bash
# one QR
otp-migrate qr ./export.png --totp

# several QR codes from a single export (any order)
otp-migrate qr ./export-1.png ./export-2.png ./export-3.png --totp

# if you already extracted the otpauth-migration:// URI
otp-migrate url 'otpauth-migration://offline?data=...' --reveal
```

When you are done, **delete the image files**. They are equivalent to your
secret keys in plain text.

## Usage

```text
otp-migrate qr   <image>...       decode one or more QR images (PNG or JPEG)
otp-migrate url  <uri>...         decode one or more otpauth-migration:// URIs
otp-migrate code <input>...       print only the current 6/8-digit TOTP code

Options:
  --json            emit accounts as a JSON array (machine readable)
  --totp            also print the current TOTP code for every TOTP account
  --reveal          include the base32 secret in plain-text output (default: redacted)
  --issuer <str>    filter accounts by issuer (case-insensitive substring)
  --name   <str>    filter accounts by account name (case-insensitive substring)
```

### Just give me the 6-digit code

If you only care about pasting the current code into another app (the classic
"call a script, get six digits" workflow), use the `code` subcommand:

```bash
# one account in the file — no filter needed
otp-migrate code ~/secrets/mts.png
# 482917

# many accounts — narrow with --issuer (and --name if still ambiguous)
otp-migrate code ~/secrets/export.png --issuer MTS

# straight to the macOS clipboard
otp-migrate code ~/secrets/mts.png --issuer MTS | pbcopy
```

`code` writes a single 6/8-digit line to **stdout** and nothing else, so it
composes cleanly in shell pipelines (`$(otp-migrate code ...)`, `| pbcopy`,
`| xclip`, etc.). Errors go to **stderr** with exit code `1`. If your filter
matches more than one TOTP account, the error lists the candidates so you can
tighten it. Inputs may be either an image path or an `otpauth-migration://`
URI — the subcommand auto-detects.

A handy zsh function for a single, recurring account:

```bash
# ~/.zshrc
mts-otp() { otp-migrate code ~/secrets/mts.png --issuer MTS "$@" ; }
```

### Multiple QR codes from one export

If you have more than ~10 accounts, Google Authenticator splits the export
into several QR codes. Pass all of them at once and they will be merged into
a single account list:

```bash
otp-migrate qr export-1.png export-2.png export-3.png --totp
```

Inputs may be passed in any order. They must share the same `batch_id` and
together cover every `batch_index` of the export — `otp-migrate` exits with
an explanatory error otherwise.

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
