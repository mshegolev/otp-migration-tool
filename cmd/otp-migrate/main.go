// Command otp-migrate decodes Google Authenticator "Export accounts" QR codes
// (otpauth-migration:// URIs) and prints the contained accounts.
//
// Usage:
//
//	otp-migrate qr      path/to/export.png
//	otp-migrate url     'otpauth-migration://offline?data=...'
//	otp-migrate qr      export.png --json
//	otp-migrate qr      export.png --totp
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mshegolev/otp-migration-tool/internal/migration"
	"github.com/mshegolev/otp-migration-tool/internal/qr"
	"github.com/mshegolev/otp-migration-tool/internal/totp"
)

const usage = `otp-migrate — decode Google Authenticator migration QR/URL.

Usage:
  otp-migrate qr  <image>          decode a QR image file (PNG or JPEG)
  otp-migrate url <uri>            decode an otpauth-migration:// URI directly
  otp-migrate -h | --help

Options:
  --json        emit accounts as a JSON array (machine readable)
  --totp        also print the current TOTP code for every TOTP account
  --reveal      include the base32 secret in plain-text output (default: redacted)

Examples:
  otp-migrate qr ./examples/demo-qr.png
  otp-migrate qr ./export.png --totp
  otp-migrate url 'otpauth-migration://offline?data=...' --json
`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, usage)
		return nil
	}

	sub := args[0]
	rest := args[1:]

	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit JSON")
	withTOTP := fs.Bool("totp", false, "print current TOTP code per account")
	reveal := fs.Bool("reveal", false, "show base32 secret in plain output")

	flags, positional := reorderFlags(rest)
	if err := fs.Parse(flags); err != nil {
		return err
	}

	var (
		accounts []migration.Account
		err      error
	)
	switch sub {
	case "qr":
		if len(positional) != 1 {
			return errors.New("`qr` requires exactly one argument: <image>")
		}
		text, qErr := qr.DecodeFile(positional[0])
		if qErr != nil {
			return qErr
		}
		accounts, err = migration.DecodeURL(text)
	case "url":
		if len(positional) != 1 {
			return errors.New("`url` requires exactly one argument: <uri>")
		}
		accounts, err = migration.DecodeURL(positional[0])
	default:
		return fmt.Errorf("unknown subcommand %q (try `-h`)", sub)
	}
	if err != nil {
		return err
	}

	if *asJSON {
		return emitJSON(stdout, accounts, *withTOTP, *reveal)
	}
	return emitText(stdout, accounts, *withTOTP, *reveal)
}

func emitText(w io.Writer, accounts []migration.Account, withTOTP, reveal bool) error {
	for i, a := range accounts {
		fmt.Fprintf(w, "[%d] %s\n", i+1, displayLabel(a))
		fmt.Fprintf(w, "    type:      %s\n", strings.ToUpper(a.Type))
		fmt.Fprintf(w, "    algorithm: %s\n", a.Algorithm)
		fmt.Fprintf(w, "    digits:    %d\n", a.Digits)
		secret := "[redacted; pass --reveal to print]"
		if reveal {
			secret = a.SecretB32
		}
		fmt.Fprintf(w, "    secret:    %s\n", secret)
		fmt.Fprintf(w, "    url:       %s\n", a.OTPAuthURL())
		if withTOTP && strings.EqualFold(a.Type, "totp") {
			code, err := totp.Now(a)
			if err != nil {
				return err
			}
			fmt.Fprintf(w, "    code now:  %s\n", code)
		}
		fmt.Fprintln(w)
	}
	return nil
}

type jsonAccount struct {
	Issuer    string `json:"issuer"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	SecretB32 string `json:"secret,omitempty"`
	URL       string `json:"otpauth_url"`
	Code      string `json:"code,omitempty"`
}

func emitJSON(w io.Writer, accounts []migration.Account, withTOTP, reveal bool) error {
	out := make([]jsonAccount, 0, len(accounts))
	for _, a := range accounts {
		j := jsonAccount{
			Issuer:    a.Issuer,
			Name:      a.Name,
			Type:      a.Type,
			Algorithm: a.Algorithm,
			Digits:    a.Digits,
			URL:       a.OTPAuthURL(),
		}
		if reveal {
			j.SecretB32 = a.SecretB32
		}
		if withTOTP && strings.EqualFold(a.Type, "totp") {
			code, err := totp.Now(a)
			if err != nil {
				return err
			}
			j.Code = code
		}
		out = append(out, j)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // we are not emitting into HTML; keep & and < readable.
	return enc.Encode(out)
}

// reorderFlags splits `args` into (flag-like tokens, positional tokens) so flags
// may appear in any order relative to positionals (e.g. `qr foo.png --json`).
// All flags in this CLI are boolean, so we never need to consume a following value.
func reorderFlags(args []string) (flags, positional []string) {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
		} else {
			positional = append(positional, a)
		}
	}
	return flags, positional
}

func displayLabel(a migration.Account) string {
	switch {
	case a.Issuer != "" && a.Name != "":
		return a.Issuer + " — " + a.Name
	case a.Issuer != "":
		return a.Issuer
	default:
		return a.Name
	}
}
