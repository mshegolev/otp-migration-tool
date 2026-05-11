// Command otp-migrate decodes Google Authenticator "Export accounts" QR codes
// (otpauth-migration:// URIs) and prints the contained accounts.
//
// Usage:
//
//	otp-migrate qr      path/to/export.png
//	otp-migrate url     'otpauth-migration://offline?data=...'
//	otp-migrate qr      export.png --json
//	otp-migrate qr      export.png --totp
//	otp-migrate code    export.png --issuer Acme
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
  otp-migrate qr   <image>...       decode one or more QR image files (PNG or JPEG)
  otp-migrate url  <uri>...         decode one or more otpauth-migration:// URIs
  otp-migrate code <input>...       print only the current 6/8-digit TOTP code
  otp-migrate -h | --help

Multiple inputs are merged as a multi-QR export (Google Authenticator splits
exports with >10 accounts across several QR codes). All inputs must belong to
the same export (matching batch_id) and together cover every batch_index.

The ` + "`code`" + ` subcommand accepts either image paths or otpauth-migration://
URIs (auto-detected). It writes the current TOTP code on a single line — ideal
for shell pipelines and clipboard managers. If the export contains more than one
account, narrow it down with --issuer and/or --name.

Options:
  --json            emit accounts as a JSON array (machine readable)
  --totp            also print the current TOTP code for every TOTP account
  --reveal          include the base32 secret in plain-text output (default: redacted)
  --issuer <str>    filter accounts by issuer (case-insensitive substring)
  --name   <str>    filter accounts by account name (case-insensitive substring)

Examples:
  otp-migrate qr ./examples/demo-qr.png
  otp-migrate qr ./export-1.png ./export-2.png ./export-3.png --totp
  otp-migrate url 'otpauth-migration://offline?data=...' --json
  otp-migrate code ~/secrets/auth.png --issuer Acme
  otp-migrate code ~/secrets/auth.png --issuer Acme | pbcopy
`

// Set by goreleaser at link time via -ldflags. Defaults are useful for `go run`
// or a plain `go build` from a checkout.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

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
	if args[0] == "version" || args[0] == "--version" || args[0] == "-v" {
		fmt.Fprintf(stdout, "otp-migrate %s (commit %s, built %s)\n", version, commit, date)
		return nil
	}

	sub := args[0]
	rest := args[1:]

	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit JSON")
	withTOTP := fs.Bool("totp", false, "print current TOTP code per account")
	reveal := fs.Bool("reveal", false, "show base32 secret in plain output")
	issuerFilter := fs.String("issuer", "", "filter accounts by issuer (case-insensitive substring)")
	nameFilter := fs.String("name", "", "filter accounts by account name (case-insensitive substring)")

	flags, positional := reorderFlags(fs, rest)
	if err := fs.Parse(flags); err != nil {
		return err
	}

	var (
		accounts []migration.Account
		err      error
	)
	switch sub {
	case "qr":
		if len(positional) == 0 {
			return errors.New("`qr` requires at least one image argument")
		}
		uris := make([]string, 0, len(positional))
		for _, path := range positional {
			text, qErr := qr.DecodeFile(path)
			if qErr != nil {
				return fmt.Errorf("%s: %w", path, qErr)
			}
			uris = append(uris, text)
		}
		accounts, err = migration.DecodeURLs(uris)
	case "url":
		if len(positional) == 0 {
			return errors.New("`url` requires at least one URI argument")
		}
		accounts, err = migration.DecodeURLs(positional)
	case "code":
		if len(positional) == 0 {
			return errors.New("`code` requires at least one image path or otpauth-migration:// URI")
		}
		uris, decErr := loadURIs(positional)
		if decErr != nil {
			return decErr
		}
		accounts, err = migration.DecodeURLs(uris)
	default:
		return fmt.Errorf("unknown subcommand %q (try `-h`)", sub)
	}
	if err != nil {
		return err
	}

	accounts = filterAccounts(accounts, *issuerFilter, *nameFilter)

	if sub == "code" {
		return emitCode(stdout, accounts, *issuerFilter, *nameFilter)
	}
	if *asJSON {
		return emitJSON(stdout, accounts, *withTOTP, *reveal)
	}
	return emitText(stdout, accounts, *withTOTP, *reveal)
}

// loadURIs converts a list of `code` positional inputs into otpauth-migration:// URIs.
// An input that already starts with the migration scheme is passed through verbatim;
// anything else is treated as a path to a QR image and decoded.
func loadURIs(inputs []string) ([]string, error) {
	uris := make([]string, 0, len(inputs))
	for _, in := range inputs {
		if strings.HasPrefix(in, "otpauth-migration://") {
			uris = append(uris, in)
			continue
		}
		text, qErr := qr.DecodeFile(in)
		if qErr != nil {
			return nil, fmt.Errorf("%s: %w", in, qErr)
		}
		uris = append(uris, text)
	}
	return uris, nil
}

// filterAccounts keeps only accounts whose Issuer and Name match the given
// case-insensitive substring filters. An empty filter matches everything.
func filterAccounts(accounts []migration.Account, issuer, name string) []migration.Account {
	if issuer == "" && name == "" {
		return accounts
	}
	issuer = strings.ToLower(issuer)
	name = strings.ToLower(name)
	out := accounts[:0:0]
	for _, a := range accounts {
		if issuer != "" && !strings.Contains(strings.ToLower(a.Issuer), issuer) {
			continue
		}
		if name != "" && !strings.Contains(strings.ToLower(a.Name), name) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// emitCode writes a single TOTP code on stdout, suitable for piping into
// `pbcopy` or another script. It expects the caller to have already applied
// any --issuer / --name filters. The filter values are taken back as
// parameters only to compose a useful error message when matching fails.
func emitCode(w io.Writer, accounts []migration.Account, issuer, name string) error {
	totps := accounts[:0:0]
	for _, a := range accounts {
		if strings.EqualFold(a.Type, "totp") {
			totps = append(totps, a)
		}
	}
	switch len(totps) {
	case 0:
		if issuer != "" || name != "" {
			return fmt.Errorf("no TOTP accounts match issuer=%q name=%q (try `otp-migrate qr <input>` to list them)", issuer, name)
		}
		return errors.New("no TOTP accounts found in the input")
	case 1:
		code, err := totp.Now(totps[0])
		if err != nil {
			return err
		}
		fmt.Fprintln(w, code)
		return nil
	default:
		var b strings.Builder
		b.WriteString("multiple TOTP accounts match — narrow with --issuer and/or --name. Candidates:")
		for _, a := range totps {
			b.WriteString("\n  - issuer=")
			b.WriteString(a.Issuer)
			b.WriteString(" name=")
			b.WriteString(a.Name)
		}
		return errors.New(b.String())
	}
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
// may appear in any order relative to positionals (e.g. `qr foo.png --json` or
// `code foo.png --issuer Acme`). Value-flags like `--issuer X` consume the next
// token as their value; boolean flags do not. We detect this via the standard
// library's IsBoolFlag interface so the function stays correct for any future
// flag we register on `fs`.
func reorderFlags(fs *flag.FlagSet, args []string) (flags, positional []string) {
	isBool := func(name string) bool {
		f := fs.Lookup(name)
		if f == nil {
			return false
		}
		bf, ok := f.Value.(interface{ IsBoolFlag() bool })
		return ok && bf.IsBoolFlag()
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		if strings.Contains(a, "=") {
			continue // `--name=value` carries its own value
		}
		name := strings.TrimLeft(a, "-")
		if !isBool(name) && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
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
