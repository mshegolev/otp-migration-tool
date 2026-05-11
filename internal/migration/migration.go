// Package migration decodes Google Authenticator export payloads ("otpauth-migration://" URIs)
// into a slice of OTP account records.
package migration

import (
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/mshegolev/otp-migration-tool/internal/migration/pb"
	"google.golang.org/protobuf/proto"
)

const (
	scheme        = "otpauth-migration"
	queryDataKey  = "data"
	exportedPath  = "offline"
)

var (
	ErrWrongScheme  = errors.New("not an otpauth-migration:// URI")
	ErrMissingData  = errors.New("missing required `data` query parameter")
	ErrInvalidProto = errors.New("payload is not a valid MigrationPayload")
)

// Account is the decoded, user-facing form of one OTP entry.
// It contains everything needed to (re)generate codes or build an otpauth:// URL.
type Account struct {
	Issuer    string
	Name      string
	Secret    []byte
	SecretB32 string
	Algorithm string
	Digits    int
	Type      string
	Counter   int64
}

// OTPAuthURL returns a Key Uri Format link as defined by Google Authenticator:
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func (a Account) OTPAuthURL() string {
	label := url.PathEscape(a.Issuer + ":" + a.Name)
	if a.Issuer == "" {
		label = url.PathEscape(a.Name)
	}
	q := url.Values{}
	q.Set("secret", a.SecretB32)
	if a.Issuer != "" {
		q.Set("issuer", a.Issuer)
	}
	q.Set("algorithm", a.Algorithm)
	q.Set("digits", fmt.Sprintf("%d", a.Digits))
	if strings.EqualFold(a.Type, "hotp") {
		q.Set("counter", fmt.Sprintf("%d", a.Counter))
	} else {
		q.Set("period", "30")
	}
	return fmt.Sprintf("otpauth://%s/%s?%s", strings.ToLower(a.Type), label, q.Encode())
}

// DecodeURL parses an otpauth-migration:// URI and returns the contained accounts.
func DecodeURL(raw string) ([]Account, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("parse URI: %w", err)
	}
	if u.Scheme != scheme {
		return nil, ErrWrongScheme
	}
	data := u.Query().Get(queryDataKey)
	if data == "" {
		return nil, ErrMissingData
	}
	return DecodePayload(data)
}

// DecodePayload parses the base64-encoded protobuf payload (the value of the
// `data` query parameter) and returns the contained accounts.
func DecodePayload(b64Data string) ([]Account, error) {
	// Some exports use URL-safe base64; some standard. Try both with permissive padding.
	decoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	}
	// `data` arrives URL-encoded inside the query string but net/url already unquoted it.
	var raw []byte
	var lastErr error
	for _, dec := range decoders {
		raw, lastErr = dec.DecodeString(b64Data)
		if lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("base64 decode: %w", lastErr)
	}

	payload := &pb.MigrationPayload{}
	if err := proto.Unmarshal(raw, payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProto, err)
	}

	out := make([]Account, 0, len(payload.OtpParameters))
	for _, p := range payload.OtpParameters {
		out = append(out, toAccount(p))
	}
	return out, nil
}

func toAccount(p *pb.OtpParameters) Account {
	return Account{
		Issuer:    p.GetIssuer(),
		Name:      p.GetName(),
		Secret:    p.GetSecret(),
		SecretB32: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(p.GetSecret()),
		Algorithm: algorithmName(p.GetAlgorithm()),
		Digits:    digitCount(p.GetDigits()),
		Type:      otpTypeName(p.GetType()),
		Counter:   p.GetCounter(),
	}
}

func algorithmName(a pb.Algorithm) string {
	switch a {
	case pb.Algorithm_ALGORITHM_SHA256:
		return "SHA256"
	case pb.Algorithm_ALGORITHM_SHA512:
		return "SHA512"
	case pb.Algorithm_ALGORITHM_MD5:
		return "MD5"
	default:
		return "SHA1"
	}
}

func digitCount(d pb.DigitCount) int {
	if d == pb.DigitCount_DIGIT_COUNT_EIGHT {
		return 8
	}
	return 6
}

func otpTypeName(t pb.OtpType) string {
	if t == pb.OtpType_OTP_TYPE_HOTP {
		return "hotp"
	}
	return "totp"
}
