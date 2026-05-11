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
	ErrWrongScheme    = errors.New("not an otpauth-migration:// URI")
	ErrMissingData    = errors.New("missing required `data` query parameter")
	ErrInvalidProto   = errors.New("payload is not a valid MigrationPayload")
	ErrEmptyInput     = errors.New("no payloads provided")
	ErrBatchMismatch  = errors.New("batch metadata mismatch across payloads (different exports?)")
	ErrBatchIncomplete = errors.New("incomplete batch: missing or duplicate batch_index")
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

// DecodeURL parses one otpauth-migration:// URI and returns the contained accounts.
// For exports split across multiple QR codes, use DecodeURLs instead.
func DecodeURL(raw string) ([]Account, error) {
	payload, err := parseURI(raw)
	if err != nil {
		return nil, err
	}
	return paramsToAccounts(payload.OtpParameters), nil
}

// DecodeURLs accepts the URIs from every QR of a multi-QR Google Authenticator
// export, validates their batch metadata, and returns the merged accounts in
// the original batch order. A single URI is handled as the degenerate case.
func DecodeURLs(raws []string) ([]Account, error) {
	if len(raws) == 0 {
		return nil, ErrEmptyInput
	}
	payloads := make([]*pb.MigrationPayload, 0, len(raws))
	for i, r := range raws {
		p, err := parseURI(r)
		if err != nil {
			return nil, fmt.Errorf("payload #%d: %w", i+1, err)
		}
		payloads = append(payloads, p)
	}
	return MergePayloads(payloads)
}

// DecodePayload parses one base64-encoded protobuf payload (the value of the
// `data` query parameter) and returns the contained accounts.
func DecodePayload(b64Data string) ([]Account, error) {
	payload, err := unmarshalPayload(b64Data)
	if err != nil {
		return nil, err
	}
	return paramsToAccounts(payload.OtpParameters), nil
}

// MergePayloads validates and concatenates payloads coming from a single
// multi-QR export. All payloads must share the same batch_id and batch_size,
// and together cover every batch_index in [0, batch_size) exactly once.
func MergePayloads(payloads []*pb.MigrationPayload) ([]Account, error) {
	if len(payloads) == 0 {
		return nil, ErrEmptyInput
	}
	// Single-QR exports often have batch_size = 1 and batch_index = 0, or all
	// zero values — both shapes work fine with the same validation rules.
	wantID := payloads[0].GetBatchId()
	wantSize := payloads[0].GetBatchSize()
	if wantSize == 0 {
		wantSize = int32(len(payloads))
	}
	if int(wantSize) != len(payloads) {
		return nil, fmt.Errorf("%w: got %d payloads, batch_size=%d", ErrBatchMismatch, len(payloads), wantSize)
	}

	seen := make(map[int32]*pb.MigrationPayload, len(payloads))
	for i, p := range payloads {
		if p.GetBatchId() != wantID {
			return nil, fmt.Errorf("%w: payload #%d has batch_id=%d, want %d",
				ErrBatchMismatch, i+1, p.GetBatchId(), wantID)
		}
		if p.GetBatchSize() != 0 && p.GetBatchSize() != wantSize {
			return nil, fmt.Errorf("%w: payload #%d has batch_size=%d, want %d",
				ErrBatchMismatch, i+1, p.GetBatchSize(), wantSize)
		}
		idx := p.GetBatchIndex()
		if idx < 0 || idx >= wantSize {
			return nil, fmt.Errorf("%w: payload #%d batch_index=%d out of range [0,%d)",
				ErrBatchIncomplete, i+1, idx, wantSize)
		}
		if _, dup := seen[idx]; dup {
			return nil, fmt.Errorf("%w: duplicate batch_index=%d", ErrBatchIncomplete, idx)
		}
		seen[idx] = p
	}

	out := make([]Account, 0)
	for i := int32(0); i < wantSize; i++ {
		p, ok := seen[i]
		if !ok {
			return nil, fmt.Errorf("%w: missing batch_index=%d", ErrBatchIncomplete, i)
		}
		out = append(out, paramsToAccounts(p.OtpParameters)...)
	}
	return out, nil
}

func parseURI(raw string) (*pb.MigrationPayload, error) {
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
	return unmarshalPayload(data)
}

func unmarshalPayload(b64Data string) (*pb.MigrationPayload, error) {
	// Some exports use URL-safe base64; some standard. Try the four variants.
	decoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	}
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
	return payload, nil
}

func paramsToAccounts(params []*pb.OtpParameters) []Account {
	out := make([]Account, 0, len(params))
	for _, p := range params {
		out = append(out, toAccount(p))
	}
	return out
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
