package migration

import (
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/mshegolev/otp-migration-tool/internal/migration/pb"
	"google.golang.org/protobuf/proto"
)

// buildFixture marshals a known MigrationPayload and returns the otpauth-migration URI.
func buildFixture(t *testing.T) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	payload := &pb.MigrationPayload{
		Version: 1,
		OtpParameters: []*pb.OtpParameters{
			{
				Secret:    secret,
				Name:      "alice",
				Issuer:    "Acme",
				Algorithm: pb.Algorithm_ALGORITHM_SHA1,
				Digits:    pb.DigitCount_DIGIT_COUNT_SIX,
				Type:      pb.OtpType_OTP_TYPE_TOTP,
			},
		},
	}
	raw, err := proto.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return "otpauth-migration://offline?data=" + url.QueryEscape(base64.StdEncoding.EncodeToString(raw))
}

func TestDecodeURL_RoundTrip(t *testing.T) {
	uri := buildFixture(t)
	accounts, err := DecodeURL(uri)
	if err != nil {
		t.Fatalf("DecodeURL: %v", err)
	}
	if len(accounts) != 1 {
		t.Fatalf("got %d accounts, want 1", len(accounts))
	}
	a := accounts[0]
	if a.Issuer != "Acme" || a.Name != "alice" {
		t.Errorf("bad label: %q / %q", a.Issuer, a.Name)
	}
	if a.Algorithm != "SHA1" || a.Digits != 6 || a.Type != "totp" {
		t.Errorf("bad params: %+v", a)
	}
	if a.SecretB32 != "JBSWY3DPEHPK3PXP" {
		t.Errorf("secret round-trip lost: %q", a.SecretB32)
	}
}

func TestDecodeURL_RejectsWrongScheme(t *testing.T) {
	_, err := DecodeURL("https://example.com")
	if err != ErrWrongScheme {
		t.Errorf("got %v, want ErrWrongScheme", err)
	}
}

func TestDecodeURL_RejectsMissingData(t *testing.T) {
	_, err := DecodeURL("otpauth-migration://offline")
	if err != ErrMissingData {
		t.Errorf("got %v, want ErrMissingData", err)
	}
}

func TestDecodeURL_RejectsCorruptPayload(t *testing.T) {
	_, err := DecodeURL("otpauth-migration://offline?data=" + url.QueryEscape("@@@notb64@@@"))
	if err == nil {
		t.Error("expected an error on corrupt payload")
	}
}

func TestOTPAuthURL_StructureForTOTP(t *testing.T) {
	a := Account{
		Issuer: "Acme", Name: "alice",
		SecretB32: "JBSWY3DPEHPK3PXP",
		Algorithm: "SHA1", Digits: 6, Type: "totp",
	}
	got := a.OTPAuthURL()
	for _, want := range []string{
		"otpauth://totp/", "Acme", "alice", "JBSWY3DPEHPK3PXP",
		"algorithm=SHA1", "digits=6", "period=30", "issuer=Acme",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("URL %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "counter=") {
		t.Errorf("TOTP URL must not have a counter: %q", got)
	}
}

// buildMultiFixture builds N URIs that together form one logical export
// (matching batch_id, batch_size=N, each carrying a single named account).
func buildMultiFixture(t *testing.T, n int, batchID int32) []string {
	t.Helper()
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString("JBSWY3DPEHPK3PXP")
	uris := make([]string, 0, n)
	for i := 0; i < n; i++ {
		p := &pb.MigrationPayload{
			Version:    1,
			BatchSize:  int32(n),
			BatchIndex: int32(i),
			BatchId:    batchID,
			OtpParameters: []*pb.OtpParameters{
				{
					Secret: secret,
					Name:   fmt.Sprintf("user-%d", i),
					Issuer: "Acme",
				},
			},
		}
		raw, err := proto.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		uris = append(uris, "otpauth-migration://offline?data="+url.QueryEscape(base64.StdEncoding.EncodeToString(raw)))
	}
	return uris
}

func TestDecodeURLs_MergesMultiQR(t *testing.T) {
	uris := buildMultiFixture(t, 3, 42)
	// Shuffle order; merge must restore by batch_index.
	uris[0], uris[2] = uris[2], uris[0]

	accounts, err := DecodeURLs(uris)
	if err != nil {
		t.Fatalf("DecodeURLs: %v", err)
	}
	if len(accounts) != 3 {
		t.Fatalf("got %d accounts, want 3", len(accounts))
	}
	for i, a := range accounts {
		want := fmt.Sprintf("user-%d", i)
		if a.Name != want {
			t.Errorf("order broken at #%d: got %q, want %q", i, a.Name, want)
		}
	}
}

func TestDecodeURLs_RejectsMismatchedBatchID(t *testing.T) {
	a := buildMultiFixture(t, 2, 1)
	b := buildMultiFixture(t, 2, 99)
	mixed := []string{a[0], b[1]}
	_, err := DecodeURLs(mixed)
	if !errors.Is(err, ErrBatchMismatch) {
		t.Errorf("got %v, want ErrBatchMismatch", err)
	}
}

func TestDecodeURLs_RejectsMissingBatchIndex(t *testing.T) {
	uris := buildMultiFixture(t, 3, 5)
	// Pass only 2 of 3 → batch_size mismatch.
	_, err := DecodeURLs(uris[:2])
	if !errors.Is(err, ErrBatchMismatch) {
		t.Errorf("got %v, want ErrBatchMismatch", err)
	}
}

func TestDecodeURLs_RejectsDuplicateIndex(t *testing.T) {
	uris := buildMultiFixture(t, 3, 5)
	// Replace index 2 with another copy of index 0 → duplicate.
	uris[2] = uris[0]
	_, err := DecodeURLs(uris)
	if !errors.Is(err, ErrBatchIncomplete) {
		t.Errorf("got %v, want ErrBatchIncomplete", err)
	}
}

func TestDecodeURLs_SingleQRWorks(t *testing.T) {
	uri := buildFixture(t)
	got, err := DecodeURLs([]string{uri})
	if err != nil {
		t.Fatalf("DecodeURLs: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 account, got %d", len(got))
	}
}

func TestDecodeURLs_EmptyInput(t *testing.T) {
	_, err := DecodeURLs(nil)
	if !errors.Is(err, ErrEmptyInput) {
		t.Errorf("got %v, want ErrEmptyInput", err)
	}
}

func TestOTPAuthURL_HOTPCarriesCounter(t *testing.T) {
	a := Account{Name: "bob", SecretB32: "JBSWY3DPEHPK3PXP", Algorithm: "SHA1", Digits: 6, Type: "hotp", Counter: 7}
	got := a.OTPAuthURL()
	if !strings.Contains(got, "otpauth://hotp/") {
		t.Errorf("wrong scheme path: %q", got)
	}
	if !strings.Contains(got, "counter=7") {
		t.Errorf("missing counter: %q", got)
	}
	if strings.Contains(got, "period=") {
		t.Errorf("HOTP must not carry period: %q", got)
	}
}
