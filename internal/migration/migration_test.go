package migration

import (
	"encoding/base32"
	"encoding/base64"
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
