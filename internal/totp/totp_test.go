package totp

import (
	"testing"
	"time"

	"github.com/mshegolev/otp-migration-tool/internal/migration"
)

// RFC 6238 Appendix B reference test vectors.
//
// The shared secret for SHA1 is the ASCII string "12345678901234567890" (20 bytes).
// SHA256 and SHA512 use longer secrets per the RFC; we cover SHA1 here because
// Google Authenticator exports are SHA1-only in practice.
func TestRFC6238_SHA1(t *testing.T) {
	const secret = "12345678901234567890" // 20 bytes ASCII

	tests := []struct {
		unix int64
		want string // 8-digit code per RFC table
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, tc := range tests {
		a := migration.Account{
			Secret:    []byte(secret),
			Algorithm: "SHA1",
			Digits:    8,
			Type:      "totp",
		}
		got, err := At(a, time.Unix(tc.unix, 0))
		if err != nil {
			t.Fatalf("At(%d): %v", tc.unix, err)
		}
		if got != tc.want {
			t.Errorf("At(unix=%d) = %q, want %q", tc.unix, got, tc.want)
		}
	}
}

func TestSixDigits(t *testing.T) {
	a := migration.Account{
		Secret:    []byte("12345678901234567890"),
		Algorithm: "SHA1",
		Digits:    6,
		Type:      "totp",
	}
	got, err := At(a, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	// 6-digit version of the RFC's 94287082 → last six digits
	if got != "287082" {
		t.Errorf("got %q, want %q", got, "287082")
	}
}

func TestRejectsBadDigits(t *testing.T) {
	a := migration.Account{Secret: []byte("k"), Algorithm: "SHA1", Digits: 7}
	if _, err := At(a, time.Now()); err == nil {
		t.Error("expected error for 7 digits")
	}
}

func TestRejectsEmptySecret(t *testing.T) {
	a := migration.Account{Algorithm: "SHA1", Digits: 6}
	if _, err := At(a, time.Now()); err == nil {
		t.Error("expected error for empty secret")
	}
}
