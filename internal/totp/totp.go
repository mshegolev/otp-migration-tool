// Package totp generates Time-based One-Time Passwords (RFC 6238) from a
// decoded migration Account.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/mshegolev/otp-migration-tool/internal/migration"
)

const defaultPeriod = 30

// Now returns the current TOTP code for the given account using the standard
// 30-second period.
func Now(a migration.Account) (string, error) {
	return At(a, time.Now())
}

// At returns the TOTP code at the given instant.
func At(a migration.Account, t time.Time) (string, error) {
	counter := uint64(t.Unix() / defaultPeriod)
	return generate(a.Secret, counter, hashFor(a.Algorithm), a.Digits)
}

func hashFor(name string) func() hash.Hash {
	switch strings.ToUpper(name) {
	case "SHA256":
		return sha256.New
	case "SHA512":
		return sha512.New
	case "MD5":
		return md5.New
	default:
		return sha1.New
	}
}

// generate implements HOTP/TOTP per RFC 4226 §5.3.
func generate(secret []byte, counter uint64, alg func() hash.Hash, digits int) (string, error) {
	if len(secret) == 0 {
		return "", fmt.Errorf("empty secret")
	}
	if digits != 6 && digits != 8 {
		return "", fmt.Errorf("unsupported digit count %d (only 6 or 8)", digits)
	}

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(alg, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod), nil
}
