//go:build ignore
// +build ignore

// Standalone helper that builds the demo migration payload with two FAKE
// accounts (issuer "Acme", "Demo") and writes:
//
//	examples/demo-qr.png  — QR image readable by `otp-migrate qr`
//	examples/demo.url     — the raw otpauth-migration:// URI as text
//
// Run with:  go run ./examples/gen_demo_qr.go
//
// The secrets here are publicly known constants — do NOT use for real accounts.
package main

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/mshegolev/otp-migration-tool/internal/migration/pb"
	"google.golang.org/protobuf/proto"
	"image/png"
)

func mustB32Decode(s string) []byte {
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	payload := &pb.MigrationPayload{
		Version:    1,
		BatchSize:  1,
		BatchIndex: 0,
		BatchId:    0,
		OtpParameters: []*pb.OtpParameters{
			{
				// RFC 6238 reference secret: "12345678901234567890" → JBSWY3DPEHPK3PXP test vector "12345678901234567890" → GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
				Secret:    mustB32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
				Name:      "alice@example.com",
				Issuer:    "Acme",
				Algorithm: pb.Algorithm_ALGORITHM_SHA1,
				Digits:    pb.DigitCount_DIGIT_COUNT_SIX,
				Type:      pb.OtpType_OTP_TYPE_TOTP,
			},
			{
				Secret:    mustB32Decode("JBSWY3DPEHPK3PXP"),
				Name:      "demo-bot",
				Issuer:    "Demo",
				Algorithm: pb.Algorithm_ALGORITHM_SHA1,
				Digits:    pb.DigitCount_DIGIT_COUNT_SIX,
				Type:      pb.OtpType_OTP_TYPE_TOTP,
			},
		},
	}

	raw, err := proto.Marshal(payload)
	if err != nil {
		panic(err)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	uri := "otpauth-migration://offline?data=" + url.QueryEscape(encoded)

	if err := os.WriteFile("examples/demo.url", []byte(uri+"\n"), 0o644); err != nil {
		panic(err)
	}

	writer := qrcode.NewQRCodeWriter()
	bm, err := writer.Encode(uri, gozxing.BarcodeFormat_QR_CODE, 384, 384, nil)
	if err != nil {
		panic(err)
	}
	f, err := os.Create("examples/demo-qr.png")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := png.Encode(f, bm); err != nil {
		panic(err)
	}
	fmt.Println("wrote examples/demo-qr.png and examples/demo.url")
}
