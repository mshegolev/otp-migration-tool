package qr

import (
	"strings"
	"testing"
)

// TestDecodeFile decodes the demo QR shipped in examples/.
// The QR encodes an otpauth-migration:// URI; we just check the scheme prefix.
func TestDecodeFile(t *testing.T) {
	got, err := DecodeFile("../../examples/demo-qr.png")
	if err != nil {
		t.Fatalf("DecodeFile: %v", err)
	}
	if !strings.HasPrefix(got, "otpauth-migration://") {
		t.Errorf("decoded text does not look like a migration URI: %q", got)
	}
}

func TestDecodeFile_Missing(t *testing.T) {
	if _, err := DecodeFile("nope-does-not-exist.png"); err == nil {
		t.Error("expected error for missing file")
	}
}
