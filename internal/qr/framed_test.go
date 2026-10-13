package qr

import (
	"image"
	"image/color"
	"image/draw"
	"strings"
	"testing"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

func TestDecodeDarkFrame(t *testing.T) {
	// Synthetic payload only: no account data or secrets.
	payload := "otpauth-migration://offline?data=" + strings.Repeat("Ab9+/xyZ0123456789", 7)
	matrix, err := qrcode.NewQRCodeWriter().Encode(payload, gozxing.BarcodeFormat_QR_CODE, 490, 490,
		map[gozxing.EncodeHintType]interface{}{gozxing.EncodeHintType_MARGIN: 0})
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewGray(image.Rect(0, 0, 518, 518))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.Gray{Y: 20}), image.Point{}, draw.Src)
	for y := 0; y < matrix.GetHeight(); y++ {
		for x := 0; x < matrix.GetWidth(); x++ {
			c := color.Gray{Y: 255}
			if matrix.Get(x, y) {
				c.Y = 0
			}
			img.SetGray(x+14, y+14, c)
		}
	}
	got, err := Decode(img)
	if err != nil {
		t.Fatalf("Decode framed QR: %v", err)
	}
	if got != payload {
		t.Fatalf("decoded payload differs from synthetic input")
	}
}

func TestDecodeBlank(t *testing.T) {
	img := image.NewGray(image.Rect(0, 0, 100, 100))
	draw.Draw(img, img.Bounds(), image.White, image.Point{}, draw.Src)
	if _, err := Decode(img); err == nil {
		t.Fatal("expected error for blank image")
	}
}
