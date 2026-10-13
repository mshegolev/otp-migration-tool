// Package qr decodes a single QR code from a PNG/JPEG file into its text payload.
// It uses a pure-Go decoder so the binary has no system dependencies.
package qr

import (
	"fmt"
	"image"
	"os"

	// Register JPEG and PNG decoders with image.Decode (side-effect imports).
	_ "image/jpeg"
	_ "image/png"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// DecodeFile opens an image at path and returns the text encoded in its QR code.
func DecodeFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open image: %w", err)
	}
	defer f.Close()

	img, _, err := image.Decode(f)
	if err != nil {
		return "", fmt.Errorf("decode image: %w", err)
	}
	return Decode(img)
}

// Decode reads the QR payload from an already-decoded image.
func Decode(img image.Image) (string, error) {
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("bitmap: %w", err)
	}
	result, err := qrcode.NewQRCodeReader().Decode(bmp, nil)
	// Screenshots may have a dark outer frame and too little quiet zone for
	// detection. Retry the pure QR reader with progressively trimmed edges.
	if err != nil {
		hints := map[gozxing.DecodeHintType]interface{}{gozxing.DecodeHintType_PURE_BARCODE: true}
		bounds := img.Bounds()
		limit := bounds.Dx() / 10
		if bounds.Dy()/10 < limit {
			limit = bounds.Dy() / 10
		}
		for inset := 0; inset <= limit; inset++ {
			cropped, cropErr := bmp.Crop(inset, inset, bounds.Dx()-2*inset, bounds.Dy()-2*inset)
			if cropErr != nil {
				break
			}
			fallback, decodeErr := qrcode.NewQRCodeReader().Decode(cropped, hints)
			if decodeErr == nil {
				return fallback.GetText(), nil
			}
		}
	}
	if err != nil {
		return "", fmt.Errorf("decode QR: %w", err)
	}
	return result.GetText(), nil
}
