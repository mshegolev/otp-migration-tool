package main

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/mshegolev/otp-migration-tool/internal/migration/pb"
	"google.golang.org/protobuf/proto"
)

// multiAccountURI builds an otpauth-migration:// URI with two TOTP accounts
// (Acme:alice and Globex:bob), so tests can exercise the --issuer / --name
// filter path that real users hit when they export many accounts at once.
func multiAccountURI(t *testing.T) string {
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
			{
				Secret:    secret,
				Name:      "bob",
				Issuer:    "Globex",
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

var sixDigitsLine = regexp.MustCompile(`^[0-9]{6}\n$`)

func TestCode_FiltersByIssuer(t *testing.T) {
	uri := multiAccountURI(t)
	var stdout, stderr bytes.Buffer
	if err := run([]string{"code", uri, "--issuer", "Globex"}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v (stderr=%s)", err, stderr.String())
	}
	if !sixDigitsLine.MatchString(stdout.String()) {
		t.Errorf("stdout %q does not match a single 6-digit line", stdout.String())
	}
}

func TestCode_FailsOnAmbiguousFilter(t *testing.T) {
	uri := multiAccountURI(t)
	var stdout, stderr bytes.Buffer
	err := run([]string{"code", uri}, &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected error for ambiguous match, got stdout=%q", stdout.String())
	}
	if !strings.Contains(err.Error(), "multiple TOTP accounts") {
		t.Errorf("error %q does not mention ambiguity", err.Error())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout should be empty on error, got %q", stdout.String())
	}
}

func TestCode_FailsWhenFilterMatchesNothing(t *testing.T) {
	uri := multiAccountURI(t)
	var stdout, stderr bytes.Buffer
	err := run([]string{"code", uri, "--issuer", "DoesNotExist"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when no account matches the filter")
	}
	if !strings.Contains(err.Error(), "no TOTP accounts match") {
		t.Errorf("error %q does not name the no-match condition", err.Error())
	}
}

func TestCode_FilterIsCaseInsensitive(t *testing.T) {
	uri := multiAccountURI(t)
	var stdout, stderr bytes.Buffer
	if err := run([]string{"code", uri, "--issuer", "globex", "--name", "BOB"}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v (stderr=%s)", err, stderr.String())
	}
	if !sixDigitsLine.MatchString(stdout.String()) {
		t.Errorf("stdout %q does not match a single 6-digit line", stdout.String())
	}
}
