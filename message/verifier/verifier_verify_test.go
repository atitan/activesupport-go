package verifier

import (
	"crypto/sha256"
	"errors"
	"os"
	"testing"

	"github.com/atitan/activesupport-go/message/codec"
	"github.com/google/go-cmp/cmp"
)

type Complex struct {
	Ab int    `json:"ab"`
	Cd string `json:"cd"`
	Ef bool   `json:"ef"`
	Gh *int   `json:"gh"`
}

var (
	// Codec setting does not matter when verifying
	msgVerifyCodec = codec.New(false, false)
	macHashFunc    = sha256.New
	macSecret      = []byte("12345678")
)

func TestVerifyModernSimpleString(t *testing.T) {
	sealed, err := os.ReadFile("testdata/TestVerifyModernSimpleString.txt")
	if err != nil {
		t.Error(err)
		return
	}

	opt := codec.MetadataOption{}
	originalData := "signed message"
	var data string

	v := New(msgVerifyCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); err != nil {
		t.Errorf("verify: %v", err)
		return
	}
	if originalData != data {
		t.Errorf("data mismatch: %q, %q", originalData, data)
	}
}

func TestVerifyModernSimpleStringURLSafe(t *testing.T) {
	sealed, err := os.ReadFile("testdata/TestVerifyModernSimpleStringURLSafe.txt")
	if err != nil {
		t.Error(err)
		return
	}

	opt := codec.MetadataOption{}
	originalData := ">?>"
	var data string

	v := New(msgVerifyCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); err != nil {
		t.Errorf("verify: %v", err)
		return
	}
	if originalData != data {
		t.Errorf("data mismatch: %q, %q", originalData, data)
	}
}

func TestVerifyModernSimpleEnvelope(t *testing.T) {
	sealed, err := os.ReadFile("testdata/TestVerifyModernSimpleEnvelope.txt")
	if err != nil {
		t.Error(err)
		return
	}

	opt := codec.MetadataOption{Purpose: "pizza"}
	originalData := "signed message"
	var data string

	v := New(msgVerifyCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); err != nil {
		t.Errorf("verify: %v", err)
		return
	}
	if originalData != data {
		t.Errorf("data mismatch: %q, %q", originalData, data)
	}
}

func TestVerifyModernComplexEnvelope(t *testing.T) {
	sealed, err := os.ReadFile("testdata/TestVerifyModernComplexEnvelope.txt")
	if err != nil {
		t.Error(err)
		return
	}

	opt := codec.MetadataOption{Purpose: "pizza"}
	originalData := Complex{Ab: 123, Cd: "yellow", Ef: true, Gh: nil}
	var data Complex

	v := New(msgVerifyCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); err != nil {
		t.Errorf("verify: %v", err)
		return
	}
	if diff := cmp.Diff(originalData, data); diff != "" {
		t.Errorf("data mismatch (-want +got):\n%s", diff)
	}
}

func TestVerifyModernComplexEnvelopeURLSafe(t *testing.T) {
	sealed, err := os.ReadFile("testdata/TestVerifyModernComplexEnvelopeURLSafe.txt")
	if err != nil {
		t.Error(err)
		return
	}

	opt := codec.MetadataOption{Purpose: "pizza"}
	originalData := Complex{Ab: 123, Cd: "yellow", Ef: true, Gh: nil}
	var data Complex

	v := New(msgVerifyCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); err != nil {
		t.Errorf("verify: %v", err)
		return
	}
	if diff := cmp.Diff(originalData, data); diff != "" {
		t.Errorf("data mismatch (-want +got):\n%s", diff)
	}
}

func TestVerifyLegacySimpleEnvelope(t *testing.T) {
	sealed, err := os.ReadFile("testdata/TestVerifyLegacySimpleEnvelope.txt")
	if err != nil {
		t.Error(err)
		return
	}

	opt := codec.MetadataOption{Purpose: "pizza"}
	originalData := "signed message"
	var data string

	v := New(msgVerifyCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); err != nil {
		t.Errorf("verify: %v", err)
		return
	}
	if originalData != data {
		t.Errorf("data mismatch: %q, %q", originalData, data)
	}
}

func TestVerifyLegacyComplexEnvelope(t *testing.T) {
	sealed, err := os.ReadFile("testdata/TestVerifyLegacyComplexEnvelope.txt")
	if err != nil {
		t.Error(err)
		return
	}

	opt := codec.MetadataOption{Purpose: "pizza"}
	originalData := Complex{Ab: 123, Cd: "yellow", Ef: true, Gh: nil}
	var data Complex

	v := New(msgVerifyCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); err != nil {
		t.Errorf("verify: %v", err)
		return
	}
	if diff := cmp.Diff(originalData, data); diff != "" {
		t.Errorf("data mismatch (-want +got):\n%s", diff)
	}
}

func TestVerifyLegacyComplexEnvelopeURLSafe(t *testing.T) {
	sealed, err := os.ReadFile("testdata/TestVerifyLegacyComplexEnvelopeURLSafe.txt")
	if err != nil {
		t.Error(err)
		return
	}

	opt := codec.MetadataOption{Purpose: "pizza"}
	originalData := Complex{Ab: 123, Cd: "yellow", Ef: true, Gh: nil}
	var data Complex

	v := New(msgVerifyCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); err != nil {
		t.Errorf("verify: %v", err)
		return
	}
	if diff := cmp.Diff(originalData, data); diff != "" {
		t.Errorf("data mismatch (-want +got):\n%s", diff)
	}
}

func TestVerifyMismatchPurpose(t *testing.T) {
	sealed, err := os.ReadFile("testdata/TestVerifyMismatchPurpose.txt")
	if err != nil {
		t.Error(err)
		return
	}

	opt := codec.MetadataOption{Purpose: "pizza"}
	var data string

	v := New(msgVerifyCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); !errors.Is(err, codec.MismatchedPurposeError) {
		t.Errorf("unexpected err: %v", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	sealed, err := os.ReadFile("testdata/TestVerifyExpired.txt")
	if err != nil {
		t.Error(err)
		return
	}

	opt := codec.MetadataOption{}
	var data string

	v := New(msgVerifyCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); !errors.Is(err, codec.ExpiredError) {
		t.Errorf("unexpected err: %v", err)
	}
}
