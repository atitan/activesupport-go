package verifier

import (
	"os"
	"testing"
	"time"

	"github.com/atitan/activesupport-go/message/codec"
)

func TestGenerateModernSimpleString(t *testing.T) {
	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{}

	data := "signed message"

	v := New(msgCodec, macHashFunc, macSecret)

	sealed, err := v.Generate(data, opt)
	if err != nil {
		t.Errorf("generate: %v", err)
		return
	}

	if err := os.WriteFile("testdata/TestGenerateModernSimpleString.txt", sealed, 0644); err != nil {
		t.Error(err)
		return
	}
}

func TestGenerateModernSimpleStringURLSafe(t *testing.T) {
	msgCodec := codec.New(true, false)
	opt := codec.MetadataOption{}

	data := ">?>"

	v := New(msgCodec, macHashFunc, macSecret)

	sealed, err := v.Generate(data, opt)
	if err != nil {
		t.Errorf("generate: %v", err)
		return
	}

	if err := os.WriteFile("testdata/TestGenerateModernSimpleStringURLSafe.txt", sealed, 0644); err != nil {
		t.Error(err)
		return
	}
}

func TestGenerateModernSimpleEnvelope(t *testing.T) {
	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{Purpose: "pizza"}

	data := "signed message"

	v := New(msgCodec, macHashFunc, macSecret)

	sealed, err := v.Generate(data, opt)
	if err != nil {
		t.Errorf("generate: %v", err)
		return
	}

	if err := os.WriteFile("testdata/TestGenerateModernSimpleEnvelope.txt", sealed, 0644); err != nil {
		t.Error(err)
		return
	}
}

func TestGenerateModernComplexEnvelope(t *testing.T) {
	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{Purpose: "pizza"}

	data := Complex{Ab: 123, Cd: "yellow", Ef: true, Gh: nil}

	v := New(msgCodec, macHashFunc, macSecret)

	sealed, err := v.Generate(data, opt)
	if err != nil {
		t.Errorf("generate: %v", err)
		return
	}

	if err := os.WriteFile("testdata/TestGenerateModernComplexEnvelope.txt", sealed, 0644); err != nil {
		t.Error(err)
		return
	}
}

func TestGenerateModernComplexEnvelopeURLSafe(t *testing.T) {
	msgCodec := codec.New(true, false)
	opt := codec.MetadataOption{Purpose: "pizza"}

	data := Complex{Ab: 123, Cd: "yellow", Ef: true, Gh: nil}

	v := New(msgCodec, macHashFunc, macSecret)

	sealed, err := v.Generate(data, opt)
	if err != nil {
		t.Errorf("generate: %v", err)
		return
	}

	if err := os.WriteFile("testdata/TestGenerateModernComplexEnvelopeURLSafe.txt", sealed, 0644); err != nil {
		t.Error(err)
		return
	}
}

func TestGenerateLegacySimpleEnvelope(t *testing.T) {
	msgCodec := codec.New(false, true)
	opt := codec.MetadataOption{Purpose: "pizza"}

	data := "signed message"

	v := New(msgCodec, macHashFunc, macSecret)

	sealed, err := v.Generate(data, opt)
	if err != nil {
		t.Errorf("generate: %v", err)
		return
	}

	if err := os.WriteFile("testdata/TestGenerateLegacySimpleEnvelope.txt", sealed, 0644); err != nil {
		t.Error(err)
		return
	}
}

func TestGenerateLegacyComplexEnvelope(t *testing.T) {
	msgCodec := codec.New(false, true)
	opt := codec.MetadataOption{Purpose: "pizza"}

	data := Complex{Ab: 123, Cd: "yellow", Ef: true, Gh: nil}

	v := New(msgCodec, macHashFunc, macSecret)

	sealed, err := v.Generate(data, opt)
	if err != nil {
		t.Errorf("generate: %v", err)
		return
	}

	if err := os.WriteFile("testdata/TestGenerateLegacyComplexEnvelope.txt", sealed, 0644); err != nil {
		t.Error(err)
		return
	}
}

func TestGenerateLegacyComplexEnvelopeURLSafe(t *testing.T) {
	msgCodec := codec.New(true, true)
	opt := codec.MetadataOption{Purpose: "pizza"}

	data := Complex{Ab: 123, Cd: "yellow", Ef: true, Gh: nil}

	v := New(msgCodec, macHashFunc, macSecret)

	sealed, err := v.Generate(data, opt)
	if err != nil {
		t.Errorf("generate: %v", err)
		return
	}

	if err := os.WriteFile("testdata/TestGenerateLegacyComplexEnvelopeURLSafe.txt", sealed, 0644); err != nil {
		t.Error(err)
		return
	}
}

func TestGenerateMismatchPurpose(t *testing.T) {
	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{Purpose: "milk"}

	data := "signed message"

	v := New(msgCodec, macHashFunc, macSecret)

	sealed, err := v.Generate(data, opt)
	if err != nil {
		t.Errorf("generate: %v", err)
		return
	}

	if err := os.WriteFile("testdata/TestGenerateMismatchPurpose.txt", sealed, 0644); err != nil {
		t.Error(err)
		return
	}
}

func TestGenerateExpired(t *testing.T) {
	msgCodec := codec.New(false, false)
	expiry := time.Unix(1767225600, 0)
	opt := codec.MetadataOption{ExpiresAt: &expiry}

	data := "signed message"

	v := New(msgCodec, macHashFunc, macSecret)

	sealed, err := v.Generate(data, opt)
	if err != nil {
		t.Errorf("generate: %v", err)
		return
	}

	if err := os.WriteFile("testdata/TestGenerateExpired.txt", sealed, 0644); err != nil {
		t.Error(err)
		return
	}
}
