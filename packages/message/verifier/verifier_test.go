package verifier

import (
	"crypto/sha512"
	"errors"
	"testing"

	"github.com/atitan/activesupport-go/message/codec"
	"github.com/google/go-cmp/cmp"
)

func TestVerifyModernSimpleString(t *testing.T) {
	sealed := `InNpZ25lZCBtZXNzYWdlIg==--bb1982469b6d7871d3a34f6175d116df41074d761f56add58d708dc880b5d2e573b331f2fdefa8bb33fbc5a2a2e9ef3c9fa726bb21a699fd299a145b4200250f`
	msgCodec := codec.New(false, false) // Setting does not matter when verifying
	macHashFunc := sha512.New
	macSecret := "1234567"
	opt := codec.MetadataOption{}

	originalData := "signed message"
	var data string

	v := New(msgCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); err != nil {
		t.Errorf("verify: %v", err)
		return
	}
	if originalData != data {
		t.Errorf("data mismatch: %q, %q", originalData, data)
	}
}

func TestVerifyModernSimpleStringURLSafe(t *testing.T) {
	sealed := `Ij4_PiI--a8846546a64f279997782e13cc1c9c8d482b41a677cad7725f723ada1a8b3b54889543d56ad6c66c12db8b8ca9117d570103a73d35e83f12ed3275de1db7b4d4`
	msgCodec := codec.New(false, false) // Setting does not matter when verifying
	macHashFunc := sha512.New
	macSecret := "1234567"
	opt := codec.MetadataOption{}

	originalData := ">?>"
	var data string

	v := New(msgCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); err != nil {
		t.Errorf("verify: %v", err)
		return
	}
	if originalData != data {
		t.Errorf("data mismatch: %q, %q", originalData, data)
	}
}

func TestVerifyModernSimpleEnvelope(t *testing.T) {
	sealed := `eyJfcmFpbHMiOnsiZGF0YSI6InNpZ25lZCBtZXNzYWdlIiwicHVyIjoiZm9yIHRlc3RpbmcifX0=--eeca8406245a2e882f192535516432dd0d65c0376ac09a680528c32971ef6cbda5a276775782b3c0e0d9a97f1022c060c4b5e7c1d055b98d61d93487ff8d23d8`
	msgCodec := codec.New(false, false) // Setting does not matter when verifying
	macHashFunc := sha512.New
	macSecret := "1234567"
	opt := codec.MetadataOption{Purpose: "for testing"}

	originalData := "signed message"
	var data string

	v := New(msgCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); err != nil {
		t.Errorf("verify: %v", err)
		return
	}
	if originalData != data {
		t.Errorf("data mismatch: %q, %q", originalData, data)
	}
}

func TestVerifyModernComplexEnvelope(t *testing.T) {
	sealed := `eyJfcmFpbHMiOnsiZGF0YSI6eyJhYiI6MTIzLCJjZCI6InllbGxvdyIsImVmIjp0cnVlLCJnaCI6bnVsbH0sInB1ciI6ImZvciB0ZXN0aW5nIn19--c43a9c6628e7d4b1139c01686ea41dc45484e38edd48a890915a696b0442ffd821a8819080b50a87bc9100f90fc1f855f89e6661e3373f7b3243707e89ce996a`
	msgCodec := codec.New(false, false) // Setting does not matter when verifying
	macHashFunc := sha512.New
	macSecret := "1234567"
	opt := codec.MetadataOption{Purpose: "for testing"}

	type Sample struct {
		Ab int
		Cd string
		Ef bool
		Gh *int
	}

	originalData := Sample{Ab: 123, Cd: "yellow", Ef: true, Gh: nil}
	var data Sample

	v := New(msgCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); err != nil {
		t.Errorf("verify: %v", err)
		return
	}
	if diff := cmp.Diff(originalData, data); diff != "" {
		t.Errorf("data mismatch (-want +got):\n%s", diff)
	}
}

func TestVerifyLegacySimpleEnvelope(t *testing.T) {
	sealed := `eyJfcmFpbHMiOnsibWVzc2FnZSI6IkluTnBaMjVsWkNCdFpYTnpZV2RsSWc9PSIsImV4cCI6bnVsbCwicHVyIjoiZm9yIHRlc3RpbmcifX0=--17e5f7d0cae6c5c00545a375d2d69dfd15fc4210486cadb9662c96f9c162c96bbb75ff68558322aff0440a574cfa722aac1496aeca7973d4376d90ce87b6366b`
	msgCodec := codec.New(false, false) // Setting does not matter when verifying
	macHashFunc := sha512.New
	macSecret := "1234567"
	opt := codec.MetadataOption{Purpose: "for testing"}

	originalData := "signed message"
	var data string

	v := New(msgCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); err != nil {
		t.Errorf("verify: %v", err)
		return
	}
	if originalData != data {
		t.Errorf("data mismatch: %q, %q", originalData, data)
	}
}

func TestVerifyLegacyComplexEnvelope(t *testing.T) {
	sealed := `eyJfcmFpbHMiOnsibWVzc2FnZSI6ImV5SmhZaUk2TVRJekxDSmpaQ0k2SW5sbGJHeHZkeUlzSW1WbUlqcDBjblZsTENKbmFDSTZiblZzYkgwPSIsImV4cCI6bnVsbCwicHVyIjoiZm9yIHRlc3RpbmcifX0=--2de168678c94508dc6ddaa943163ddf2ecb55d96b85a73fa94b9c55e9dcdce1d40dded6c379b301900ba0c0537cc8af792478ce9490ea62d6a868e56ede39632`
	msgCodec := codec.New(false, false) // Setting does not matter when verifying
	macHashFunc := sha512.New
	macSecret := "1234567"
	opt := codec.MetadataOption{Purpose: "for testing"}

	type Sample struct {
		Ab int
		Cd string
		Ef bool
		Gh *int
	}

	originalData := Sample{Ab: 123, Cd: "yellow", Ef: true, Gh: nil}
	var data Sample

	v := New(msgCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); err != nil {
		t.Errorf("verify: %v", err)
		return
	}
	if diff := cmp.Diff(originalData, data); diff != "" {
		t.Errorf("data mismatch (-want +got):\n%s", diff)
	}
}

func TestVerifyMismatchPurpose(t *testing.T) {
	sealed := `eyJfcmFpbHMiOnsiZGF0YSI6InNpZ25lZCBtZXNzYWdlIiwicHVyIjoiYWFhYSJ9fQ==--14d8c833366b43fe353ea93489953e71310568364356eaae6ee55efb59dd486f87219b08e4516f50a7896d414bd2226139b7ed3103ab09527ca2551e5578744c`
	msgCodec := codec.New(false, false) // Setting does not matter when verifying
	macHashFunc := sha512.New
	macSecret := "1234567"
	opt := codec.MetadataOption{Purpose: "for testing"}

	var data string

	v := New(msgCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); !errors.Is(err, codec.MismatchedPurposeError) {
		t.Errorf("unexpected err: %v", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	sealed := `eyJfcmFpbHMiOnsiZGF0YSI6InNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyNS0wMS0yNVQxMTo1MToyMi41OTRaIn19--b97886fba07ab97615d6f5cad67612e99bedcd180f175cce947833f5e1579e6fd2147c2f97b54505ece7d4fa42e5314e3936cd6ef7aa102f8432561a2d1e4f44`
	msgCodec := codec.New(false, false) // Setting does not matter when verifying
	macHashFunc := sha512.New
	macSecret := "1234567"
	opt := codec.MetadataOption{}

	var data string

	v := New(msgCodec, macHashFunc, macSecret)

	if err := v.Verify(sealed, &data, opt); !errors.Is(err, codec.ExpiredError) {
		t.Errorf("unexpected err: %v", err)
	}
}
