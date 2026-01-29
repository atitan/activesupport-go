package encryptor

import (
	"crypto/sha256"
	"os"
	"testing"

	"github.com/atitan/activesupport-go/message/codec"
)

func TestDecryptCBC128(t *testing.T) {
	ciphertext, err := os.ReadFile("testdata/TestDecryptCBC128.txt")
	if err != nil {
		t.Error(err)
		return
	}

	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{}

	originalData := "encrypted message"
	var data string

	e := New(msgCodec, false, []byte("1234567890123456"), sha256.New, nil)

	if err := e.Decrypt(ciphertext, &data, opt); err != nil {
		t.Error(err)
		return
	}
	if originalData != data {
		t.Errorf("data mismatch: %q, %q", originalData, data)
	}
}

func TestDecryptCBC192(t *testing.T) {
	ciphertext, err := os.ReadFile("testdata/TestDecryptCBC192.txt")
	if err != nil {
		t.Error(err)
		return
	}

	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{}

	originalData := "encrypted message"
	var data string

	e := New(msgCodec, false, []byte("123456789012345678901234"), sha256.New, nil)

	if err := e.Decrypt(ciphertext, &data, opt); err != nil {
		t.Error(err)
		return
	}
	if originalData != data {
		t.Errorf("data mismatch: %q, %q", originalData, data)
	}
}

func TestDecryptCBC256(t *testing.T) {
	ciphertext, err := os.ReadFile("testdata/TestDecryptCBC256.txt")
	if err != nil {
		t.Error(err)
		return
	}

	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{}

	originalData := "encrypted message"
	var data string

	e := New(msgCodec, false, []byte("12345678901234567890123456789012"), sha256.New, nil)

	if err := e.Decrypt(ciphertext, &data, opt); err != nil {
		t.Error(err)
		return
	}
	if originalData != data {
		t.Errorf("data mismatch: %q, %q", originalData, data)
	}
}

func TestDecryptCBC256CustomHMAC(t *testing.T) {
	ciphertext, err := os.ReadFile("testdata/TestDecryptCBC256CustomHMAC.txt")
	if err != nil {
		t.Error(err)
		return
	}

	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{}

	originalData := "encrypted message"
	var data string

	e := New(msgCodec, false, []byte("12345678901234567890123456789012"), sha256.New, []byte("abcdefg"))

	if err := e.Decrypt(ciphertext, &data, opt); err != nil {
		t.Error(err)
		return
	}
	if originalData != data {
		t.Errorf("data mismatch: %q, %q", originalData, data)
	}
}

func TestDecryptGCM128(t *testing.T) {
	ciphertext, err := os.ReadFile("testdata/TestDecryptGCM128.txt")
	if err != nil {
		t.Error(err)
		return
	}

	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{}

	originalData := "encrypted message"
	var data string

	e := New(msgCodec, true, []byte("1234567890123456"), nil, nil)

	if err := e.Decrypt(ciphertext, &data, opt); err != nil {
		t.Error(err)
		return
	}
	if originalData != data {
		t.Errorf("data mismatch: %q, %q", originalData, data)
	}
}

func TestDecryptGCM192(t *testing.T) {
	ciphertext, err := os.ReadFile("testdata/TestDecryptGCM192.txt")
	if err != nil {
		t.Error(err)
		return
	}

	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{}

	originalData := "encrypted message"
	var data string

	e := New(msgCodec, true, []byte("123456789012345678901234"), nil, nil)

	if err := e.Decrypt(ciphertext, &data, opt); err != nil {
		t.Error(err)
		return
	}
	if originalData != data {
		t.Errorf("data mismatch: %q, %q", originalData, data)
	}
}

func TestDecryptGCM256(t *testing.T) {
	ciphertext, err := os.ReadFile("testdata/TestDecryptGCM256.txt")
	if err != nil {
		t.Error(err)
		return
	}

	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{}

	originalData := "encrypted message"
	var data string

	e := New(msgCodec, true, []byte("12345678901234567890123456789012"), nil, nil)

	if err := e.Decrypt(ciphertext, &data, opt); err != nil {
		t.Error(err)
		return
	}
	if originalData != data {
		t.Errorf("data mismatch: %q, %q", originalData, data)
	}
}
