package encryptor

import (
	"crypto/sha256"
	"os"
	"testing"

	"github.com/atitan/activesupport-go/message/codec"
)

func TestEncryptCBC128(t *testing.T) {
	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{}

	originalData := "encrypted message"

	e := New(msgCodec, false, []byte("1234567890123456"), sha256.New, nil)

	ciphertext, err := e.Encrypt(originalData, opt)
	if err != nil {
		t.Error(err)
		return
	}

	if err := os.WriteFile("testdata/TestEncryptCBC128.txt", ciphertext, 0644); err != nil {
		t.Error(err)
		return
	}
}

func TestEncryptCBC192(t *testing.T) {
	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{}

	originalData := "encrypted message"

	e := New(msgCodec, false, []byte("123456789012345678901234"), sha256.New, nil)

	ciphertext, err := e.Encrypt(originalData, opt)
	if err != nil {
		t.Error(err)
		return
	}

	if err := os.WriteFile("testdata/TestEncryptCBC192.txt", ciphertext, 0644); err != nil {
		t.Error(err)
		return
	}
}

func TestEncryptCBC256(t *testing.T) {
	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{}

	originalData := "encrypted message"

	e := New(msgCodec, false, []byte("12345678901234567890123456789012"), sha256.New, nil)

	ciphertext, err := e.Encrypt(originalData, opt)
	if err != nil {
		t.Error(err)
		return
	}

	if err := os.WriteFile("testdata/TestEncryptCBC256.txt", ciphertext, 0644); err != nil {
		t.Error(err)
		return
	}
}

func TestEncryptCBC256CustomHMAC(t *testing.T) {
	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{}

	originalData := "encrypted message"

	e := New(msgCodec, false, []byte("12345678901234567890123456789012"), sha256.New, []byte("abcdefg"))

	ciphertext, err := e.Encrypt(originalData, opt)
	if err != nil {
		t.Error(err)
		return
	}

	if err := os.WriteFile("testdata/TestEncryptCBC256CustomHMAC.txt", ciphertext, 0644); err != nil {
		t.Error(err)
		return
	}
}

func TestEncryptGCM128(t *testing.T) {
	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{}

	originalData := "encrypted message"

	e := New(msgCodec, true, []byte("1234567890123456"), nil, nil)

	ciphertext, err := e.Encrypt(originalData, opt)
	if err != nil {
		t.Error(err)
		return
	}

	if err := os.WriteFile("testdata/TestEncryptGCM128.txt", ciphertext, 0644); err != nil {
		t.Error(err)
		return
	}
}

func TestEncryptGCM192(t *testing.T) {
	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{}

	originalData := "encrypted message"

	e := New(msgCodec, true, []byte("123456789012345678901234"), nil, nil)

	ciphertext, err := e.Encrypt(originalData, opt)
	if err != nil {
		t.Error(err)
		return
	}

	if err := os.WriteFile("testdata/TestEncryptGCM192.txt", ciphertext, 0644); err != nil {
		t.Error(err)
		return
	}
}

func TestEncryptGCM256(t *testing.T) {
	msgCodec := codec.New(false, false)
	opt := codec.MetadataOption{}

	originalData := "encrypted message"

	e := New(msgCodec, true, []byte("12345678901234567890123456789012"), nil, nil)

	ciphertext, err := e.Encrypt(originalData, opt)
	if err != nil {
		t.Error(err)
		return
	}

	if err := os.WriteFile("testdata/TestEncryptGCM256.txt", ciphertext, 0644); err != nil {
		t.Error(err)
		return
	}
}
