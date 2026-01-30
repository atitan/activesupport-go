package keygenerator

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestGenerateKey16(t *testing.T) {
	password := []byte("4aa19bef10a27fd29e09058b10e8c279cd0b3ecc7791ee527d8d02de71b1861bd259c3d03da8b89059eb8f2e0453aebdc17659e9eaf1aeefc8858c5a0b051bbf")
	k := New(password, 1000, sha256.New)

	out := k.GenerateKey([]byte("this is a salt"), 16)
	expected := []byte{71, 181, 67, 190, 212, 199, 249, 78, 109, 170, 64, 46, 89, 172, 166, 67}
	if !bytes.Equal(out, expected) {
		t.Errorf("data mismatch: %q, %q", out, expected)
	}
}

func TestGenerateKey32(t *testing.T) {
	password := []byte("4aa19bef10a27fd29e09058b10e8c279cd0b3ecc7791ee527d8d02de71b1861bd259c3d03da8b89059eb8f2e0453aebdc17659e9eaf1aeefc8858c5a0b051bbf")
	k := New(password, 1000, sha256.New)

	out := k.GenerateKey([]byte("this is a salt"), 32)
	expected := []byte{71, 181, 67, 190, 212, 199, 249, 78, 109, 170, 64, 46, 89, 172, 166, 67, 185, 156, 60, 112, 215, 71, 58, 63, 31, 129, 152, 92, 84, 69, 208, 77}
	if !bytes.Equal(out, expected) {
		t.Errorf("data mismatch: %q, %q", out, expected)
	}
}
