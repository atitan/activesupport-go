package encryptor

import (
	"bytes"
	"testing"
)

func TestAddPKCS7Padding(t *testing.T) {
	unpadded := []byte{100, 100, 100}
	expected := []byte{100, 100, 100, 5, 5, 5, 5, 5}

	padded := AddPKCS7Padding(unpadded, 8)

	if !bytes.Equal(padded, expected) {
		t.Errorf("not equal: %v, %v", padded, expected)
	}
}

func TestAddPKCS7PaddingEmpty(t *testing.T) {
	unpadded := []byte{}
	expected := []byte{8, 8, 8, 8, 8, 8, 8, 8}

	padded := AddPKCS7Padding(unpadded, 8)

	if !bytes.Equal(padded, expected) {
		t.Errorf("not equal: %v, %v", padded, expected)
	}
}

func TestAddPKCS7PaddingFull(t *testing.T) {
	unpadded := []byte{100, 100, 100, 100, 100, 100, 100, 100}
	expected := []byte{100, 100, 100, 100, 100, 100, 100, 100, 8, 8, 8, 8, 8, 8, 8, 8}

	padded := AddPKCS7Padding(unpadded, 8)

	if !bytes.Equal(padded, expected) {
		t.Errorf("not equal: %v, %v", padded, expected)
	}
}

func TestRemovePKCS7Padding(t *testing.T) {
	padded := []byte{100, 100, 100, 5, 5, 5, 5, 5}
	expected := []byte{100, 100, 100}

	unpadded := RemovePKCS7Padding(padded)

	if !bytes.Equal(unpadded, expected) {
		t.Errorf("not equal: %v, %v", unpadded, expected)
	}
}

func TestRemovePKCS7PaddingEmpty(t *testing.T) {
	padded := []byte{}
	expected := []byte{}

	unpadded := RemovePKCS7Padding(padded)

	if !bytes.Equal(unpadded, expected) {
		t.Errorf("not equal: %v, %v", unpadded, expected)
	}
}

func TestRemovePKCS7PaddingFull(t *testing.T) {
	padded := []byte{100, 100, 100, 100, 100, 100, 100, 100, 8, 8, 8, 8, 8, 8, 8, 8}
	expected := []byte{100, 100, 100, 100, 100, 100, 100, 100}

	unpadded := RemovePKCS7Padding(padded)

	if !bytes.Equal(unpadded, expected) {
		t.Errorf("not equal: %v, %v", unpadded, expected)
	}
}
