package encryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"hash"
	"io"

	"github.com/atitan/activesupport-go/message/codec"
	"github.com/atitan/activesupport-go/message/verifier"
)

const GCMTagSize = 16

var (
	separator             = []byte("--")
	InvalidSignatureError = errors.New("Encryptor: invalid signature")
)

type Encryptor struct {
	msgCodec      codec.Codec
	encAEADCipher bool
	encBlock      cipher.Block
	macVerifier   *verifier.Verifier
}

func New(msgCodec codec.Codec, encAEADCipher bool, encSecret []byte, macHashFunc func() hash.Hash, macSecret []byte) *Encryptor {
	encBlock, err := aes.NewCipher(encSecret)
	if err != nil {
		panic("encryptor: invalid length of encryption secret")
	}

	var macVerifier *verifier.Verifier
	if !encAEADCipher {
		if macHashFunc == nil {
			panic("encryptor: empty hash func")
		}

		if macSecret == nil {
			macSecret = encSecret
		}

		macVerifier = verifier.New(msgCodec, macHashFunc, macSecret)
	}

	return &Encryptor{
		msgCodec:      msgCodec,
		encAEADCipher: encAEADCipher,
		encBlock:      encBlock,
		macVerifier:   macVerifier,
	}
}

func (e *Encryptor) Encrypt(data any, opt codec.MetadataOption) ([]byte, error) {
	serialized, err := e.msgCodec.SerializeWithMetadata(data, opt)
	if err != nil {
		return nil, err
	}

	encryptionParts := make([][]byte, 0, 3)

	if e.encAEADCipher {
		aesgcm, err := cipher.NewGCMWithTagSize(e.encBlock, GCMTagSize)
		if err != nil {
			return nil, err
		}

		nonce := make([]byte, aesgcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}

		sealed := aesgcm.Seal(nil, nonce, serialized, nil)
		ciphertext, authTag := sealed[:len(sealed)-GCMTagSize], sealed[len(sealed)-GCMTagSize:]

		encryptionParts = append(
			encryptionParts,
			ciphertext,
			nonce,
			authTag,
		)
	} else {
		iv := make([]byte, e.encBlock.BlockSize())
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}

		serialized = AddPKCS7Padding(serialized, e.encBlock.BlockSize())
		ciphertext := make([]byte, len(serialized))

		aescbc := cipher.NewCBCEncrypter(e.encBlock, iv)
		aescbc.CryptBlocks(ciphertext, serialized)

		encryptionParts = append(
			encryptionParts,
			ciphertext,
			iv,
		)
	}

	for i := range encryptionParts {
		encryptionParts[i] = e.msgCodec.Encode(encryptionParts[i])
	}

	encrypted := bytes.Join(encryptionParts, separator)

	if !e.encAEADCipher {
		encrypted = e.macVerifier.EncodeAndAppendMAC(encrypted)
	}

	return encrypted, nil
}
