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
	separator           = []byte("--")
	InvalidMessageError = errors.New("encryptor: invalid message")
)

type Encryptor struct {
	msgCodec      codec.Codec
	encAEADCipher bool
	encBlock      cipher.Block
	macVerifier   *verifier.Verifier
}

func New(msgCodec codec.Codec, encAEADCipher bool, encSecret []byte, hmacFunc func() hash.Hash, hmacSecret []byte) *Encryptor {
	encBlock, err := aes.NewCipher(encSecret)
	if err != nil {
		panic("encryptor: invalid length of encryption secret")
	}

	var macVerifier *verifier.Verifier
	if !encAEADCipher {
		if hmacFunc == nil {
			panic("encryptor: empty hash func")
		}
		if hmacSecret == nil {
			hmacSecret = encSecret
		}

		macVerifier = verifier.New(msgCodec, hmacFunc, hmacSecret)
	}

	return &Encryptor{
		msgCodec:      msgCodec,
		encAEADCipher: encAEADCipher,
		encBlock:      encBlock,
		macVerifier:   macVerifier,
	}
}

func (e *Encryptor) Decrypt(encrypted []byte, data any, opt codec.MetadataOption) error {
	var err error

	if !e.encAEADCipher {
		encrypted, err = e.macVerifier.VerifyMACAndDecode(encrypted)
		if err != nil {
			return InvalidMessageError
		}
	}

	encryptionParts := bytes.Split(encrypted, separator)

	for i := range encryptionParts {
		encryptionParts[i], err = e.msgCodec.Decode(encryptionParts[i])
		if err != nil {
			return InvalidMessageError
		}
	}

	var serialized []byte

	if e.encAEADCipher {
		if len(encryptionParts) != 3 {
			return InvalidMessageError
		}

		ciphertext, nonce, authTag := encryptionParts[0], encryptionParts[1], encryptionParts[2]

		ciphertext = append(ciphertext, authTag...)

		aesgcm, err := cipher.NewGCMWithTagSize(e.encBlock, GCMTagSize)
		if err != nil {
			return InvalidMessageError
		}

		serialized, err = aesgcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return InvalidMessageError
		}
	} else {
		if len(encryptionParts) != 2 {
			return InvalidMessageError
		}

		ciphertext, iv := encryptionParts[0], encryptionParts[1]

		aescbc := cipher.NewCBCDecrypter(e.encBlock, iv)
		aescbc.CryptBlocks(ciphertext, ciphertext)

		serialized = RemovePKCS7Padding(ciphertext)
	}

	return e.msgCodec.DeserializeWithMetadata(serialized, data, opt)
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

		aescbc := cipher.NewCBCEncrypter(e.encBlock, iv)
		aescbc.CryptBlocks(serialized, serialized)

		encryptionParts = append(
			encryptionParts,
			serialized, // Encrypted
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
