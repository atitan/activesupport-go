package keygenerator

import (
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

type KeyGenerator struct {
	password  []byte
	iteration int
	hmacFunc  func() hash.Hash
}

func New(password []byte, iteration int, hmacFunc func() hash.Hash) *KeyGenerator {
	if password == nil {
		panic("keygenerator: empty password")
	}

	if iteration < 1 {
		panic("keygenerator: invalid iteration")
	}

	if hmacFunc == nil {
		panic("keygenerator: empty hmacFunc")
	}

	return &KeyGenerator{
		password:  password,
		iteration: iteration,
		hmacFunc:  hmacFunc,
	}
}

func (k *KeyGenerator) GenerateKey(salt []byte, keyLen int) []byte {
	return pbkdf2.Key(k.password, salt, k.iteration, keyLen, k.hmacFunc)
}
