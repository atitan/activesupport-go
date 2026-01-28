package verifier

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"hash"

	"github.com/atitan/activesupport-go/message/codec"
)

var (
	separator             = []byte("--")
	InvalidSignatureError = errors.New("verifier: invalid signature")
)

type Verifier struct {
	msgCodec    codec.Codec
	macHashFunc func() hash.Hash
	macSecret   []byte
}

func New(msgCodec codec.Codec, macHashFunc func() hash.Hash, macSecret string) *Verifier {
	if macHashFunc == nil {
		panic("verifier: empty hash func")
	}
	if macSecret == "" {
		panic("verifier: empty secret")
	}

	return &Verifier{
		msgCodec:    msgCodec,
		macHashFunc: macHashFunc,
		macSecret:   []byte(macSecret),
	}
}

func (v *Verifier) Verify(sealed []byte, data any, opt codec.MetadataOption) error {
	encoded, err := v.VerifyAndExtractMAC(sealed)
	if err != nil {
		return err
	}

	serialized, err := v.msgCodec.Decode(encoded)
	if err != nil {
		return err
	}

	return v.msgCodec.DeserializeWithMetadata(serialized, data, opt)
}

func (v *Verifier) Generate(data any, opt codec.MetadataOption) ([]byte, error) {
	serialized, err := v.msgCodec.SerializeWithMetadata(data, opt)
	if err != nil {
		return nil, err
	}

	encoded := v.msgCodec.Encode(serialized)
	sealed := v.GenerateAndAppendMAC(encoded)

	return sealed, nil
}

func (v *Verifier) GenerateMAC(encoded []byte) []byte {
	mac := hmac.New(v.macHashFunc, v.macSecret)
	mac.Write(encoded)

	return mac.Sum(nil)
}

func (v *Verifier) GenerateAndAppendMAC(encoded []byte) []byte {
	mac := v.GenerateMAC(encoded)

	return hex.AppendEncode(append(encoded, separator...), mac)
}

func (v *Verifier) VerifyAndExtractMAC(sealed []byte) ([]byte, error) {
	encoded, hexMAC, found := bytes.Cut(sealed, separator)
	if !found {
		return nil, InvalidSignatureError
	}

	unverifiedMAC := make([]byte, hex.DecodedLen(len(hexMAC)))
	n, err := hex.Decode(unverifiedMAC, hexMAC)
	if err != nil {
		return nil, InvalidSignatureError
	}
	unverifiedMAC = unverifiedMAC[:n]

	computedMAC := v.GenerateMAC(encoded)
	if !hmac.Equal(unverifiedMAC, computedMAC) {
		return nil, InvalidSignatureError
	}

	return encoded, nil
}
