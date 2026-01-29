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

func New(msgCodec codec.Codec, macHashFunc func() hash.Hash, macSecret []byte) *Verifier {
	if macHashFunc == nil {
		panic("verifier: empty hash func")
	}
	if macSecret == nil {
		panic("verifier: empty secret")
	}

	return &Verifier{
		msgCodec:    msgCodec,
		macHashFunc: macHashFunc,
		macSecret:   macSecret,
	}
}

func (v *Verifier) Verify(sealed []byte, data any, opt codec.MetadataOption) error {
	serialized, err := v.VerifyMACAndDecode(sealed)
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

	return v.EncodeAndAppendMAC(serialized), nil
}

func (v *Verifier) CalculateMAC(encoded []byte) []byte {
	mac := hmac.New(v.macHashFunc, v.macSecret)
	mac.Write(encoded)

	return mac.Sum(nil)
}

func (v *Verifier) EncodeAndAppendMAC(serialized []byte) []byte {
	encoded := v.msgCodec.Encode(serialized)
	mac := v.CalculateMAC(encoded)

	return hex.AppendEncode(append(encoded, separator...), mac)
}

func (v *Verifier) VerifyMACAndDecode(sealed []byte) ([]byte, error) {
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

	computedMAC := v.CalculateMAC(encoded)
	if !hmac.Equal(unverifiedMAC, computedMAC) {
		return nil, InvalidSignatureError
	}

	serialized, err := v.msgCodec.Decode(encoded)
	if err != nil {
		return nil, err
	}

	return serialized, nil
}
