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
	macSeparator          = []byte("--")
	InvalidSignatureError = errors.New("verifier: invalid signature")
)

type Verifier struct {
	msgCodec    codec.Codec
	macHashFunc func() hash.Hash
	macSecret   []byte
}

func New(msgCodec codec.Codec, macHashFunc func() hash.Hash, macSecret string) *Verifier {
	if macSecret == "" {
		panic("verifier: empty secret")
	}

	return &Verifier{
		msgCodec:    msgCodec,
		macHashFunc: macHashFunc,
		macSecret:   []byte(macSecret),
	}
}

func (v *Verifier) Verify(sealed string, data any, opt codec.MetadataOption) error {
	encoded, err := v.verifyAndExtractMAC([]byte(sealed))
	if err != nil {
		return err
	}

	serialized, err := v.msgCodec.Decode(encoded)
	if err != nil {
		return err
	}

	return v.msgCodec.DeserializeWithMetadata(serialized, data, opt)
}

func (v *Verifier) Generate(data any, opt codec.MetadataOption) (string, error) {
	serialized, err := v.msgCodec.SerializeWithMetadata(data, opt)
	if err != nil {
		return "", err
	}

	encoded := v.msgCodec.Encode(serialized)
	sealed := v.generateAndAppendMAC(encoded)

	return string(sealed), nil
}

func (v *Verifier) generateMAC(encoded []byte) []byte {
	mac := hmac.New(v.macHashFunc, v.macSecret)
	mac.Write(encoded)

	return mac.Sum(nil)
}

func (v *Verifier) generateAndAppendMAC(encoded []byte) []byte {
	mac := v.generateMAC(encoded)

	return hex.AppendEncode(append(encoded, macSeparator...), mac)
}

func (v *Verifier) verifyAndExtractMAC(sealed []byte) ([]byte, error) {
	encoded, hexMAC, found := bytes.Cut(sealed, macSeparator)
	if !found {
		return nil, InvalidSignatureError
	}

	unverifiedMAC := make([]byte, hex.DecodedLen(len(hexMAC)))
	n, err := hex.Decode(unverifiedMAC, hexMAC)
	if err != nil {
		return nil, InvalidSignatureError
	}
	unverifiedMAC = unverifiedMAC[:n]

	computedMAC := v.generateMAC(encoded)
	if !hmac.Equal(unverifiedMAC, computedMAC) {
		return nil, InvalidSignatureError
	}

	return encoded, nil
}
