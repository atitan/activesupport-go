package codec

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	urlEncoding = base64.URLEncoding.WithPadding(base64.NoPadding)
	stdEncoding = base64.StdEncoding.WithPadding(base64.StdPadding)

	ExpiredError           = errors.New("codec: data expired")
	MismatchedPurposeError = errors.New("codec: mismatched purpose")
	InvalidMetadataError   = errors.New("codec: invalid metadata")
)

type Envelope struct {
	Rails Metadata `json:"_rails"`
}

type Metadata struct {
	Data    json.RawMessage `json:"data,omitempty"`
	Message string          `json:"message,omitempty"`
	Expiry  *time.Time      `json:"exp,omitempty"`
	Purpose string          `json:"pur,omitempty"`
}

type MetadataOption struct {
	ExpiresAt *time.Time
	ExpiresIn *time.Duration
	Purpose   string
}

func (mo MetadataOption) pickExpiry() *time.Time {
	if mo.ExpiresAt != nil {
		return mo.ExpiresAt
	}

	if mo.ExpiresIn != nil {
		t := time.Now().Add(*mo.ExpiresIn)
		return &t
	}

	return nil
}

type Codec struct {
	urlSafe        bool
	legacyMetadata bool
}

func New(urlSafe, legacyMetadata bool) Codec {
	return Codec{
		urlSafe:        urlSafe,
		legacyMetadata: legacyMetadata,
	}
}

func (c Codec) Encode(src []byte) []byte {
	return Encode(src, c.urlSafe)
}

func (c Codec) Decode(src []byte) ([]byte, error) {
	decoded, err := Decode(src, c.urlSafe)
	if err == nil {
		return decoded, nil
	}

	// Decode either url safe or not to support Rails 7.1 => 7.2 transition
	// Referenced rails commit: f643919
	return Decode(src, !c.urlSafe)
}

func (c Codec) SerializeWithMetadata(data any, opt MetadataOption) ([]byte, error) {
	if c.legacyMetadata {
		serialized, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}

		msg := Encode(serialized, false)
		env := Envelope{
			Rails: Metadata{
				Message: string(msg),
				Expiry:  opt.pickExpiry(),
				Purpose: opt.Purpose,
			},
		}

		return json.Marshal(env)
	} else {
		serialized, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}

		env := Envelope{
			Rails: Metadata{
				Data:    serialized,
				Expiry:  opt.pickExpiry(),
				Purpose: opt.Purpose,
			},
		}

		return json.Marshal(env)
	}
}

func (c Codec) DeserializeWithMetadata(data []byte, v any, opt MetadataOption) error {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		// The data is not an envelope, try unmarshal it directly
		if err := json.Unmarshal(data, v); err != nil {
			return fmt.Errorf("unmarshal directly: %w", err)
		}

		return nil
	}

	meta := env.Rails

	if meta.Expiry != nil && time.Now().After(*meta.Expiry) {
		return ExpiredError
	}

	if meta.Purpose != opt.Purpose {
		return MismatchedPurposeError
	}

	// Legacy metadata
	if meta.Message != "" {
		serialized, err := Decode([]byte(meta.Message), false)
		if err != nil {
			return InvalidMetadataError
		}

		if err := json.Unmarshal(serialized, v); err != nil {
			return fmt.Errorf("unmarshal legacy metadata: %w", err)
		}

		return nil
	}

	// Modern metadata
	if meta.Data != nil {
		if err := json.Unmarshal(meta.Data, v); err != nil {
			return fmt.Errorf("unmarshal modern metadata: %w", err)
		}

		return nil
	}

	return InvalidMetadataError
}

func Encode(src []byte, urlSafe bool) []byte {
	var enc *base64.Encoding
	if urlSafe {
		enc = urlEncoding
	} else {
		enc = stdEncoding
	}

	dst := make([]byte, enc.EncodedLen(len(src)))
	enc.Encode(dst, src)

	return dst
}

func Decode(src []byte, urlSafe bool) ([]byte, error) {
	var enc *base64.Encoding
	if urlSafe {
		enc = urlEncoding
	} else {
		enc = stdEncoding
	}

	dst := make([]byte, enc.DecodedLen(len(src)))
	n, err := enc.Decode(dst, src)
	if err != nil {
		return nil, err
	}

	dst = dst[:n]
	return dst, err
}
