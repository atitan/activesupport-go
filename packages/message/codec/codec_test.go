package codec

import (
	"testing"
)

func TestEncode(t *testing.T) {
	stdEncoding := map[string]string{
		"1":       "MQ==",
		"12":      "MTI=",
		"123":     "MTIz",
		"1234":    "MTIzNA==",
		"12345":   "MTIzNDU=",
		"123456":  "MTIzNDU2",
		"1234567": "MTIzNDU2Nw==",
		"ÿÿÿ":     "w7/Dv8O/",
		">?>":     "Pj8+",
	}

	for src, dst := range stdEncoding {
		out := string(Encode([]byte(src), false))
		if out != dst {
			t.Errorf("input: %s; want %s; got: %s", src, dst, out)
		}
	}

	urlEncoding := map[string]string{
		"1":       "MQ",
		"12":      "MTI",
		"123":     "MTIz",
		"1234":    "MTIzNA",
		"12345":   "MTIzNDU",
		"123456":  "MTIzNDU2",
		"1234567": "MTIzNDU2Nw",
		"ÿÿÿ":     "w7_Dv8O_",
		">?>":     "Pj8-",
	}

	for src, dst := range urlEncoding {
		out := string(Encode([]byte(src), true))
		if out != dst {
			t.Errorf("input: %s; want %s; got: %s", src, dst, out)
		}
	}
}
