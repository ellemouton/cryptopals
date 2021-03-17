package set1

import (
	"encoding/hex"
	"errors"
)

func FixedXOR(a []byte, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("byte arrays are of different lengths")
	}

	out := make([]byte, len(a))

	for i := 0; i < len(out); i++ {
		out[i] = a[i] ^ b[i]
	}

	return out, nil

}

func HexStrFixedXOR(a string, b string) (string, error) {
	aBytes, err := hex.DecodeString(a)
	if err != nil {
		return "", err
	}

	bBytes, err := hex.DecodeString(b)
	if err != nil {
		return "", err
	}

	outBytes, err := FixedXOR(aBytes, bBytes)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(outBytes), nil
}
