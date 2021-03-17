package set1

import (
	"encoding/base64"
	"encoding/hex"
)

func HexToBase64(hexStr string) (string, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}
