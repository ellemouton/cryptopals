package set1

import (
	"errors"
)

func RepeatingKeyEncrypt(input, key []byte) ([]byte, error) {
	if len(key) > len(input) {
		return nil, errors.New("key is larger than input. Handle this")
	}

	keySeq := []byte{}
	for len(keySeq) < len(input) {
		keySeq = append(keySeq, key...)
	}

	keySeq = keySeq[:len(input)]

	return FixedXOR(input, keySeq)
}
