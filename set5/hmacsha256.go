package set5

import (
	"crypto/sha1"
	"crypto/sha256"

	"github.com/ellemouton/cryptopals/set1"
)

func HMACSHA256(key, msg []byte) ([]byte, error) {
	blockSize := 64

	if len(key) > blockSize {
		hash := sha1.Sum(key)
		key = hash[:]
	}

	for len(key) < blockSize {
		key = append(key, 0x0)
	}

	var (
		opad []byte
		ipad []byte
	)

	for i := 0; i < blockSize; i++ {
		opad = append(opad, 0x5c)
		ipad = append(ipad, 0x36)
	}

	t1, err := set1.FixedXOR(key, ipad)
	if err != nil {
		return nil, err
	}

	t2, err := set1.FixedXOR(key, opad)
	if err != nil {
		return nil, err
	}

	t3 := sha256.Sum256(append(t1[:], msg...))
	t4 := sha256.Sum256(append(t2[:], t3[:]...))

	return t4[:], nil
}
