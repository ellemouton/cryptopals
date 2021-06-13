package set4

import (
	"time"

	"github.com/ellemouton/cryptopals/set1"
	"github.com/ellemouton/cryptopals/set4/sha1"
)

func HMACSHA1(key, msg []byte) ([]byte, error) {
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

	t3 := sha1.Sum(append(t1[:], msg...))
	t4 := sha1.Sum(append(t2[:], t3[:]...))

	return t4[:], nil
}

func InsecureCompare(a, b []byte, delay time.Duration) bool {
	if len(a) != len(b) {
		return false
	}

	for i, v := range a {
		if v != b[i] {
			return false
		}

		time.Sleep(delay)
	}

	return true
}
