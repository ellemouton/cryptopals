package set3

import (
	"encoding/binary"

	"github.com/ellemouton/cryptopals/set1"
)

func CTR(key, plaintxt []byte, nonce int64) ([]byte, error) {
	ksProvider := keystreamProvider(key, nonce)

	var ct []byte

	for {
		if len(plaintxt) == 0 {
			break
		}

		ks, err := ksProvider()
		if err != nil {
			return nil, err
		}

		var res []byte

		if len(plaintxt) < len(ks) {
			res, err = set1.FixedXOR(plaintxt, ks[:len(plaintxt)])
			plaintxt = plaintxt[len(plaintxt):]
		} else {
			res, err = set1.FixedXOR(plaintxt[:16], ks)
			plaintxt = plaintxt[16:]
		}
		if err != nil {
			return nil, err
		}

		ct = append(ct, res...)
	}

	return ct, nil
}

func keystreamProvider(key []byte, nonce int64) func() ([]byte, error) {
	n := make([]byte, 16)
	binary.LittleEndian.PutUint16(n, uint16(nonce))

	var blockCount uint16

	return func() ([]byte, error) {
		bc := make([]byte, 16)
		binary.LittleEndian.PutUint16(bc, blockCount)
		blockCount++
		input := append(n[:8], bc[:8]...)
		return set1.EncryptAESECB(key, input)
	}
}
