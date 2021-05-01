package set3

import (
	"encoding/binary"

	"github.com/ellemouton/cryptopals/set1"
)

func MT19937StreamCipher(key []byte, pt []byte) ([]byte, error) {
	ksProvider := keyStreamProvider(key)

	var ct []byte

	for {
		if len(pt) == 0 {
			break
		}

		ksNum, err := ksProvider()
		if err != nil {
			return nil, err
		}

		ks := make([]byte, 4)
		binary.LittleEndian.PutUint32(ks, ksNum)

		var res []byte

		if len(pt) < len(ks) {
			res, err = set1.FixedXOR(pt, ks[:len(pt)])
			pt = pt[len(pt):]
		} else {
			res, err = set1.FixedXOR(pt[:4], ks)
			pt = pt[4:]
		}
		if err != nil {
			return nil, err
		}

		ct = append(ct, res...)
	}

	return ct, nil
}

func keyStreamProvider(key []byte) func() (uint32, error) {
	mt := NewMT19937()
	mt.SeedMT(uint32(binary.LittleEndian.Uint16(key)))

	return func() (uint32, error) {
		return mt.ExtractNumber()
	}
}
