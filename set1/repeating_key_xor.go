package set1

import (
	"errors"
	"math"
)

func DecryptRepeatingXORCypher(cyphertext []byte) ([]byte, []byte, error) {
	key, err := EstimateRepeatingXORKey(cyphertext)
	if err != nil {
		return nil, nil, err
	}

	res, err := RepeatingKeyEncrypt(cyphertext, key)
	if err != nil {
		return nil, nil, err
	}

	return res, key, nil
}

func EstimateRepeatingXORKey(cyphertext []byte) ([]byte, error) {
	bestKeySize, err := EstimateKeySize(cyphertext)
	if err != nil {
		return nil, err
	}

	blocks := make([][]byte, bestKeySize)

	for i := 0; i < len(cyphertext); i++ {
		index := i % bestKeySize
		if len(blocks[index]) == 0 {
			blocks[index] = []byte{}
		}
		blocks[index] = append(blocks[index], cyphertext[i])
	}

	var key []byte

	for i := 0; i < len(blocks); i++ {
		b, _, err := FindSingleByteXOR(blocks[i])
		if err != nil {
			return nil, err
		}

		key = append(key, *b)
	}

	return key, nil
}

func EstimateKeySize(cyphertext []byte) (int, error) {
	var bestKeySize int
	smallestED := math.MaxFloat64

	for ks := 2; ks <= 40; ks++ {
		var score float64
		numChunks := 4

		for i := 0; i < numChunks-1; i++ {
			for j := i + 1; j < numChunks; j++ {
				ed, err := NormalizedEditDistance(cyphertext[i*ks:(i*ks)+ks], cyphertext[j*ks:(j*ks)+ks])
				if err != nil {
					return 0, err
				}

				score += ed
			}
		}

		if score < smallestED {
			smallestED = score
			bestKeySize = ks
		}
	}

	return bestKeySize, nil
}

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

func EditDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, errors.New("lengths must match")
	}

	c, err := FixedXOR(a, b)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, by := range c {
		bitCount, err := countBits(int(by))
		if err != nil {
			return 0, err
		}
		count += bitCount
	}

	return count, nil
}

func NormalizedEditDistance(a, b []byte) (float64, error) {
	ed, err := EditDistance(a, b)
	if err != nil {
		return 0, err
	}

	return float64(ed) / float64(len(a)), nil
}

func countBits(num int) (int, error) {
	if num >= 1<<8 {
		return 0, errors.New("number must fit into 1 byte")
	}

	count := 0
	for i := 0; i < 8; i++ {
		if ((1 << i) & num) != 0 {
			count++
		}
	}

	return count, nil
}
