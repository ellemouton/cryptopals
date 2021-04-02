package set2

import (
	"encoding/base64"
	"log"
	"math"
	"math/rand"

	"github.com/ellemouton/cryptopals/set1"
)

func ECBDecryptionSimple() ([]byte, error) {
	ct, err := EncryptWithUnknownStr(nil)
	if err != nil {
		return nil, err
	}

	myIn := easyInput(len(ct))
	var plain []byte

	for b := 0; b < len(ct); b++ {
		myIn = myIn[1:]
		res, err := EncryptWithUnknownStr(myIn)
		if err != nil {
			return nil, err
		}

		chunk := res[0:len(ct)]

		for i := 0; i < 256; i++ {
			temp := append(myIn, plain...)
			temp = append(temp, byte(i))
			c, err := EncryptWithUnknownStr(temp)
			if err != nil {
				return nil, err
			}

			ed, err := set1.EditDistance(chunk, c[0:len(ct)])
			if err != nil {
				return nil, err
			}

			if ed == 0 {
				plain = append(plain, byte(i))
				break
			}
		}
	}

	return plain, nil
}

func DetermineEBCKeySize() (int, error) {
	// Determine key size being used
	var keySize int
	for ks := 1; ks <= 100; ks++ {
		plainTxt := easyInput(ks * 2)

		res, err := EncryptWithUnknownStr(plainTxt)
		if err != nil {
			return 0, err
		}

		ed, err := set1.EditDistance(res[0:ks], res[ks:ks*2])
		if err != nil {
			return 0, err
		}

		if ed == 0 {
			keySize = ks
			break
		}
	}

	return keySize, nil
}

func easyInput(size int) []byte {
	var res []byte
	for i := 0; i < size; i++ {
		res = append(res, []byte("A")...)
	}

	return res
}

// AES-128-ECB(attacker-controlled || target-bytes, random-key)
func EncryptWithUnknownStr(input []byte) ([]byte, error) {
	unknownStr := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
		"YnkK"

	unknown, err := base64.StdEncoding.DecodeString(unknownStr)
	if err != nil {
		log.Fatal(err)
	}

	input = append(input, unknown...)
	return EncryptECBFixedKey(input)
}

// AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
func EncryptWithUnknownStrAndPrefix(input []byte) ([]byte, error) {
	unknownStr := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
		"YnkK"

	unknown, err := base64.StdEncoding.DecodeString(unknownStr)
	if err != nil {
		log.Fatal(err)
	}

	res := GetRandomPrefix()
	res = append(res, input...)
	res = append(res, unknown...)
	return EncryptECBFixedKey(res)
}

var (
	fixedKey   []byte
	randomPref []byte
)

func GetRandomPrefix() []byte {
	if randomPref != nil {
		return randomPref
	}

	prefLen := rand.Intn(40)
	randomPref = make([]byte, prefLen)
	rand.Read(randomPref)

	return randomPref
}

func EncryptECBFixedKey(input []byte) ([]byte, error) {
	if fixedKey == nil {
		fixedKey = GenAESKey()
	}

	padded := PKCS7Pad(input, len(fixedKey))
	return set1.EncryptAESECB(fixedKey, padded)
}

func DecryptECBFixedKey(input []byte) ([]byte, error) {
	return set1.DecryptAESECB(fixedKey, input)
}

func ECBDecryptionHard() ([]byte, error) {
	ks := 16

	threeIn := easyInput(ks * 3)

	ct1, err := EncryptWithUnknownStrAndPrefix(threeIn)
	if err != nil {
		return nil, err
	}

	ctPattern := make([]byte, 16)
	m := make(map[string]int)
	for i := 0; i < len(ct1); i += ks {
		m[string(ct1[i:i+16])]++
		if m[string(ct1[i:i+16])] == 2 {
			copy(ctPattern, ct1[i:i+16])
			break
		}
	}

	// Find length of the random bytes

	count := 0
	pos := 0
	for {
		input := easyInput(ks + count)
		ct, err := EncryptWithUnknownStrAndPrefix(input)
		if err != nil {
			return nil, err
		}

		pos = findFirstPosition(ctPattern, ct)
		if pos != -1 {
			break
		}

		count++
	}

	randomPrefLen := pos - count

	ct, err := EncryptWithUnknownStrAndPrefix(nil)
	if err != nil {
		return nil, err
	}

	unknownTxtLen := 16 * int(math.Ceil(float64(len(ct)-randomPrefLen)/float64(16)))
	myIn := easyInput(unknownTxtLen + count)
	var plain []byte

	for b := 0; b < len(ct)-randomPrefLen; b++ {
		myIn = myIn[1:]
		res, err := EncryptWithUnknownStrAndPrefix(myIn)
		if err != nil {
			return nil, err
		}

		chunk := res[pos : pos+unknownTxtLen]

		for i := 0; i < 256; i++ {
			temp := append(myIn, plain...)
			temp = append(temp, byte(i))
			c, err := EncryptWithUnknownStrAndPrefix(temp)
			if err != nil {
				return nil, err
			}

			ed, err := set1.EditDistance(chunk, c[pos:pos+unknownTxtLen])
			if err != nil {
				return nil, err
			}

			if ed == 0 {
				plain = append(plain, byte(i))
				break
			}
		}
	}

	return plain, nil
}

func findFirstPosition(data, space []byte) int {
	if len(data) > len(space) {
		return -1
	}

	span := len(data)

	for i := 0; i < len(space)-span; i++ {
		if string(data) == string(space[i:i+span]) {
			return i
		}
	}

	return -1
}
