package set2

import (
	"encoding/base64"
	"log"

	"github.com/ellemouton/cryptopals/set1"
)

var unknownStr = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
	"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
	"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
	"YnkK"

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
			log.Fatal(err)
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

func EncryptWithUnknownStr(input []byte) ([]byte, error) {
	unknown, err := base64.StdEncoding.DecodeString(unknownStr)
	if err != nil {
		log.Fatal(err)
	}

	input = append(input, unknown...)
	return EncryptECBFixedKey(input)
}

var fixedKey []byte

func EncryptECBFixedKey(input []byte) ([]byte, error) {
	if fixedKey == nil {
		fixedKey = GenAESKey()
	}

	padded := PKCS7Pad(input, len(fixedKey))
	return set1.EncryptAESECB(fixedKey, padded)
}
