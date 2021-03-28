package set2

import (
	"fmt"
	"math/rand"

	"github.com/ellemouton/cryptopals/set1"
)

func CBCDecrypt(ciphertxt, key, iv []byte) ([]byte, error) {
	plaintxt := make([]byte, len(ciphertxt))
	prev := iv

	for i := 0; i < len(plaintxt); i += len(key) {
		d, err := set1.DecryptAESECB(key, ciphertxt[i:i+len(key)])
		if err != nil {
			return nil, err
		}

		xor, err := set1.FixedXOR(d, prev)
		if err != nil {
			return nil, err
		}

		copy(plaintxt[i:i+len(key)], xor[:])

		prev = ciphertxt[i : i+len(key)]
	}

	return plaintxt, nil
}

func CBCEncrypt(plaintxt, key, iv []byte) ([]byte, error) {
	paddedPlaintxt := PKCS7Pad(plaintxt, len(key))
	ciphertxt := make([]byte, len(paddedPlaintxt))
	prev := iv

	for i := 0; i < len(ciphertxt); i += len(key) {
		xor, err := set1.FixedXOR(paddedPlaintxt[i:i+len(key)], prev)
		if err != nil {
			return nil, err
		}

		d, err := set1.EncryptAESECB(key, xor)
		if err != nil {
			return nil, err
		}

		copy(ciphertxt[i:i+len(key)], d[:])

		prev = ciphertxt[i : i+len(key)]
	}

	return ciphertxt, nil
}

func ModeOracle(input []byte) (string, error) {
	in := PKCS7Pad(input, 16)

	// duplicate the input to at least 3 times the block size
	for len(in) < 16*3 {
		in = append(in, in...)
	}

	ct, err := RandomEncrypt(in)
	if err != nil {
		return "", nil
	}

	if set1.IsAESECBEncrypted(ct, 16) {
		return "ECB", nil
	}

	return "CBC", nil
}

func RandomEncrypt(plaintxt []byte) ([]byte, error) {
	key := GenAESKey()

	before := make([]byte, rand.Intn(11))
	rand.Read(before)
	after := make([]byte, rand.Intn(11))
	rand.Read(after)

	var pt []byte
	pt = append(before, plaintxt...)
	pt = append(pt, after...)

	var (
		res []byte
		err error
	)

	switch rand.Intn(2) {
	case 0:
		fmt.Println("using ECB")
		paddedPlaintxt := PKCS7Pad(plaintxt, len(key))
		res, err = set1.EncryptAESECB(key, paddedPlaintxt)
		if err != nil {
			return nil, err
		}
	default:
		fmt.Println("using CBC")
		iv := GenAESKey()
		res, err = CBCEncrypt(plaintxt, key, iv)
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

func GenAESKey() []byte {
	token := make([]byte, 16)
	rand.Read(token)
	return token
}
