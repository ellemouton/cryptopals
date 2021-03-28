package set2

import "github.com/ellemouton/cryptopals/set1"

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
