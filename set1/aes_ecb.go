package set1

import "crypto/aes"

func DecryptAESECB(key, ciphertxt []byte) ([]byte, error) {
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	b := make([]byte, len(ciphertxt))
	size := cipher.BlockSize()

	for i := 0; i < len(ciphertxt); i += size {
		cipher.Decrypt(b[i:i+size], ciphertxt[i:i+size])
	}

	return b, nil
}