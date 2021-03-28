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

func EncryptAESECB(key, plaintxt []byte) ([]byte, error) {
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	b := make([]byte, len(plaintxt))
	size := cipher.BlockSize()

	for i := 0; i < len(plaintxt); i += size {
		cipher.Encrypt(b[i:i+size], plaintxt[i:i+size])
	}

	return b, nil
}

func IsAESECBEncrypted(ciphertxt []byte, keylen int) bool {
	m := make(map[string]int)

	for i := 0; i < len(ciphertxt); i += keylen {
		m[string(ciphertxt[i:i+keylen])]++
	}

	return len(m) < len(ciphertxt)/keylen
}
