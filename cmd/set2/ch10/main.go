package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/ellemouton/cryptopals/set1"
	"github.com/ellemouton/cryptopals/set2"
)

func main() {
	file, err := os.Open("input.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var text string
	for scanner.Scan() {
		text += scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	ciphertxt, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		log.Fatal(err)
	}

	key := []byte("YELLOW SUBMARINE")

	res, err := set2.CBCDecrypt(ciphertxt, key, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		log.Fatal(err)
	}

	redo, err := set2.CBCEncrypt(res, key, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		log.Fatal(err)
	}

	res, err = CBFDecrypt(redo, key, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(res))
}

func CBFDecrypt(ciphertxt, key, iv []byte) ([]byte, error) {
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

func CBFEncrypt(plaintxt, key, iv []byte) ([]byte, error) {
	paddedPlaintxt := set2.PKCS7Pad(plaintxt, len(key))
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
