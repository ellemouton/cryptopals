package main

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/ellemouton/cryptopals/set2"
)

var texts = []string{
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
}

var (
	key []byte
	iv  []byte
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	ct, err := pickAndEncrypt()
	if err != nil {
		log.Fatal(err)
	}

	res, err := PaddingOracle(ct, iv)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Res: \t\t\t", string(res))
}

func PaddingOracle(ct, iv []byte) ([]byte, error) {
	if len(ct)%16 != 0 {
		return nil, errors.New("cipher text len must be multiple of 16")
	}

	res := []byte{}
	prevCT := iv
	for i := 0; i < len(ct); i += 16 {
		pt, err := PaddingOracleSingle(prevCT, ct[i:i+16])
		if err != nil {
			return nil, err
		}

		res = append(res, pt...)
		prevCT = ct[i : i+16]
	}

	return res, nil
}

func PaddingOracleSingle(prevCT, ct []byte) ([]byte, error) {
	pt := make([]byte, len(ct))
	prevCp := make([]byte, len(prevCT))

	for index := 15; index >= 0; index-- {
		num := 16 - index

		for x := 15; x > index; x-- {
			prevCp[x] = pt[x] ^ prevCT[x] ^ byte(num)
		}

		for i := 0; i < 256; i++ {
			prevCp[index] = byte(i)
			ok, err := decryptAndCheck(ct, prevCp)
			if err != nil {
				return nil, err
			}

			if !ok {
				continue
			}

			// We assume that the last byte of the pt is now <num>h
			// plaintxt = <num> ^ prevCT[index] ^ prevCP[index]
			pt[index] = byte(num) ^ prevCT[index] ^ prevCp[index]
			break
		}
	}

	return pt, nil
}

func pickAndEncrypt() ([]byte, error) {
	pt := []byte(texts[rand.Intn(len(texts))])

	fmt.Println("chosen plain txt:\t", string(pt))

	iv = set2.GenAESKey()
	key = set2.GenAESKey()

	return set2.CBCEncrypt(pt, key, iv)
}

func decryptAndCheck(ct, iv []byte) (bool, error) {
	pt, err := set2.CBCDecrypt(ct, key, iv)
	if err != nil {
		return false, err
	}

	valid, _ := set2.ValidateAndStripPKCS7Pad(pt)
	if !valid {
		return false, nil
	}

	return true, nil
}
