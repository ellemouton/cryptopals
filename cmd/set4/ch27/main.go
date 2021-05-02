package main

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/ellemouton/cryptopals/set1"
	"github.com/ellemouton/cryptopals/set2"
)

var (
	key                    []byte
	errIsNotAsciiCompliant = errors.New("is not ascii compliant")
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	key = set2.GenAESKey()

	k, err := extractKey()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("key cracked?", string(key) == string(k))
}

func extractKey() ([]byte, error) {
	// How long is og ct?
	ct, err := encrypt("blah")
	if err != nil {
		return nil, err
	}

	// We want at least 3 blocks of 16 bytes each
	if len(ct) < 16*3 {
		return nil, errors.New("Need longer input")
	}

	// Alter the ct so that instead of [ct1, ct2, ct3, ...] we have instead
	// [ct1, 0, ct1, ...]
	copy(ct[16:32], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	copy(ct[32:48], ct[:16])

	_, pt, err := decryptAndCheckASCIICompliance(ct)
	if !errors.Is(err, errIsNotAsciiCompliant) && err != nil {
		return nil, err
	}

	if !errors.Is(err, errIsNotAsciiCompliant) {
		return nil, errors.New("ascii was compliant")
	}

	// Assuming that we get pt from the non compliance error above
	return set1.FixedXOR([]byte(pt)[:16], []byte(pt)[32:48])
}

func encrypt(input string) ([]byte, error) {
	if strings.ContainsAny(input, ";=") {
		return nil, errors.New("input cant contain special chars ';' or '='")
	}

	input = "comment1=cooking%20MCs;userdata=" + input + ";comment2=%20like%20a%20pound%20of%20bacon"

	padded := set2.PKCS7Pad([]byte(input), 16)

	return set2.CBCEncrypt(padded, key, key)
}

func decryptAndCheckASCIICompliance(ct []byte) (bool, string, error) {
	pt, err := set2.CBCDecrypt(ct, key, key)
	if err != nil {
		return false, "", err
	}

	for i := 0; i < len(pt); i++ {
		if pt[i] > 127 {
			return false, string(pt), errIsNotAsciiCompliant
		}
	}

	return true, string(pt), nil
}
