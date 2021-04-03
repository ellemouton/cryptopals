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
	key []byte
	iv  []byte
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	// The assumption is that the IV is publically known and the key is not.
	iv = set2.GenAESKey()
	key = set2.GenAESKey()

	err := bitFlipAttack()
	if err != nil {
		log.Fatal(err)
	}
}

func bitFlipAttack() error {
	ct, err := encrypt("test")
	if err != nil {
		return err
	}

	admin, pt, err := decryptAndCheckAdmin(ct)
	if err != nil {
		return err
	}

	fmt.Println("Does origional ciphertxt contain ';admin=true;'?", admin)

	fmt.Println(pt)

	x := make([]byte, 16)
	xp := make([]byte, 16)
	z := make([]byte, 16)

	copy(z, pt[16:32])
	copy(x, ct[0:16])

	zp := []byte(";admin=true;aaaa")

	xp, err = set1.FixedXOR(z, zp)
	if err != nil {
		return err
	}

	xp, err = set1.FixedXOR(xp, x)
	if err != nil {
		return err
	}

	copy(ct[0:16], xp[:])

	admin, pt, err = decryptAndCheckAdmin(ct)
	if err != nil {
		return err
	}
	fmt.Println(pt)
	fmt.Println("Does altered ciphertxt contain ';admin=true;'?", admin)

	return nil
}

func encrypt(input string) ([]byte, error) {
	if strings.ContainsAny(input, ";=") {
		return nil, errors.New("input cant contain special chars ';' or '='")
	}

	input = "comment1=cooking%20MCs;userdata=" + input + ";comment2=%20like%20a%20pound%20of%20bacon"

	padded := set2.PKCS7Pad([]byte(input), 16)

	return set2.CBCEncrypt(padded, key, iv)
}

func decryptAndCheckAdmin(ct []byte) (bool, string, error) {
	pt, err := set2.CBCDecrypt(ct, key, iv)
	if err != nil {
		return false, "", err
	}

	return strings.Contains(string(pt), ";admin=true;"), string(pt), nil
}
