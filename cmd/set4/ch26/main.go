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
	"github.com/ellemouton/cryptopals/set3"
)

var (
	key []byte
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	key = set2.GenAESKey()

	err := bitFlipAttack()
	if err != nil {
		log.Fatal(err)
	}
}

func bitFlipAttack() error {
	ct, err := encrypt("")
	if err != nil {
		return err
	}

	admin, pt, err := decryptAndCheckAdmin(ct)
	if err != nil {
		return err
	}

	fmt.Println("Does origional ciphertxt contain ';admin=true;'?", admin)
	fmt.Println(pt)

	// Can determine Key stream for a section of the text
	wanted := []byte(";admin=true;")

	// 1. Figure out where in the text we have control:
	ct1, err := encrypt("A")
	if err != nil {
		return err
	}

	ct2, err := encrypt("B")
	if err != nil {
		return err
	}

	diff, err := set1.FixedXOR(ct1, ct2)
	if err != nil {
		return err
	}

	offset := 0
	for i := 0; i < len(diff); i++ {
		if diff[i] != 0 {
			offset = i
			break
		}
	}

	// 2. Get keystream for that section
	input := []byte{}
	for i := 0; i < len(wanted); i++ {
		input = append(input, []byte("A")[0])
	}

	ct, err = encrypt(string(input))
	if err != nil {
		return err
	}

	ks, err := set1.FixedXOR(ct[offset:offset+len(wanted)], input)
	if err != nil {
		return err
	}

	// Now go get and inject the replacement ct
	replacementCT, err := set1.FixedXOR(ks, wanted)
	if err != nil {
		return err
	}

	copy(ct[offset:offset+len(wanted)], replacementCT[:])

	admin, pt, err = decryptAndCheckAdmin(ct)
	if err != nil {
		return err
	}

	fmt.Println("Does altered ciphertxt contain ';admin=true;'?", admin)
	fmt.Println(pt)

	return nil
}

func encrypt(input string) ([]byte, error) {
	if strings.ContainsAny(input, ";=") {
		return nil, errors.New("input cant contain special chars ';' or '='")
	}

	input = "comment1=cooking%20MCs;userdata=" + input + ";comment2=%20like%20a%20pound%20of%20bacon"

	return set3.CTR(key, []byte(input), 0)
}

func decryptAndCheckAdmin(ct []byte) (bool, string, error) {
	pt, err := set3.CTR(key, ct, 0)
	if err != nil {
		return false, "", err
	}

	return strings.Contains(string(pt), ";admin=true;"), string(pt), nil
}
