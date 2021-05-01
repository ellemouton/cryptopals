package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/ellemouton/cryptopals/set1"
	"github.com/ellemouton/cryptopals/set2"
	"github.com/ellemouton/cryptopals/set3"
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	// First part copied from ch7 to get the plaintxt

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

	pt, err := set1.DecryptAESECB([]byte("YELLOW SUBMARINE"), ciphertxt)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt the plaintxt with CTR under a random key
	key := set2.GenAESKey()
	ct, err := set3.CTR(key, pt, 0)
	if err != nil {
		log.Fatal(err)
	}

	var pt2 = make([]byte, 0, len(ct))
	for i := 0; i < len(ct); i++ {
		pt2 = append(pt2, []byte("A")[0])
	}

	ct2, err := edit(ct, key, 0, 0, pt2)
	if err != nil {
		log.Fatal(err)
	}

	temp, err := set1.FixedXOR(ct, ct2)
	if err != nil {
		log.Fatal(err)
	}

	pt, err = set1.FixedXOR(temp, pt2)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(pt))
}

func edit(ct, key []byte, nonce int64, offset int, newtxt []byte) ([]byte, error) {
	pt, err := set3.CTR(key, ct, nonce)
	if err != nil {
		return nil, err
	}

	copy(pt[offset:len(newtxt)], newtxt)

	return set3.CTR(key, pt, nonce)
}
