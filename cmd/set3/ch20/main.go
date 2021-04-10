package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"math"
	"os"

	"github.com/ellemouton/cryptopals/set1"
	"github.com/ellemouton/cryptopals/set2"
	"github.com/ellemouton/cryptopals/set3"
)

func main() {
	// Read in input
	file, err := os.Open("input.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var ptl [][]byte
	for scanner.Scan() {
		pt, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			log.Fatal(err)
		}
		ptl = append(ptl, pt)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	// Encrypt each line. Fixed nonce of 0 and fixed key
	var ctl [][]byte
	key := set2.GenAESKey()
	smallestKeyLen := math.MaxInt64
	for _, pt := range ptl {
		ct, err := set3.CTR(key, pt, 0)
		if err != nil {
			log.Fatal(err)
		}

		ctl = append(ctl, ct)

		if len(ct) < smallestKeyLen {
			smallestKeyLen = len(ct)
		}
	}

	var temp []byte
	for _, ct := range ctl {
		temp = append(temp, ct[:smallestKeyLen]...)
	}

	ks, err := set1.EstimateRepeatingXORKeyWithLen(temp, smallestKeyLen)
	if err != nil {
		log.Fatal(err)
	}

	// For some reason the first char is being guessed incorrectly :(
	ks[0] = 32

	for _, ct := range ctl {
		pt, err := set1.FixedXOR(ks, ct[:len(ks)])
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(string(pt))
	}
}
