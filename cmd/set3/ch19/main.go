package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"os"

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
	for _, pt := range ptl {
		ct, err := set3.CTR(key, pt, 0)
		if err != nil {
			log.Fatal(err)
		}
		//fmt.Println(string(pt))

		ctl = append(ctl, ct)
	}

	ptlRecon := make([][]byte, len(ctl))
	keyGuess := []byte{32, 143, 164, 104, 39, 29, 188, 208, 234, 32, 170, 181,
		189, 209, 40, 186, 6, 241, 118, 31, 119, 193, 57, 5, 121, 236, 123,
		146, 126, 229, 1, 128, 13, 178, 249, 15, 177}
	for i, ct := range ctl {
		ptlRecon[i] = make([]byte, len(ct))
		for j := 0; j < len(keyGuess) && j < len(ctl[i]); j++ {
			ptlRecon[i][j] = ct[j] ^ keyGuess[j]
		}
		fmt.Println(string(ptlRecon[i]))
	}

	fmt.Println("key is: ", keyGuess)
}
