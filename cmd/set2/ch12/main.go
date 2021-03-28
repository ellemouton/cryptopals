package main

import (
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/ellemouton/cryptopals/set1"
	"github.com/ellemouton/cryptopals/set2"
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	keySize, err := set2.DetermineEBCKeySize()
	// Is ECB mode?
	plainTxt := []byte("Well hello there")
	var in []byte
	in = append(in, plainTxt...)

	// duplicate the input to at least 3 times the block size
	for len(in) < 16*3 {
		in = append(in, in...)
	}

	res, err := set2.EncryptWithUnknownStr(in)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Is using ECB mode?", set1.IsAESECBEncrypted(res, keySize))

	pt, err := set2.ECBDecryptionSimple()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(pt))
}
