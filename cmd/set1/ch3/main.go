package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/ellemouton/cryptopals/set1"
)

func main() {
	in := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	bytes, err := hex.DecodeString(in)
	if err != nil {
		log.Fatal(err)
	}

	closestFit, _, err := set1.FindSingleByteXOR(bytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(*closestFit))

	test := []byte{}
	for i := 0; i < len([]byte(bytes)); i++ {
		test = append(test, byte(*closestFit))
	}

	res, err := set1.FixedXOR(bytes, test)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(res))
}
