package main

import (
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/ellemouton/cryptopals/set2"
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	res, err := set2.ECBDecryptionHard()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(res))
}
