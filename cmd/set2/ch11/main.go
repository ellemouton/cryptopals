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
	res, err := set2.ModeOracle([]byte("Sunshine and rainbows"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(res)
}
