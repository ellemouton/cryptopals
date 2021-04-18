package main

import (
	"fmt"

	"github.com/ellemouton/cryptopals/set3"
)

func main() {
	mt := set3.NewMT19937()
	mt.SeedMT(0)
	fmt.Println(mt.ExtractNumber())
}
