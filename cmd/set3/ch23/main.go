package main

import (
	"fmt"
	"log"
	"time"

	"github.com/ellemouton/cryptopals/set3"
)

func main() {
	mt := set3.NewMT19937()
	mt.SeedMT(uint32(time.Now().Unix()))

	mtClone, err := set3.CloneMT19937(mt)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("OG:")
	fmt.Println(mt.ExtractNumber())
	fmt.Println(mt.ExtractNumber())
	fmt.Println(mt.ExtractNumber())

	fmt.Println("Clone:")
	fmt.Println(mtClone.ExtractNumber())
	fmt.Println(mtClone.ExtractNumber())
	fmt.Println(mtClone.ExtractNumber())
}
