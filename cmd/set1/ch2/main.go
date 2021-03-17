package main

import (
	"fmt"
	"log"

	"github.com/ellemouton/cryptopals/set1"
)

func main() {
	fmt.Println("============= Fixed XOR  ==============")

	a := "1c0111001f010100061a024b53535009181c"
	b := "686974207468652062756c6c277320657965"
	fmt.Printf("Hex inputs are: \na:\t%s\nb:\t%s\n", a, b)

	fmt.Println("calculating....")
	res, err := set1.HexStrFixedXOR(a, b)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("XOR output is: %s\n", res)
	fmt.Println("==========================================")
}
