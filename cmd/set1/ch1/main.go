package main

import (
	"fmt"
	"log"

	"github.com/ellemouton/cryptopals/set1"
)

func main() {
	fmt.Println("============= hex to base64 ==============")

	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	fmt.Printf("Hex input is: %s\n", input)

	fmt.Println("converting....")
	res, err := set1.HexToBase64(input)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Base64 output is: %s\n", res)
	fmt.Println("==========================================")
}
