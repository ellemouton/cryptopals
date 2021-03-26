package main

import (
	"fmt"

	"github.com/ellemouton/cryptopals/set2"
)

func main() {
	data := []byte("YELLOW SUBMARINE")
	fmt.Println(data)
	fmt.Println(set2.PKCS7Pad(data, 20))
}
