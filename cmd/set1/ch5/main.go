package main

import (
	"encoding/hex"
	"fmt"

	"github.com/ellemouton/cryptopals/set1"
)

func main() {
	res, _ := set1.RepeatingKeyEncrypt([]byte("Burning 'em"), []byte("ICE"))
	fmt.Println(hex.EncodeToString(res))
}
