package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/ellemouton/cryptopals/set3"
)

func main() {
	b, err := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	if err != nil {
		log.Fatal(err)
	}

	key := []byte("YELLOW SUBMARINE")

	pt, err := set3.CTR(key, b, 0)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(pt))
}
