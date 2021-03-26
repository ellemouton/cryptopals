package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/ellemouton/cryptopals/set1"
)

func main() {
	file, err := os.Open("input.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var text string
	for scanner.Scan() {
		text += scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	ciphertxt, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		log.Fatal(err)
	}

	key := "YELLOW SUBMARINE"

	plaintxt, err := set1.DecryptAESECB([]byte(key), ciphertxt)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(plaintxt))

}
