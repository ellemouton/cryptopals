package main

import (
	"bufio"
	"encoding/hex"
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

	best := ""
	size := 16
	i := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		i++
		line := scanner.Text()
		ciphertxt, err := hex.DecodeString(line)
		if err != nil {
			log.Fatal(err)
		}

		if set1.IsAESECBEncrypted(ciphertxt, size) {
			best = line
			break
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("line:", i)
	fmt.Println(best)
}
