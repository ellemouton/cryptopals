package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"os"

	"github.com/ellemouton/cryptopals/set1"
)

func main() {
	file, err := os.Open("input.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	smallestScore := math.MaxFloat64
	var (
		bestLine []byte
		bestByte byte
	)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		bytes, err := hex.DecodeString(line)
		if err != nil {
			log.Fatal(err)
		}

		b, score, err := set1.FindSingleByteXOR(bytes)
		if err != nil {
			log.Fatal(err)
		}

		if score < smallestScore {
			smallestScore = score
			bestByte = *b
			bestLine = bytes
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	test := []byte{}
	for i := 0; i < len([]byte(bestLine)); i++ {
		test = append(test, bestByte)
	}

	res, err := set1.FixedXOR(bestLine, test)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("The encoded line is: ", hex.EncodeToString(bestLine))
	fmt.Println("It was encoded by XORing with: ", string(bestByte))
	fmt.Println("The decoded line is: ", string(res))
}
