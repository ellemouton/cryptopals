package main

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"time"

	"github.com/ellemouton/cryptopals/set5"
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())
	//babyDH()

	a := big.NewInt(rand.Int63n(10))
	A := set5.DHPubkey(a)

	b := big.NewInt(rand.Int63n(10))
	B := set5.DHPubkey(b)

	sA := set5.DHKey(a, B)
	sB := set5.DHKey(b, A)
	fmt.Println(sA)
	fmt.Println(sB)
}

func babyDH() {
	p, g := 37, 5

	a := rand.Intn(10)
	A := int(math.Pow(float64(g), float64(a))) % p

	b := rand.Intn(10)
	B := int(math.Pow(float64(g), float64(b))) % p

	sA := int(math.Pow(float64(B), float64(a))) % p
	sB := int(math.Pow(float64(A), float64(b))) % p

	fmt.Println(sA)
	fmt.Println(sB)
	fmt.Println(sA == sB)
}
