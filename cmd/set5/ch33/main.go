package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/rand"

	"github.com/ellemouton/cryptopals/set5"
)

var PStr = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
	"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
	"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
	"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
	"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
	"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
	"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
	"fffffffffffff"

func main() {
	//babyDH()

	pBytes, err := hex.DecodeString(PStr)
	if err != nil {
		log.Fatal(err)
	}

	p := new(big.Int).SetBytes(pBytes)
	g := big.NewInt(2)

	a := big.NewInt(rand.Int63n(100))
	A := set5.DHPubkey(a, g, p)

	b := big.NewInt(rand.Int63n(100))
	B := set5.DHPubkey(b, g, p)

	sA := set5.DHKey(a, B, p)
	sB := set5.DHKey(b, A, p)
	sAH := sha256.Sum256(sA)
	sBH := sha256.Sum256(sB)
	fmt.Println(hex.EncodeToString(sAH[:]))
	fmt.Println(hex.EncodeToString(sBH[:]))
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
