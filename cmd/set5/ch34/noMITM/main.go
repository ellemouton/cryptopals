package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"math/rand"

	"github.com/ellemouton/cryptopals/set2"
	"github.com/ellemouton/cryptopals/set4/sha1"
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
	chanAB := make(chan string)

	go bob(chanAB)

	err := alice(chanAB, "ermergerd")
	if err != nil {
		log.Fatal(err)
	}
}

func alice(ch chan string, msg string) error {
	// Choose P and G
	pBytes, err := hex.DecodeString(PStr)
	if err != nil {
		return err
	}

	p := new(big.Int).SetBytes(pBytes)
	g := big.NewInt(2)

	// Derive a & A for alice
	a := big.NewInt(rand.Int63n(100))
	A := set5.DHPubkey(a, g, p)

	// 1. A sends "p", "g", "A"
	fmt.Println("A: sending P, g and A")
	ch <- string(p.Bytes())
	ch <- string(g.Bytes())
	ch <- string(A.Bytes())

	B := new(big.Int).SetBytes([]byte(<-ch))
	fmt.Println("A: received B")

	// Derive secret key
	secret := set5.DHKey(a, B, p)
	sha := sha1.Sum(secret)
	s := sha[:16]

	// 4. Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
	iv := randomIV()
	cipherTxt, err := set2.CBCEncrypt([]byte(msg), s, iv)
	if err != nil {
		return err
	}

	fmt.Printf("A: secret: %s, iv: %s\n", hex.EncodeToString(s),
		hex.EncodeToString(iv))

	payload := append(cipherTxt, iv...)

	fmt.Println("A: sending encrypted msg")
	ch <- string(payload)

	// get ciphertxt and IV and decrypt
	ct := []byte(<-ch)
	iv = ct[len(ct)-16:]
	ct = ct[:len(ct)-16]
	pt, err := set2.CBCDecrypt(ct, s, iv)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("A: received msg: %s\n", string(pt))

	_, pt = set2.ValidateAndStripPKCS7Pad(pt)
	fmt.Println("Is message the same?", string(pt) == msg)

	return nil
}

func bob(ch chan string) {
	var (
		ct, iv     []byte
		p, g, A, B *big.Int
	)

	for {

		// 2. B recieves p, g and A
		p = new(big.Int).SetBytes([]byte(<-ch))
		g = new(big.Int).SetBytes([]byte(<-ch))
		A = new(big.Int).SetBytes([]byte(<-ch))
		fmt.Println("B: received P, g and A")

		// Derive b & B for bob
		b := big.NewInt(rand.Int63n(100))
		B = set5.DHPubkey(b, g, p)

		// 3. B sends B
		fmt.Println("B: sending B")
		ch <- string(B.Bytes())

		// Derive secret key
		secret := set5.DHKey(b, A, p)
		sha := sha1.Sum(secret)
		s := sha[:16]

		// get ciphertxt and IV and decrypt
		ct = []byte(<-ch)
		iv = ct[len(ct)-16:]
		ct = ct[:len(ct)-16]
		pt, err := set2.CBCDecrypt(ct, s, iv)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("B: received msg: %s\n", string(pt))

		// 5. Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
		iv = randomIV()

		fmt.Printf("B: secret: %s, iv: %s\n", hex.EncodeToString(s),
			hex.EncodeToString(iv))

		cipherTxt, err := set2.CBCEncrypt(pt, s, iv)
		if err != nil {
			log.Fatal(err)
		}

		payload := append(cipherTxt, iv...)

		fmt.Println("B: sending encrypted msg")
		ch <- string(payload)
	}
}

func randomIV() []byte {
	token := make([]byte, 16)
	rand.Read(token)
	return token
}
