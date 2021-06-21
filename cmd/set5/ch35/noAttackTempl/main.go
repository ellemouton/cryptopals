package main

import (
	"encoding/hex"
	"errors"
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
	chanAM := make(chan string)
	chanMB := make(chan string)

	go bob(chanMB)
	go mallary(chanAM, chanMB)

	err := alice(chanAM, "ermergerd")
	if err != nil {
		log.Fatal(err)
	}
}

func mallary(chA, chB chan string) {
	var (
		p, g, A, B *big.Int
		ct         []byte
	)

	for {
		// get p and g from alice
		p = new(big.Int).SetBytes([]byte(<-chA))
		g = new(big.Int).SetBytes([]byte(<-chA))
		fmt.Println("M: received P and g from alice")

		// passes on to bob: p and g
		fmt.Println("M: sending P and g to bob")
		chB <- string(p.Bytes())
		chB <- string(g.Bytes())

		// get ACK from bob
		<-chB
		fmt.Println("M: got ACK from bob")

		// send ACK to alice
		fmt.Println("M: sending ACK to alice")
		chA <- "ACK"

		// Get A from alice
		A = new(big.Int).SetBytes([]byte(<-chA))
		fmt.Println("M: got A from alice")

		// Send A to bob
		fmt.Println("M: sending A to bob")
		chB <- string(A.Bytes())

		// get B from bob
		B = new(big.Int).SetBytes([]byte(<-chB))
		fmt.Println("M: got B from bob")

		// pass it back to alice
		fmt.Println("M: sending B to alice")
		chA <- string(B.Bytes())

		// get encrypted msg from alice
		ct = []byte(<-chA)
		fmt.Println("M: got ct from alice")

		// send it to bob
		fmt.Println("M: passing ct to bob")
		chB <- string(ct)

		// get encrypted msg from bob
		ct = []byte(<-chB)
		fmt.Println("M: got ct from bob")

		// pass it on to alice
		fmt.Println("M: passing ct to alice")
		chA <- string(ct)
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

	// A sends "p", "g"
	fmt.Println("A: sending P and g. Awaiting ACK.")
	ch <- string(p.Bytes())
	ch <- string(g.Bytes())

	// A waits for "ACK"
	ack := <-ch
	if ack != "ACK" {
		return errors.New(fmt.Sprintf("expected ACK, got %s", ack))
	}
	fmt.Println("A: received ACK")

	// Derive a & A for alice
	a := big.NewInt(rand.Int63n(100))
	A := set5.DHPubkey(a, g, p)

	fmt.Println("A: sending A")
	ch <- string(A.Bytes())

	B := new(big.Int).SetBytes([]byte(<-ch))
	fmt.Println("A: received B")

	// Derive secret key
	secret := set5.DHKey(a, B, p)
	sha := sha1.Sum(secret)
	s := sha[:16]

	// Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
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

		// B recieves p and g
		p = new(big.Int).SetBytes([]byte(<-ch))
		g = new(big.Int).SetBytes([]byte(<-ch))
		fmt.Println("B: received P and g")

		// Send ACK
		fmt.Println("B: sending ACK")
		ch <- "ACK"

		// Wait for A
		A = new(big.Int).SetBytes([]byte(<-ch))
		fmt.Println("B: received A")

		// Derive b & B for bob
		b := big.NewInt(rand.Int63n(100))
		B = set5.DHPubkey(b, g, p)

		// B sends B
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

		// Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
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
