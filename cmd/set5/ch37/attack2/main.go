package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"strconv"

	"github.com/ellemouton/cryptopals/set5"
)

// Variables that the client and server agree on
var (
	N, G, K *big.Int
)

func main() {
	chanCS := make(chan string)

	go func() {
		if err := server(chanCS); err != nil {
			log.Fatal(err)
		}
	}()

	if err := client(chanCS); err != nil {
		log.Fatal(err)
	}

}

/*
The trick here is to note that (ab^u)%a = 0 always
*/
func client(ch chan string) error {
	var email, password string

	// get email address from user
	fmt.Println("email: ")
	fmt.Scanln(&email)

	// send I (email)
	ch <- email

	// Send A = N
	ch <- string(N.Bytes())

	// get salt and B from server
	salt, err := strconv.ParseInt(<-ch, 10, 64)
	if err != nil {
		return err
	}

	// get B from server
	<-ch

	// get password address from user
	fmt.Println("password: ")
	fmt.Scanln(&password)

	s := big.NewInt(0).Bytes()
	k := sha256.Sum256(s)

	saltBytes := make([]byte, 64)
	binary.LittleEndian.PutUint64(saltBytes, uint64(salt))

	// get and send hmac to server
	hmac, err := set5.HMACSHA256(k[:], saltBytes)
	if err != nil {
		return err
	}
	ch <- string(hmac)

	// print server response
	fmt.Println(<-ch)

	return nil
}

func server(ch chan string) error {
	// always listening for new client requests.
	for {
		// Get an I and A from a client
		I := <-ch
		A := new(big.Int).SetBytes([]byte(<-ch))

		sesh, err := newServerSession(I)
		if err != nil {
			return err
		}

		// send salt and B to client
		ch <- strconv.FormatInt(sesh.salt, 10)
		ch <- string(sesh.B.Bytes())

		uH := sha256.Sum256(append(A.Bytes(), sesh.B.Bytes()...))
		u := new(big.Int).SetBytes(uH[:])

		temp := set5.DHPubkey(u, sesh.v, N)
		temp.Mul(temp, A)

		s := set5.DHKey(sesh.b, temp, N)
		k := sha256.Sum256(s[:])

		saltBytes := make([]byte, 64)
		binary.LittleEndian.PutUint64(saltBytes, uint64(sesh.salt))

		hmac, err := set5.HMACSHA256(k[:], saltBytes)
		if err != nil {
			return err
		}

		// wait for hmac from client
		clientHmac := []byte(<-ch)

		if bytes.Compare(hmac, clientHmac) == 0 {
			ch <- "SUCCESS"
		} else {
			ch <- "FAILURE"
		}
	}
	return nil
}

type serverSession struct {
	salt int64
	v    *big.Int
	b, B *big.Int
}

func newServerSession(email string) (*serverSession, error) {
	// map of emails to passwords
	users := map[string]string{
		"elle.mouton@gmail.com": "superSecure",
	}

	psswd, ok := users[email]
	if !ok {
		return nil, errors.New("no such user")
	}

	// gen salt
	salt := rand.Int63n(10000)

	// x = bigInt(sha256(salt | password))
	x := getX(salt, psswd)

	// v = (g^x)%N
	v := set5.DHPubkey(x, G, N)

	// Derive b & B for the server
	b := big.NewInt(rand.Int63n(1000))
	B := new(big.Int).Add(set5.DHPubkey(b, G, N), new(big.Int).Mul(v, K))

	return &serverSession{
		salt: salt,
		v:    v,
		b:    b,
		B:    B,
	}, nil
}

func getX(salt int64, password string) *big.Int {
	xH := sha256.Sum256([]byte(fmt.Sprint("%s%s", strconv.FormatInt(salt, 10), password)))
	return new(big.Int).SetBytes(xH[:])
}

func init() {
	n, err := hex.DecodeString(nistPrimeStr)
	if err != nil {
		log.Fatal(err)
	}

	N = new(big.Int).SetBytes(n)

	G = big.NewInt(2)
	K = big.NewInt(3)
}

var nistPrimeStr = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
	"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
	"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
	"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
	"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
	"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
	"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
	"fffffffffffff"
