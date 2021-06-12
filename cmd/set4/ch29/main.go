package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"github.com/ellemouton/cryptopals/set4/sha1"
)

var (
	minKeyLen = 3
	maxKeyLen = 20
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	wanted := []byte(";admin=true")

	key := pickRandomKey()
	mac := sha1.SecretPrefixedMac(key, msg)
	fmt.Println("Origional message: ", string(msg))
	fmt.Println("Real key len:", len(key))
	fmt.Println("MAC: ", mac)
	fmt.Println("valid mac?", sha1.AuthenticateMAC(key, msg, mac))

	// split mac into 5
	var iv [5]uint32
	for i, _ := range iv {
		offset := i * 4
		iv[i] = binary.BigEndian.Uint32(mac[offset : offset+4])
	}

	var (
		mac2      [20]byte
		forgedMsg []byte
		keyLen    int
	)

	// We dont know the key so gotta guess its len
	for i := minKeyLen; i < maxKeyLen; i++ {

		custom := sha1.CustomInit(iv)
		custom.Write(wanted)

		// add expected padding and write that
		gluePadding := sha1.MDPadBytes(i + len(msg))
		forgedMsg = append(msg, append(gluePadding, wanted...)...)
		expectedPadding := sha1.MDPadBytes(i + len(forgedMsg))
		custom.Write(expectedPadding)
		mac2 = custom.GetState()

		if sha1.AuthenticateMAC(key, forgedMsg, mac2[:]) {
			keyLen = i
			break
		}
	}

	fmt.Println("New message: ", string(forgedMsg))
	fmt.Println("Guessed key len: ", keyLen)
	fmt.Println("MAC: ", mac2)
	fmt.Println("valid mac?", sha1.AuthenticateMAC(key, forgedMsg, mac2[:]))
}

func pickRandomKey() []byte {
	token := make([]byte, rand.Intn(maxKeyLen-minKeyLen)+minKeyLen)
	rand.Read(token)
	return token
}
