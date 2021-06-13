package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/ellemouton/cryptopals/set4"
	"github.com/ellemouton/cryptopals/set4/md4"
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
	mac := md4.SecretKeyedMac(key, msg)
	fmt.Println("Origional message: ", string(msg))
	fmt.Println("Real key len:", len(key))
	fmt.Println("MAC: ", mac)
	fmt.Println("valid mac?", md4.AuthenticateMAC(key, msg, mac))

	// get state from mac
	var iv [4]uint32
	for i, _ := range iv {
		offset := i * 4
		temp := mac[offset : offset+4]
		var b uint32
		b += uint32(temp[0]) << 0
		b += uint32(temp[1]) << 8
		b += uint32(temp[2]) << 16
		b += uint32(temp[3]) << 24
		iv[i] = b
	}

	var (
		mac2      []byte
		forgedMsg []byte
		keyLen    int
	)

	// We dont know the key so gotta guess its len
	for i := minKeyLen; i < maxKeyLen; i++ {
		custom := md4.CustomInit(iv)
		custom.Write(wanted)

		// add expected padding and write that
		gluePadding := set4.MDPadBytesLE(i + len(msg))
		forgedMsg = append(msg, append(gluePadding, wanted...)...)
		expectedPadding := set4.MDPadBytesLE(i + len(forgedMsg))
		custom.Write(expectedPadding)
		mac2 = custom.GetState()

		if md4.AuthenticateMAC(key, forgedMsg, mac2[:]) {
			keyLen = i
			break
		}
	}

	fmt.Println("New message: ", string(forgedMsg))
	fmt.Println("Guessed key len: ", keyLen)
	fmt.Println("MAC: ", mac2)
	fmt.Println("valid mac?", md4.AuthenticateMAC(key, forgedMsg, mac2))
}

func pickRandomKey() []byte {
	token := make([]byte, rand.Intn(maxKeyLen-minKeyLen)+minKeyLen)
	rand.Read(token)
	return token
}
