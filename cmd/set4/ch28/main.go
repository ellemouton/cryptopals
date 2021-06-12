package main

import (
	"fmt"

	"github.com/ellemouton/cryptopals/set2"
	"github.com/ellemouton/cryptopals/set4"
)

func main() {
	key := set2.GenAESKey()
	msg := []byte("my secret message")
	mac := set4.SecretPrefixedMac(key, msg)

	fmt.Println(set4.AuthenticateMAC(key, msg, mac))

	// try alter the message
	msg = []byte("my very secret message")
	fmt.Println(set4.AuthenticateMAC(key, msg, mac))

	h := set4.New()
	h.Write([]byte("blah"))
	fmt.Println(h.Sum(nil))
	h.Write([]byte("blah"))
	fmt.Println(h.Sum(nil))

	//h2 := set4.New()
	fmt.Println(set4.Sum([]byte("blahblah")))
}
