package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"math/rand"
	"strings"
	"time"

	"github.com/ellemouton/cryptopals/set3"
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	// Part 1: Implement the stream cipher
	key := Gen2ByteKey()

	pt := []byte("YELLOW SUBMARINE")
	ct, err := set3.MT19937StreamCipher(key, pt)
	if err != nil {
		log.Fatal(err)
	}

	pt2, err := set3.MT19937StreamCipher(key, ct)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(pt2))

	// Part 2: Crack the key. They say we should use a 2 byte seed.... so...
	// BRUTE FORCE

	k := Gen2ByteKey()

	randomChars := make([]byte, rand.Intn(100))
	rand.Read(randomChars)

	knownTxt := []byte("AAAAAAAAAAAAAA")
	pt = append(randomChars, knownTxt...)

	ct, err = set3.MT19937StreamCipher(k, pt)
	if err != nil {
		log.Fatal(err)
	}

	// 2 byte seed => try all numbers between 0 and 2^16
	var i uint16
	for ; i <= uint16(math.Exp2(16)-1); i++ {
		iBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(iBytes, i)

		b, err := set3.MT19937StreamCipher(iBytes, ct)
		if err != nil {
			log.Fatal(err)
		}

		if strings.Contains(string(b), string(knownTxt)) {
			fmt.Println("found it:", iBytes)
			fmt.Println(string(iBytes) == string(k))
			break
		}
	}

	// Part 3: Password reset token seeded with current time:
	mt := set3.NewMT19937()
	mt.SeedMT(uint32(time.Now().Unix()))
	token, err := mt.ExtractNumber()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(isSeededFromCurrentTime(token))

}

func isSeededFromCurrentTime(token uint32) (bool, error) {

	// check the past 10 seconds
	t := time.Now().Unix()
	for i := 0; i <= 10; i++ {
		mt := set3.NewMT19937()
		mt.SeedMT(uint32(t - int64(i)))
		temp, err := mt.ExtractNumber()
		if err != nil {
			return false, err
		}

		if temp == token {
			return true, nil
		}
	}

	return false, nil
}

func Gen2ByteKey() []byte {
	token := make([]byte, 2)
	rand.Read(token)
	return token
}
