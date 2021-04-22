package main

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/ellemouton/cryptopals/set3"
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	num, err := extractOne()
	if err != nil {
		log.Fatal(err)
	}

	seed, err := crackseed(num)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Cracked seed is: %d\n", seed)
}

// crackseed does a brute force attack. It assumes that unix timestamp was used
// to seed the generator so it just tries all timestamps from the last hour.
func crackseed(num uint32) (uint32, error) {
	hourAgo := time.Now().Add(time.Hour * -1).Unix()
	now := time.Now().Unix()

	for i := hourAgo; i < now; i++ {
		mt := set3.NewMT19937()
		mt.SeedMT(uint32(i))
		ext, err := mt.ExtractNumber()
		if err != nil {
			return 0, err
		}

		if ext == num {
			return uint32(i), nil
		}
	}

	return 0, errors.New("not cracked")
}

func extractOne() (uint32, error) {
	mt := set3.NewMT19937()

	// Wait random number of seconds between 40 and 1000
	var (
		min int64 = 40
		max int64 = 1000
	)

	sleepTime := time.Second * time.Duration(min+rand.Int63n(max-min))
	fmt.Printf("sleeping for %f seconds\n", sleepTime.Seconds())
	time.Sleep(sleepTime)

	seed := uint32(time.Now().Local().Unix())
	fmt.Printf("seed is: %d\n", seed)
	mt.SeedMT(seed)

	sleepTime = time.Second * time.Duration(min+rand.Int63n(max-min))
	fmt.Printf("sleeping for %f seconds\n", sleepTime.Seconds())
	time.Sleep(sleepTime)

	return mt.ExtractNumber()
}
