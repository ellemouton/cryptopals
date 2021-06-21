package set5

import (
	"math/big"
	"math/rand"
	"time"
)

func DHKey(a, B, P *big.Int) []byte {
	s := new(big.Int).Exp(B, a, P)
	return s.Bytes()
}

func DHPubkey(a, G, P *big.Int) *big.Int {
	return new(big.Int).Exp(G, a, P)
}

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}
