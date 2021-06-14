package set5

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"math/big"
)

var (
	P *big.Int
	G *big.Int
)

func DHKey(a, B *big.Int) [32]byte {
	s := new(big.Int).Exp(B, a, P)
	return sha256.Sum256(s.Bytes())
}

func DHPubkey(a *big.Int) *big.Int {
	return new(big.Int).Exp(G, a, P)
}

func init() {
	pStr := "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
		"fffffffffffff"

	p, err := hex.DecodeString(pStr)
	if err != nil {
		log.Fatal(err)
	}

	P = new(big.Int).SetBytes(p)
	G = big.NewInt(2)
}
