package set4

import (
	"bytes"
	"crypto/sha1"
)

func SecretPrefixedMac(key, msg []byte) []byte {
	res := sha1.Sum(append(key, msg...))
	return res[:]
}

func AuthenticateMAC(key, msg, mac []byte) bool {
	return bytes.Compare(SecretPrefixedMac(key, msg), mac) == 0
}
