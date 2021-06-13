package sha1

import (
	"bytes"
)

func SecretPrefixedMac(key, msg []byte) []byte {
	res := Sum(append(key, msg...))
	return res[:]
}

func AuthenticateMAC(key, msg, mac []byte) bool {
	return bytes.Compare(SecretPrefixedMac(key, msg), mac) == 0
}
