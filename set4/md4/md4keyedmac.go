package md4

import "bytes"

func SecretKeyedMac(key, msg []byte) []byte {
	return Sum(append(key, msg...))
}

func AuthenticateMAC(key, msg, mac []byte) bool {
	return bytes.Compare(SecretKeyedMac(key, msg), mac) == 0
}
