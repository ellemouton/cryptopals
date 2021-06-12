package sha1

import (
	"bytes"
	"encoding/binary"
)

func SecretPrefixedMac(key, msg []byte) []byte {
	res := Sum(append(key, msg...))
	return res[:]
}

func AuthenticateMAC(key, msg, mac []byte) bool {
	return bytes.Compare(SecretPrefixedMac(key, msg), mac) == 0
}

func MDPadBytes(ml int) []byte {
	// ml is message len in bytes (so x8 to get bit length)

	// add bit '1' (gonna actually add 1 byte meaning: one '1' bit and 7 '0'
	// bits
	p := []byte{0x80}
	res := p

	// gonna end up adding 64 bits (8 bytes) in the end. So use fake length
	// to account for that
	fakeLen := ml + len(p) + 8

	// now determine how many '0's to add so that the final thing will be
	// multiple of 512 bits (64 bytes)
	var zeros [64]byte
	res = append(res, zeros[:64-(fakeLen%64)][:]...)

	// now just need to add the OG message bit length encoded as 64 bit
	// big-endian.
	l := ml * 8

	binary.BigEndian.PutUint64(zeros[:], uint64(l))
	res = append(res, zeros[0:8]...)

	return res
}
