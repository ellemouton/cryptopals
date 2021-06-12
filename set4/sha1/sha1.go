// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha1 implements the SHA-1 hash algorithm as defined in RFC 3174.
//
// SHA-1 is cryptographically broken and should not be used for secure
// applications.
package sha1

import (
	"encoding/binary"
	"hash"
)

var block = blockGeneric

// The size of a SHA-1 checksum in bytes.
const Size = 20

// The blocksize of SHA-1 in bytes.
const BlockSize = 64

const (
	chunk = 64
	init0 = 0x67452301
	init1 = 0xEFCDAB89
	init2 = 0x98BADCFE
	init3 = 0x10325476
	init4 = 0xC3D2E1F0
)

// Digest represents the partial evaluation of a checksum.
type Digest struct {
	h   [5]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

func (d *Digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.nx = 0
	d.len = 0
}

// New returns a new hash.Hash computing the SHA1 checksum. The Hash also
// implements encoding.BinaryMarshaler and encoding.BinaryUnmarshaler to
// marshal and unmarshal the internal state of the hash.
func New() hash.Hash {
	d := new(Digest)
	d.Reset()
	return d
}

func (d *Digest) Size() int { return Size }

func (d *Digest) BlockSize() int { return BlockSize }

func (d *Digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *Digest) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func padding(d *Digest) []byte {
	var res []byte

	len := d.len
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var (
		tmp  [64]byte
		tmp2 [64]byte
	)
	tmp[0] = 0x80
	if len%64 < 56 {
		res = tmp[0 : 56-len%64]
	} else {
		res = tmp[0 : 64+56-len%64]
	}

	// Length in bits.
	len <<= 3
	binary.BigEndian.PutUint64(tmp2[:], len)
	return append(res, tmp2[0:8]...)
}

func (d *Digest) checkSum() [Size]byte {
	pad := padding(d)
	d.Write(pad)

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var Digest [Size]byte

	binary.BigEndian.PutUint32(Digest[0:], d.h[0])
	binary.BigEndian.PutUint32(Digest[4:], d.h[1])
	binary.BigEndian.PutUint32(Digest[8:], d.h[2])
	binary.BigEndian.PutUint32(Digest[12:], d.h[3])
	binary.BigEndian.PutUint32(Digest[16:], d.h[4])

	return Digest
}

// Sum returns the SHA-1 checksum of the data.
func Sum(data []byte) [Size]byte {
	var d Digest
	d.Reset()
	d.Write(data)
	return d.checkSum()
}

func CustomInit(iv [5]uint32) *Digest {
	d := new(Digest)

	d.h[0] = iv[0]
	d.h[1] = iv[1]
	d.h[2] = iv[2]
	d.h[3] = iv[3]
	d.h[4] = iv[4]
	d.nx = 0
	d.len = 0

	return d
}

func (d *Digest) GetState() [Size]byte {
	var Digest [Size]byte

	binary.BigEndian.PutUint32(Digest[0:], d.h[0])
	binary.BigEndian.PutUint32(Digest[4:], d.h[1])
	binary.BigEndian.PutUint32(Digest[8:], d.h[2])
	binary.BigEndian.PutUint32(Digest[12:], d.h[3])
	binary.BigEndian.PutUint32(Digest[16:], d.h[4])

	return Digest
}
