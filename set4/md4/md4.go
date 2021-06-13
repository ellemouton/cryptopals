package md4 // import "golang.org/x/crypto/md4"

import (
	"crypto"
	"hash"
)

func init() {
	crypto.RegisterHash(crypto.MD4, New)
}

// The size of an MD4 checksum in bytes.
const Size = 16

// The blocksize of MD4 in bytes.
const BlockSize = 64

const (
	_Chunk = 64
	_Init0 = 0x67452301
	_Init1 = 0xEFCDAB89
	_Init2 = 0x98BADCFE
	_Init3 = 0x10325476
)

// Digest represents the partial evaluation of a checksum.
type Digest struct {
	s   [4]uint32
	x   [_Chunk]byte
	nx  int
	len uint64
}

func (d *Digest) Reset() {
	d.s[0] = _Init0
	d.s[1] = _Init1
	d.s[2] = _Init2
	d.s[3] = _Init3
	d.nx = 0
	d.len = 0
}

// New returns a new hash.Hash computing the MD4 checksum.
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
		n := len(p)
		if n > _Chunk-d.nx {
			n = _Chunk - d.nx
		}
		for i := 0; i < n; i++ {
			d.x[d.nx+i] = p[i]
		}
		d.nx += n
		if d.nx == _Chunk {
			_Block(d, d.x[0:])
			d.nx = 0
		}
		p = p[n:]
	}
	n := _Block(d, p)
	p = p[n:]
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d0 *Digest) Sum(in []byte) []byte {
	// Make a copy of d0, so that caller can keep writing and summing.
	d := new(Digest)
	*d = *d0
	hash := d.checkSum()
	return append(in, hash[:]...)
}

func Sum(data []byte) []byte {
	var d Digest
	d.Reset()
	d.Write(data)
	return d.checkSum()
}

func CustomInit(iv [4]uint32) *Digest {
	d := new(Digest)
	d.s[0] = iv[0]
	d.s[1] = iv[1]
	d.s[2] = iv[2]
	d.s[3] = iv[3]
	d.nx = 0
	d.len = 0
	return d
}

func (d *Digest) GetState() []byte {
	var in []byte
	for _, s := range d.s {
		in = append(in, byte(s>>0))
		in = append(in, byte(s>>8))
		in = append(in, byte(s>>16))
		in = append(in, byte(s>>24))
	}
	return in
}

func (d0 *Digest) checkSum() []byte {
	pad := padding(d0)
	d0.Write(pad)

	if d0.nx != 0 {
		panic("d.nx != 0")
	}

	var in []byte
	for _, s := range d0.s {
		in = append(in, byte(s>>0))
		in = append(in, byte(s>>8))
		in = append(in, byte(s>>16))
		in = append(in, byte(s>>24))
	}
	return in
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
	for i := uint(0); i < 8; i++ {
		tmp2[i] = byte(len >> (8 * i))
	}

	return append(res, tmp2[0:8]...)
}
