package set3

import "errors"

var (
	w                  = 32
	n                  = 624
	m                  = 397
	r                  = 31
	a           uint32 = 0x9908B0DF
	u           uint32 = 11
	d           uint32 = 0xFFFFFFFF
	s           uint32 = 7
	b           uint32 = 0x9D2C5680
	t           uint32 = 15
	c           uint32 = 0xEFC60000
	I           uint32 = 18
	f           uint32 = 1812433253
	lower_mask  uint32 = 0x7FFFFFFF
	higher_mask uint32 = 0x80000000
)

type MT19937 struct {
	MT    []uint32
	index int
}

func NewMT19937() *MT19937 {
	return &MT19937{
		MT:    make([]uint32, n),
		index: n + 1,
	}
}

func (mt *MT19937) SeedMT(seed uint32) {
	mt.index = n
	mt.MT[0] = seed

	for i := 1; i < n; i++ {
		mt.MT[i] = f*(mt.MT[i-1]^(mt.MT[i-1]>>(w-2))) + uint32(i)
	}
}

func (mt *MT19937) ExtractNumber() (uint32, error) {
	if mt.index >= n {
		if mt.index > n {
			return 0, errors.New("generator was not seeded")
		}
		mt.twist()
	}

	y := mt.MT[mt.index]
	y = y ^ ((y >> u) & d)
	y = y ^ ((y << s) & b)
	y = y ^ ((y << t) & c)
	y = y ^ (y >> I)

	mt.index++
	return y, nil
}

func (mt *MT19937) twist() {
	for i := 0; i < n; i++ {
		x := (mt.MT[i] & higher_mask) + (mt.MT[(i+1)%n] & lower_mask)
		xA := x >> 1
		if x%2 != 0 {
			xA = xA ^ a
		}
		mt.MT[i] = mt.MT[(i+m)%n] ^ xA
	}
	mt.index = 0
}

// CLONEING

func CloneMT19937(mt *MT19937) (*MT19937, error) {
	clone := NewMT19937()

	for i := 0; i < n; i++ {
		next, err := mt.ExtractNumber()
		if err != nil {
			return nil, err
		}

		clone.MT[i] = untemper(next)
	}

	// fast forward so that clone is on same round as origional
	clone.index = 0
	for i := 0; i < n; i++ {
		_, err := clone.ExtractNumber()
		if err != nil {
			return nil, err
		}
	}

	return clone, nil
}

func untemper(n uint32) uint32 {
	y := reverseRShiftXOR(n, I)
	y = reverseLXORShiftAndAnd(y, t, c)
	y = reverseLXORShiftAndAnd(y, s, b)
	y = reverseRXORShiftAndAnd(y, u, d)

	return y
}

func reverseLXORShiftAndAnd(num uint32, t uint32, c uint32) uint32 {
	var (
		res   uint32
		start = 0
		end   = int(t)
	)

	chunk := num & mask(start, end)
	res |= chunk

	for end != 32 {
		start = end
		end += int(t)
		if end > 32 {
			end = 32
		}

		chunk = (chunk & ((c & mask(start, end)) >> start)) ^ ((num & mask(start, end)) >> start)
		res |= (chunk << start)
	}

	return res
}

func reverseRXORShiftAndAnd(num uint32, t uint32, c uint32) uint32 {
	var (
		res   uint32
		start = 32 - int(t)
		end   = 32
	)

	chunk := (num & mask(start, end)) >> start
	res = chunk << start

	for start != 0 {
		end = start
		start -= int(t)
		if start < 0 {
			chunk = chunk >> -start
			start = 0
		}

		chunk = (chunk & ((c & mask(start, end)) >> start)) ^ ((num & mask(start, end)) >> start)

		res |= chunk << start
	}

	return res
}

func reverseRShiftXOR(num uint32, I uint32) uint32 {
	var (
		res   uint32
		start = 32 - int(I)
		end   = 32
	)

	chunk := (num & mask(start, end)) >> start

	res |= chunk << start

	for start != 0 {
		end = start
		start -= int(I)
		if start < 0 {
			chunk = chunk >> -start
			start = 0
		}

		chunk ^= (num & mask(start, end)) >> start
		res |= chunk << start

	}

	return res
}

func mask(start, end int) uint32 {
	var res uint32

	for i := 0; i < end-start; i++ {
		res |= 1 << i
	}

	for i := 0; i < start; i++ {
		res = res << 1
	}

	return res
}
