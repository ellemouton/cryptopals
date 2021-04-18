package set3

import "errors"

var (
	w                  = 64
	n                  = 312
	m                  = 156
	r                  = 31
	a           uint64 = 0xB5026F5AA96619E9
	u           uint64 = 29
	d           uint64 = 0x5555555555555555
	s           uint64 = 17
	b           uint64 = 0x71D67FFFEDA60000
	t           uint64 = 37
	c           uint64 = 0xFFF7EEE000000000
	I           uint64 = 43
	f           uint64 = 6364136223846793005
	lower_mask  uint64 = 0x000000007FFFFFFF
	higher_mask uint64 = 0xFFFFFFFF80000000
)

type MT19937 struct {
	MT    []uint64
	index int
}

func NewMT19937() *MT19937 {
	return &MT19937{
		MT:    make([]uint64, n),
		index: n + 1,
	}
}

func (mt *MT19937) SeedMT(seed uint64) {
	mt.index = n
	mt.MT[0] = seed

	for i := 1; i < n; i++ {
		mt.MT[i] = f*(mt.MT[i-1]^(mt.MT[i-1]>>(w-2))) + uint64(i)
	}
}

func (mt *MT19937) ExtractNumber() (uint64, error) {
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
