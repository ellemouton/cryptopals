package set2

func PKCS7Pad(data []byte, blockLen int) []byte {
	size := blockLen

	if blockLen < len(data) {
		size += blockLen * (len(data) / blockLen)
	}

	num := size - len(data)
	res := make([]byte, len(data)+num)
	copy(res, data)

	for i := len(data); i < len(data)+num; i++ {
		res[i] = byte(num)
	}

	return res
}
