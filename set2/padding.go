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

func ValidateAndStripPKCS7Pad(data []byte) (bool, []byte) {
	num := int(data[len(data)-1])
	count := 1

	if count == num {
		return true, data[0 : len(data)-count]
	}

	for i := len(data) - 2; i >= 0; i-- {

		if int(data[i]) != num {
			return false, nil
		}

		count++

		if count == num {
			return true, data[0 : len(data)-count]
		}
	}

	return false, nil
}
