package main

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

func main() {
	fmt.Println(probeSig("file"))
}

func probeSig(file string) (string, error) {
	sig := make([]byte, 20, 20)

	for i := 0; i < len(sig); i++ {
		var (
			longestDur     int64
			longestDurByte int
		)
		for j := 0; j < 256; j++ {
			sig[i] = byte(j)

			code, dur, err := sendAndTime(file, sig)
			if err != nil {
				return "", err
			}

			if code == 200 {
				break
			}

			if int64(dur) > longestDur {
				longestDur = int64(dur)
				longestDurByte = j
			}
		}
		sig[i] = byte(longestDurByte)
		fmt.Println(sig)
	}

	return hex.EncodeToString(sig), nil
}

func sendAndTime(file string, sig []byte) (int, time.Duration, error) {
	url := buildURL(file, sig)

	t0 := time.Now()

	resp, err := http.Get(url)
	if err != nil {
		return 0, 0, err
	}

	defer resp.Body.Close()
	return resp.StatusCode, time.Since(t0), nil
}

func buildURL(file string, sig []byte) string {
	return fmt.Sprintf("http://127.0.0.1:9000/test?file=%s&signature=%s", file, hex.EncodeToString(sig))
}
