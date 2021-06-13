package main

import (
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"time"
)

func main() {
	fmt.Println(probeSig("file"))
}

func probeSig(file string) (string, error) {
	sig := make([]byte, 20, 20)

	var prevAvg1 int64
	var prevAvg2 int64
	var expectedOneByteDur int64

	index := 0
	for index < len(sig) {
		var (
			longestDur     int64
			longestDurByte int
			totalDur       int64
		)

		//expectedOffset := int64(index) * expectedOneByteDur

		for j := 0; j < 256; j++ {
			sig[index] = byte(j)

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

			totalDur += int64(dur) // - expectedOffset
		}

		sig[index] = byte(longestDurByte)
		fmt.Println(sig)

		avgDur := (totalDur - int64(sig[index])) / 255

		if index == 0 {
			index++
			continue
		}

		if index == 1 {
			expectedOneByteDur = avgDur
		}

		temp := int64(math.Abs(float64(expectedOneByteDur) - math.Abs(float64(avgDur-prevAvg1))))
		if temp > expectedOneByteDur/2 {
			// assume then that previous byte is incorrect. So gotta
			// roll back.
			fmt.Println("found bug. rolling back to prev byte")
			index -= 1
			prevAvg1 = prevAvg2
			continue
		}

		prevAvg2 = prevAvg1
		prevAvg1 = avgDur

		index++
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
