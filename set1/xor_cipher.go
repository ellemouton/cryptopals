package set1

import (
	"math"
	"strings"
)

func FindSingleByteXOR(bytes []byte) (*byte, float64, error) {
	smallestScore := math.MaxFloat64
	var closestFit byte

	// Loop through each possible char (1 byte per char)
	for char := 0; char < 256; char++ {
		test := []byte{}
		for i := 0; i < len([]byte(bytes)); i++ {
			test = append(test, byte(char))
		}

		res, err := FixedXOR(bytes, test)
		if err != nil {
			return nil, 0, err
		}

		score := ScoreText(string(res))

		if score < smallestScore {
			smallestScore = score
			closestFit = byte(char)
		}
	}

	return &closestFit, smallestScore, nil
}

// Smaller score means better match
func ScoreText(text string) float64 {
	trained := FrequencyMap(defaultTrainingData)
	current := FrequencyMap(text)

	var score float64

	for k, _ := range trained {
		score += math.Abs(trained[k] - current[k])
	}

	return score
}

const defaultTrainingData = `Routing hints are important for nodes that only have private channels (channels that are not announced to the network and ie are not intended to be used for routing). For these nodes, when they create an invoicce (ie: someone intends to pay them) they need to include routing hints in the invoice so that the payer can construct a path to the recipient. 
Yes I would say they do leak privacy since they include the short channel ID of the channel and so now anyone with the invoice knows which tx on the blockchain is linked to the channel.
`

func FrequencyMap(source string) map[byte]float64 {
	source = strings.ToUpper(source)

	b := []byte(source)
	m := make(map[byte]int)
	totalCount := 0
	for _, char := range b {
		m[char]++
		totalCount++
	}

	// Normalize the map
	n := make(map[byte]float64)
	for k, v := range m {
		n[k] = float64(v) / float64(totalCount)
	}

	return n
}
