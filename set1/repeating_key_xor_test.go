package set1

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRepeatingKeyEncrypt(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		key       string
		expectOut string
	}{
		{
			name: "1",
			input: "Burning 'em, if you ain't quick and nimble\n" +
				"I go crazy when I hear a cymbal",
			key: "ICE",
			expectOut: "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527" +
				"2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := RepeatingKeyEncrypt([]byte(test.input), []byte(test.key))
			require.NoError(t, err)

			require.Equal(t, test.expectOut, hex.EncodeToString(res))
		})
	}
}

func TestEditDistance(t *testing.T) {
	tests := []struct {
		name             string
		a                string
		b                string
		expectedDistance int
	}{
		{
			name:             "1",
			a:                "this is a test",
			b:                "wokka wokka!!!",
			expectedDistance: 37,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := EditDistance([]byte(test.a), []byte(test.b))
			require.NoError(t, err)
			require.Equal(t, test.expectedDistance, res)
		})
	}
}
