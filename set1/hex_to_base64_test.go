package set1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHexToBase64(t *testing.T) {
	tests := []struct {
		name               string
		hex                string
		expectBase64String string
	}{
		{
			name:               "1",
			hex:                "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
			expectBase64String: "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := HexToBase64(test.hex)
			require.NoError(t, err)
			require.Equal(t, test.expectBase64String, res)
		})
	}
}
