package set1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFixedXOR(t *testing.T) {
	tests := []struct {
		name      string
		a         string
		b         string
		expectOut string
	}{
		{
			name:      "1",
			a:         "1c0111001f010100061a024b53535009181c",
			b:         "686974207468652062756c6c277320657965",
			expectOut: "746865206b696420646f6e277420706c6179",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := HexStrFixedXOR(test.a, test.b)
			require.NoError(t, err)
			require.Equal(t, test.expectOut, res)
		})
	}
}
