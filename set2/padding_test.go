package set2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPKCS7Pad(t *testing.T) {
	tests := []struct {
		name           string
		blockSize      int
		input          string
		expectedOutput string
	}{
		{
			name:           "1",
			blockSize:      20,
			input:          "YELLOW SUBMARINE",
			expectedOutput: "YELLOW SUBMARINE\x04\x04\x04\x04",
		},
		{
			name:           "2",
			blockSize:      21,
			input:          "YELLOW SUBMARINE",
			expectedOutput: "YELLOW SUBMARINE\x05\x05\x05\x05\x05",
		},
		{
			name:           "3",
			blockSize:      3,
			input:          "YELLOW SUBMARINE",
			expectedOutput: "YELLOW SUBMARINE\x02\x02",
		},
		{
			name:           "4",
			blockSize:      16,
			input:          "admin",
			expectedOutput: "admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expectedOutput, string(PKCS7Pad([]byte(test.input), test.blockSize)))
		})
	}
}

func TestPKCS7PadValidation(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectValid    bool
		expectStripped string
	}{
		{
			name:           "1",
			input:          "ICE ICE BABY\x04\x04\x04\x04",
			expectValid:    true,
			expectStripped: "ICE ICE BABY",
		},
		{
			name:        "2",
			input:       "ICE ICE BABY\x05\x05\x05\x05",
			expectValid: false,
		},
		{
			name:        "3",
			input:       "ICE ICE BABY\x01\x02\x03\x04",
			expectValid: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			valid, stripped := ValidateAndStripPKCS7Pad([]byte(test.input))
			require.Equal(t, test.expectValid, valid)
			require.Equal(t, test.expectStripped, string(stripped))
		})
	}
}
