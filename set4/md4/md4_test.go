package md4

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMD4(t *testing.T) {
	tests := []struct {
		input  string
		output string
	}{
		{
			input:  "",
			output: "31d6cfe0d16ae931b73c59d7e0c089c0",
		},
		{
			input:  "a",
			output: "bde52cb31de33e46245e05fbdbd6fb24",
		},
		{
			input:  "abc",
			output: "a448017aaf21d8525fc10ae87aa6729d",
		},
		{
			input:  "message digest",
			output: "d9130a8164549fe818874806e1c7014b",
		},
		{
			input:  "abcdefghijklmnopqrstuvwxyz",
			output: "d79e1c308aa5bbcdeea8ed63df412da9",
		},
		{
			input:  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			output: "043f8582f241db351ce627e153e7f0e4",
		},
		{
			input:  "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
			output: "e33b4ddc9c38f2199c3e7b164fcc0536",
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			res := hex.EncodeToString(Sum([]byte(test.input)))
			require.Equal(t, res, test.output)
		})
	}
}
