package set4

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHMACSHA1(t *testing.T) {
	key := []byte("key")
	data := []byte("The quick brown fox jumps over the lazy dog")

	res, err := HMACSHA1(key, data)
	require.NoError(t, err)

	require.Equal(t, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9", hex.EncodeToString(res))
}
