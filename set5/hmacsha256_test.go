package set5

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHMACSHA256(t *testing.T) {
	key := []byte("key")
	data := []byte("The quick brown fox jumps over the lazy dog")

	res, err := HMACSHA256(key, data)
	require.NoError(t, err)

	require.Equal(t, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", hex.EncodeToString(res))
}
