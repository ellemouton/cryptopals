package set2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAESCBC(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	plaintxt := []byte("YELLOW SUBMARINE")
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	ciphertxt, err := CBCEncrypt(plaintxt, []byte(key), iv)
	require.NoError(t, err)

	plaintxtV2, err := CBCDecrypt(ciphertxt, []byte(key), iv)
	require.NoError(t, err)

	require.Equal(t, plaintxtV2, plaintxt)
}
