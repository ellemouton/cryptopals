package set1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAESECB(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	ciphertxt := []byte("YELLOW SUBMARINE")

	plaintxt, err := DecryptAESECB([]byte(key), ciphertxt)
	require.NoError(t, err)

	ciphertxtV2, err := EncryptAESECB([]byte(key), plaintxt)
	require.NoError(t, err)

	require.Equal(t, ciphertxtV2, ciphertxt)
}
