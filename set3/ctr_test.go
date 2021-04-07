package set3

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCTR(t *testing.T) {
	tests := []struct {
		name  string
		ct    string
		pt    string
		key   []byte
		nonce int64
	}{
		{
			name:  "1",
			key:   []byte("YELLOW SUBMARINE"),
			ct:    "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
			pt:    "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ",
			nonce: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			txt, err := base64.StdEncoding.DecodeString(test.ct)
			require.NoError(t, err)

			pt, err := CTR(test.key, txt, test.nonce)
			require.NoError(t, err)
			require.Equal(t, test.pt, string(pt))

			ct, err := CTR(test.key, pt, test.nonce)
			require.NoError(t, err)
			require.Equal(t, string(txt), string(ct))
		})
	}

}
