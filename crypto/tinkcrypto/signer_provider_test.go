package tinkcrypto

import (
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/signature"
	"testing"
)

func TestSignerProvider(t *testing.T) {
	testCases := []struct {
		name string
		kh   *keyset.Handle
	}{
		{
			name: "test with RSA PKCS1 key",
			kh:   newKeySet(t, signature.RSA_SSA_PKCS1_4096_SHA512_F4_Key_Template()),
		},
		{
			name: "test with ECDSA ECDSA P-256 key",
			kh:   newKeySet(t, signature.ECDSAP256KeyTemplate()),
		},
		{
			name: "test with Ed25519 key",
			kh:   newKeySet(t, signature.ED25519KeyTemplate()),
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			p := &SignerProvider{}

			s, err := p.Signer(tc.kh)
			require.NoError(t, err)

			require.NotNil(t, s)
		})
	}
}

func newKeySet(t *testing.T, kt *tinkpb.KeyTemplate) *keyset.Handle {
	kh, err := keyset.NewHandle(kt)
	if err != nil {
		t.Fatal(err)
	}
	return kh
}
