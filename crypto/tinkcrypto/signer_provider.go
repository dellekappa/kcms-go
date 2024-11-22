package tinkcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	"github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	"github.com/tink-crypto/tink-go/v2/proto/ed25519_go_proto"
	"github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pkcs1_go_proto"
	"github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
	"math/big"
)

const (
	rsassaSignerTypeURL  = "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey"
	ecdsaSignerTypeURL   = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
	ed25519SignerTypeURL = "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"
)

type SignerProvider struct{}

func (p *SignerProvider) Signer(kh interface{}) (crypto.Signer, error) {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, errBadKeyHandleFormat
	}

	return convertToPrivateKey(keyHandle)
}

func convertToPrivateKey(privHandle *keyset.Handle) (crypto.Signer, error) {
	keySet := insecurecleartextkeyset.KeysetMaterial(privHandle)
	var keyData *tink_go_proto.KeyData
	for _, k := range keySet.GetKey() {
		if k.KeyId == keySet.PrimaryKeyId {
			keyData = k.GetKeyData()
			break
		}
	}

	if keyData == nil {
		return nil, errors.New("no key found in keyset")
	}

	switch keyData.TypeUrl {
	case rsassaSignerTypeURL:
		// Unmarshal the RSA private key
		rsaPrivKey := &rsa_ssa_pkcs1_go_proto.RsaSsaPkcs1PrivateKey{}
		if err := proto.Unmarshal(keyData.Value, rsaPrivKey); err != nil {
			return nil, fmt.Errorf("unmarshal RSA private key: %w", err)
		}

		return convertProtoToRSAPrivateKey(rsaPrivKey)
	case ecdsaSignerTypeURL:
		// Unmarshal the ECDSA private key
		ecdsaPrivKey := &ecdsa_go_proto.EcdsaPrivateKey{}
		if err := proto.Unmarshal(keyData.Value, ecdsaPrivKey); err != nil {
			return nil, fmt.Errorf("unmarshal ECDSA private key: %w", err)
		}

		return convertProtoToECDSAPrivateKey(ecdsaPrivKey)
	case ed25519SignerTypeURL:
		// Unmarshal the ED25519 private key
		ed25519PrivKey := &ed25519_go_proto.Ed25519PrivateKey{}
		if err := proto.Unmarshal(keyData.Value, ed25519PrivKey); err != nil {
			return nil, fmt.Errorf("unmarshal ED25519 private key: %w", err)
		}

		return convertProtoToED25519PrivateKey(ed25519PrivKey)
	default:
		return nil, fmt.Errorf("unsupported key type %s", keyData.TypeUrl)
	}
}

func convertProtoToRSAPrivateKey(protoKey *rsa_ssa_pkcs1_go_proto.RsaSsaPkcs1PrivateKey) (*rsa.PrivateKey, error) {
	// Extract the private key components from the proto
	d := new(big.Int).SetBytes(protoKey.D)
	n := new(big.Int).SetBytes(protoKey.PublicKey.N)
	e := int(new(big.Int).SetBytes(protoKey.PublicKey.E).Int64())
	p := new(big.Int).SetBytes(protoKey.P)
	q := new(big.Int).SetBytes(protoKey.Q)

	// Create the RSA private key
	privKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: e,
		},
		D:      d,
		Primes: []*big.Int{p, q},
	}

	// Calculate additional private key parameters
	if err := privKey.Validate(); err != nil {
		return nil, fmt.Errorf("invalid RSA private key: %w", err)
	}

	privKey.Precompute()

	return privKey, nil

}

func convertProtoToECDSAPrivateKey(protoKey *ecdsa_go_proto.EcdsaPrivateKey) (*ecdsa.PrivateKey, error) {
	// Determine the curve based on the parameters in the proto
	var curve elliptic.Curve
	switch protoKey.PublicKey.Params.Curve {
	case common_go_proto.EllipticCurveType_NIST_P256:
		curve = elliptic.P256() // Assuming P-256; adjust based on your proto definition
	default:
		return nil, errors.New("unsupported curve type")
	}

	// Extract the D value
	d := new(big.Int).SetBytes(protoKey.KeyValue)

	// Create the ECDSA private key
	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(protoKey.PublicKey.X),
			Y:     new(big.Int).SetBytes(protoKey.PublicKey.Y),
		},
		D: d,
	}

	return privKey, nil
}

func convertProtoToED25519PrivateKey(protoKey *ed25519_go_proto.Ed25519PrivateKey) (*ed25519.PrivateKey, error) {
	// Extract the private key bytes from the proto
	seedBytes := protoKey.KeyValue

	// Validate key length
	if len(seedBytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid ED25519 private key seed size: expected %d, got %d", ed25519.SeedSize, len(seedBytes))
	}

	// Convert to ed25519.PrivateKey type
	privateKey := ed25519.NewKeyFromSeed(seedBytes)

	return &privateKey, nil

}
