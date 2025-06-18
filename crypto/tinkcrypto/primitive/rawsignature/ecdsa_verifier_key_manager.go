package rawsignature

import (
	"fmt"
	"github.com/dellekappa/kcms-go/crypto/tinkcrypto/primitive/rawsignature/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

const (
	ecdsaRawVerifierKeyVersion = 0
	ecdsaRawVerifierTypeURL    = "type.googleapis.com/google.crypto.tink.raw.EcdsaPublicKey"
)

// common errors
var errInvalidECDSAVerifierKey = fmt.Errorf("ecdsa_raw_verifier_key_manager: invalid key")
var errECDSAVerifierNotImplemented = fmt.Errorf("ecdsa_raw_verifier_key_manager: not implemented")

// ecdsaRawVerifierKeyManager is an implementation of KeyManager interface.
// It doesn't support key generation.
type ecdsaRawVerifierKeyManager struct{}

// Primitive creates an ECDSAVerifier subtle for the given serialized ECDSAPublicKey proto.
func (km *ecdsaRawVerifierKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDSAVerifierKey
	}
	key := new(ecdsapb.EcdsaPublicKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidECDSAVerifierKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, fmt.Errorf("ecdsa_verifier_key_manager: %s", err)
	}
	_, curve, encoding := getECDSAParamNames(key.GetParams())
	ret, err := subtle.NewECDSARawVerifier(curve, encoding, key.X, key.Y)
	if err != nil {
		return nil, fmt.Errorf("ecdsa_raw_verifier_key_manager: invalid key: %s", err)
	}
	return ret, nil
}

// NewKey is not implemented.
func (km *ecdsaRawVerifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errECDSAVerifierNotImplemented
}

// NewKeyData creates a new KeyData according to specification in  the given
// serialized ECDSAKeyFormat. It should be used solely by the key management API.
func (km *ecdsaRawVerifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errECDSAVerifierNotImplemented
}

// DoesSupport indicates if this key manager supports the given key type.
func (km *ecdsaRawVerifierKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdsaRawVerifierTypeURL
}

// TypeURL returns the key type of keys managed by this key manager.
func (km *ecdsaRawVerifierKeyManager) TypeURL() string {
	return ecdsaRawVerifierTypeURL
}

// validateKey validates the given ECDSAPublicKey.
func (km *ecdsaRawVerifierKeyManager) validateKey(key *ecdsapb.EcdsaPublicKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, ecdsaRawVerifierKeyVersion); err != nil {
		return fmt.Errorf("ecdsa_raw_verifier_key_manager: %s", err)
	}
	_, curve, encoding := getECDSAParamNames(key.GetParams())
	return subtle.ValidateECDSAParams(curve, encoding)
}
