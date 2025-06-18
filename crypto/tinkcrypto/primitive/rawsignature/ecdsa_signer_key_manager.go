package rawsignature

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/subtle"
	"google.golang.org/protobuf/proto"

	subtleSignature "github.com/dellekappa/kcms-go/crypto/tinkcrypto/primitive/rawsignature/subtle"
)

const (
	ecdsaRawSignerKeyVersion = 0
	ecdsaRawSignerTypeURL    = "type.googleapis.com/google.crypto.tink.raw.EcdsaPrivateKey"
)

var errInvalidECDSASignKey = errors.New("ecdsa_raw_signer_key_manager: invalid key")
var errInvalidECDSASignKeyFormat = errors.New("ecdsa_raw_signer_key_manager: invalid key format")

type ecdsaRawSignerKeyManager struct{}

func (km *ecdsaRawSignerKeyManager) Primitive(serializedKey []byte) (interface{}, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidECDSASignKey
	}
	key := new(ecdsapb.EcdsaPrivateKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidECDSASignKey
	}
	if err := km.validateKey(key); err != nil {
		return nil, err
	}
	_, curve, encoding := getECDSAParamNames(key.GetPublicKey().GetParams())
	ret, err := subtleSignature.NewECDSARawSigner(curve, encoding, key.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("ecdsa_raw_signer_key_manager: %s", err)
	}
	return ret, nil
}

func (km *ecdsaRawSignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidECDSASignKeyFormat
	}
	keyFormat := new(ecdsapb.EcdsaKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, fmt.Errorf("ecdsa_raw_signer_key_manager: invalid proto: %s", err)
	}
	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("ecdsa_raw_signer_key_manager: invalid key format: %s", err)
	}
	// generate key
	params := keyFormat.GetParams()
	curve := commonpb.EllipticCurveType_name[int32(params.Curve)]
	tmpKey, err := ecdsa.GenerateKey(subtle.GetCurve(curve), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa_raw_signer_key_manager: cannot generate ECDSA key: %s", err)
	}

	keyValue := tmpKey.D.Bytes()
	pub := newECDSAPublicKey(ecdsaRawSignerKeyVersion, params, tmpKey.X.Bytes(), tmpKey.Y.Bytes())
	priv := newECDSAPrivateKey(ecdsaRawSignerKeyVersion, pub, keyValue)
	return priv, nil
}

func (km *ecdsaRawSignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}
	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, errInvalidECDSASignKeyFormat
	}
	return &tinkpb.KeyData{
		TypeUrl:         ecdsaRawSignerTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

// PublicKeyData extracts the public key data from the private key.
func (km *ecdsaRawSignerKeyManager) PublicKeyData(serializedPrivKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdsapb.EcdsaPrivateKey)
	if err := proto.Unmarshal(serializedPrivKey, privKey); err != nil {
		return nil, errInvalidECDSASignKey
	}
	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidECDSASignKey
	}
	return &tinkpb.KeyData{
		TypeUrl:         ecdsaRawVerifierTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

func (km *ecdsaRawSignerKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == ecdsaRawSignerTypeURL
}

func (km *ecdsaRawSignerKeyManager) TypeURL() string {
	return ecdsaRawSignerTypeURL
}

// validateKey validates the given ECDSAPrivateKey.
func (km *ecdsaRawSignerKeyManager) validateKey(key *ecdsapb.EcdsaPrivateKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, ecdsaRawSignerKeyVersion); err != nil {
		return fmt.Errorf("ecdsa_raw_signer_key_manager: invalid key: %s", err)
	}
	_, curve, encoding := getECDSAParamNames(key.GetPublicKey().GetParams())
	return subtleSignature.ValidateECDSAParams(curve, encoding)
}

// validateKeyFormat validates the given ECDSAKeyFormat.
func (km *ecdsaRawSignerKeyManager) validateKeyFormat(format *ecdsapb.EcdsaKeyFormat) error {
	_, curve, encoding := getECDSAParamNames(format.GetParams())
	return subtleSignature.ValidateECDSAParams(curve, encoding)
}
