/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/mac"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/signature"

	"github.com/dellekappa/kms-go/spi/kms"

	"github.com/dellekappa/kms-go/crypto/tinkcrypto/primitive/bbs"
	"github.com/dellekappa/kms-go/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/dellekappa/kms-go/crypto/tinkcrypto/primitive/secp256k1"
)

// nolint:gocyclo,funlen
func keyTemplate(keyType kms.KeyType, _ ...kms.KeyOpts) (*tinkpb.KeyTemplate, error) {
	switch keyType {
	case kms.AES128GCMType:
		return aead.AES128GCMKeyTemplate(), nil
	case kms.AES256GCMNoPrefixType:
		// RAW (to support keys not generated by Tink)
		return aead.AES256GCMNoPrefixKeyTemplate(), nil
	case kms.AES256GCMType:
		return aead.AES256GCMKeyTemplate(), nil
	case kms.ChaCha20Poly1305Type:
		return aead.ChaCha20Poly1305KeyTemplate(), nil
	case kms.XChaCha20Poly1305Type:
		return aead.XChaCha20Poly1305KeyTemplate(), nil
	case kms.RSARS256Type:
		return signature.RSA_SSA_PKCS1_3072_SHA256_F4_RAW_Key_Template(), nil
	case kms.ECDSAP256TypeDER:
		return signature.ECDSAP256KeyWithoutPrefixTemplate(), nil
	case kms.ECDSAP384TypeDER:
		// Since Tink's signature.ECDSAP384KeyWithoutPrefixTemplate() uses SHA_512 as the hashing function during
		// signature/verification, the kms type must explicitly use SHA_384 just as IEEEP384 key template below.
		// For this reason, the KMS cannot use Tink's `signature.ECDSAP384KeyWithoutPrefixTemplate()` template here.
		return createECDSAKeyTemplate(ecdsapb.EcdsaSignatureEncoding_DER, commonpb.HashType_SHA384,
			commonpb.EllipticCurveType_NIST_P384), nil
	case kms.ECDSAP521TypeDER:
		return signature.ECDSAP521KeyWithoutPrefixTemplate(), nil
	case kms.ECDSAP256TypeIEEEP1363:
		// JWS keys should sign using IEEE_P1363 format only (not DER format)
		return createECDSAIEEE1363KeyTemplate(commonpb.HashType_SHA256, commonpb.EllipticCurveType_NIST_P256), nil
	case kms.ECDSAP384TypeIEEEP1363:
		return createECDSAIEEE1363KeyTemplate(commonpb.HashType_SHA384, commonpb.EllipticCurveType_NIST_P384), nil
	case kms.ECDSAP521TypeIEEEP1363:
		return createECDSAIEEE1363KeyTemplate(commonpb.HashType_SHA512, commonpb.EllipticCurveType_NIST_P521), nil
	case kms.ED25519Type:
		return signature.ED25519KeyWithoutPrefixTemplate(), nil
	case kms.HMACSHA256Tag256Type:
		return mac.HMACSHA256Tag256KeyTemplate(), nil
	case kms.NISTP256ECDHKWType:
		return ecdh.NISTP256ECDHKWKeyTemplate(), nil
	case kms.NISTP384ECDHKWType:
		return ecdh.NISTP384ECDHKWKeyTemplate(), nil
	case kms.NISTP521ECDHKWType:
		return ecdh.NISTP521ECDHKWKeyTemplate(), nil
	case kms.X25519ECDHKWType:
		return ecdh.X25519ECDHKWKeyTemplate(), nil
	case kms.BLS12381G2Type:
		return bbs.BLS12381G2KeyTemplate(), nil
	case kms.ECDSASecp256k1DER:
		return secp256k1.DERKeyTemplate()
	case kms.ECDSASecp256k1IEEEP1363:
		return secp256k1.IEEEP1363KeyTemplate()
	default:
		return nil, fmt.Errorf("getKeyTemplate: key type '%s' unrecognized", keyType)
	}
}

func createECDSAIEEE1363KeyTemplate(hashType commonpb.HashType, curve commonpb.EllipticCurveType) *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(ecdsapb.EcdsaSignatureEncoding_IEEE_P1363, hashType, curve)
}

func createECDSAKeyTemplate(sigEncoding ecdsapb.EcdsaSignatureEncoding, hashType commonpb.HashType,
	curve commonpb.EllipticCurveType) *tinkpb.KeyTemplate {
	params := &ecdsapb.EcdsaParams{
		HashType: hashType,
		Curve:    curve,
		Encoding: sigEncoding,
	}
	format := &ecdsapb.EcdsaKeyFormat{Params: params}
	serializedFormat, _ := proto.Marshal(format) //nolint:errcheck

	return &tinkpb.KeyTemplate{
		TypeUrl:          ecdsaPrivateKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}
