package rawsignature

import (
	"fmt"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

// This file contains pre-generated KeyTemplates for Signer and Verifier.
// One can use these templates to generate new Keysets.

// ECDSAP256KeyTemplate is a KeyTemplate that generates a new ECDSA private key with the following parameters:
//   - Hash function: SHA256
//   - Curve: NIST P-256
//   - Signature encoding: DER
//   - Output prefix type: TINK
func ECDSAP256KeyTemplate() *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		ecdsapb.EcdsaSignatureEncoding_DER,
		tinkpb.OutputPrefixType_TINK)
}

// ECDSAP256KeyWithoutPrefixTemplate is a KeyTemplate that generates a new ECDSA private key with the following
// parameters:
//   - Hash function: SHA256
//   - Curve: NIST P-256
//   - Signature encoding: DER
//   - Output prefix type: RAW
//
// Note that this template uses a different encoding than ESDSA_P256_RAW in Tinkey.
func ECDSAP256KeyWithoutPrefixTemplate() *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		ecdsapb.EcdsaSignatureEncoding_DER,
		tinkpb.OutputPrefixType_RAW)
}

// ECDSAP256RawKeyTemplate is a KeyTemplate that generates a new ECDSA private key with the following
// parameters:
//   - Hash function: SHA256
//   - Curve: NIST P-256
//   - Signature encoding: IEEE_P1363
//   - Output prefix type: RAW
func ECDSAP256RawKeyTemplate() *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
		tinkpb.OutputPrefixType_RAW)
}

// ECDSAP384SHA384KeyTemplate is a KeyTemplate that generates a new ECDSA private key with the following parameters:
//   - Hash function: SHA384
//   - Curve: NIST P-384
//   - Signature encoding: DER
//   - Output prefix type: TINK
func ECDSAP384SHA384KeyTemplate() *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(commonpb.HashType_SHA384,
		commonpb.EllipticCurveType_NIST_P384,
		ecdsapb.EcdsaSignatureEncoding_DER,
		tinkpb.OutputPrefixType_TINK)
}

// ECDSAP384SHA384KeyWithoutPrefixTemplate is a KeyTemplate that generates a new ECDSA private key with the following parameters:
//   - Hash function: SHA384
//   - Curve: NIST P-384
//   - Signature encoding: DER
//   - Output prefix type: RAW
func ECDSAP384SHA384KeyWithoutPrefixTemplate() *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(commonpb.HashType_SHA384,
		commonpb.EllipticCurveType_NIST_P384,
		ecdsapb.EcdsaSignatureEncoding_DER,
		tinkpb.OutputPrefixType_RAW)
}

// ECDSAP384SHA512KeyTemplate is a KeyTemplate that generates a new ECDSA private key with the following parameters:
//   - Hash function: SHA512
//   - Curve: NIST P-384
//   - Signature encoding: DER
//   - Output prefix type: TINK
func ECDSAP384SHA512KeyTemplate() *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P384,
		ecdsapb.EcdsaSignatureEncoding_DER,
		tinkpb.OutputPrefixType_TINK)
}

// ECDSAP384KeyWithoutPrefixTemplate is a KeyTemplate that generates a new ECDSA private key with the following
// parameters:
//   - Hash function: SHA512
//   - Curve: NIST P-384
//   - Signature encoding: DER
//   - Output prefix type: RAW
func ECDSAP384KeyWithoutPrefixTemplate() *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P384,
		ecdsapb.EcdsaSignatureEncoding_DER,
		tinkpb.OutputPrefixType_RAW)
}

// ECDSAP521KeyTemplate is a KeyTemplate that generates a new ECDSA private key with the following parameters:
//   - Hash function: SHA512
//   - Curve: NIST P-521
//   - Signature encoding: DER
//   - Output prefix type: TINK
func ECDSAP521KeyTemplate() *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		ecdsapb.EcdsaSignatureEncoding_DER,
		tinkpb.OutputPrefixType_TINK)
}

// ECDSAP521KeyWithoutPrefixTemplate is a KeyTemplate that generates a new ECDSA private key with the following
// parameters:
//   - Hash function: SHA512
//   - Curve: NIST P-521
//   - Signature encoding: DER
//   - Output prefix type: RAW
func ECDSAP521KeyWithoutPrefixTemplate() *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(commonpb.HashType_SHA512,
		commonpb.EllipticCurveType_NIST_P521,
		ecdsapb.EcdsaSignatureEncoding_DER,
		tinkpb.OutputPrefixType_RAW)
}

// createECDSAKeyTemplate creates a KeyTemplate containing an EcdsaKeyFormat
// with the given parameters.
func createECDSAKeyTemplate(hashType commonpb.HashType, curve commonpb.EllipticCurveType, encoding ecdsapb.EcdsaSignatureEncoding, prefixType tinkpb.OutputPrefixType) *tinkpb.KeyTemplate {
	params := &ecdsapb.EcdsaParams{
		HashType: hashType,
		Curve:    curve,
		Encoding: encoding,
	}
	format := &ecdsapb.EcdsaKeyFormat{Params: params}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal key format: %s", err))
	}
	return &tinkpb.KeyTemplate{
		TypeUrl:          ecdsaRawSignerTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: prefixType,
	}
}
