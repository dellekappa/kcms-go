package rawsignature

import (
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
)

// getECDSAParamNames returns the string representations of each parameter in
// the given ECDSAParams.
func getECDSAParamNames(params *ecdsapb.EcdsaParams) (string, string, string) {
	hashName := commonpb.HashType_name[int32(params.GetHashType())]
	curveName := commonpb.EllipticCurveType_name[int32(params.GetCurve())]
	encodingName := ecdsapb.EcdsaSignatureEncoding_name[int32(params.GetEncoding())]
	return hashName, curveName, encodingName
}

// newECDSAPrivateKey creates a ECDSAPrivateKey with the specified paramaters.
func newECDSAPrivateKey(version uint32, publicKey *ecdsapb.EcdsaPublicKey, keyValue []byte) *ecdsapb.EcdsaPrivateKey {
	return &ecdsapb.EcdsaPrivateKey{
		Version:   version,
		PublicKey: publicKey,
		KeyValue:  keyValue,
	}
}

// newECDSAPublicKey creates a ECDSAPublicKey with the specified paramaters.
func newECDSAPublicKey(version uint32, params *ecdsapb.EcdsaParams, x, y []byte) *ecdsapb.EcdsaPublicKey {
	return &ecdsapb.EcdsaPublicKey{
		Version: version,
		Params:  params,
		X:       x,
		Y:       y,
	}
}
