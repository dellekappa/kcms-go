package subtle

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	sigsubtle "github.com/tink-crypto/tink-go/v2/signature/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle"
)

var errInvalidECDSASignature = errors.New("ecdsa_digest_verifier: invalid signature")

// ECDSARawVerifier is an implementation of Verifier for ECDSA.
// At the moment, the implementation only accepts signatures with strict DER encoding.
type ECDSARawVerifier struct {
	publicKey *ecdsa.PublicKey
	encoding  string
}

// NewECDSARawVerifier creates a new instance of ECDSARawVerifier.
func NewECDSARawVerifier(curve string, encoding string, x []byte, y []byte) (*ECDSARawVerifier, error) {
	publicKey := &ecdsa.PublicKey{
		Curve: subtle.GetCurve(curve),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	return NewECDSARawVerifierFromPublicKey(encoding, publicKey)
}

// NewECDSARawVerifierFromPublicKey creates a new instance of ECDSARawVerifier.
func NewECDSARawVerifierFromPublicKey(encoding string, publicKey *ecdsa.PublicKey) (*ECDSARawVerifier, error) {
	if publicKey.Curve == nil {
		return nil, errors.New("ecdsa_raw_verifier: invalid curve")
	}
	if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return nil, fmt.Errorf("ecdsa_raw_verifier: invalid public key")
	}
	curve := subtle.ConvertCurveName(publicKey.Curve.Params().Name)
	if err := ValidateECDSAParams(curve, encoding); err != nil {
		return nil, fmt.Errorf("ecdsa_raw_verifier: %s", err)
	}
	return &ECDSARawVerifier{
		publicKey: publicKey,
		encoding:  encoding,
	}, nil
}

// Verify verifies whether the given signature is valid for the given data.
// It returns an error if the signature is not valid; nil otherwise.
func (e *ECDSARawVerifier) Verify(signatureBytes, data []byte) error {
	signature, err := sigsubtle.DecodeECDSASignature(signatureBytes, e.encoding)
	if err != nil {
		return fmt.Errorf("ecdsa_raw_verifier: %s", err)
	}
	valid := ecdsa.Verify(e.publicKey, data, signature.R, signature.S)
	if !valid {
		return errInvalidECDSASignature
	}
	return nil
}
