package subtle

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	sigsubtle "github.com/tink-crypto/tink-go/v2/signature/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle"
)

// ECDSARawSigner is an implementation of Signer for ECDSA.
// At the moment, the implementation only accepts DER encoding.
type ECDSARawSigner struct {
	privateKey *ecdsa.PrivateKey
	encoding   string
}

func NewECDSARawSigner(curve, encoding string, keyValue []byte) (*ECDSARawSigner, error) {
	privKey := new(ecdsa.PrivateKey)
	c := subtle.GetCurve(curve)
	if c == nil {
		return nil, errors.New("ecdsa_raw_signer: invalid curve")
	}
	privKey.PublicKey.Curve = c
	privKey.D = new(big.Int).SetBytes(keyValue)
	privKey.PublicKey.X, privKey.PublicKey.Y = c.ScalarBaseMult(keyValue)
	return NewECDSARawSignerFromPrivateKey(encoding, privKey)
}

// NewECDSARawSignerFromPrivateKey creates a new instance of ECDSARawSigner
func NewECDSARawSignerFromPrivateKey(encoding string, privateKey *ecdsa.PrivateKey) (*ECDSARawSigner, error) {
	if privateKey.Curve == nil {
		return nil, errors.New("ecdsa_raw_signer: privateKey.Curve can't be nil")
	}
	curve := subtle.ConvertCurveName(privateKey.Curve.Params().Name)
	if err := ValidateECDSAParams(curve, encoding); err != nil {
		return nil, fmt.Errorf("ecdsa_raw_signer: %s", err)
	}
	return &ECDSARawSigner{
		privateKey: privateKey,
		encoding:   encoding,
	}, nil
}

// Sign computes a signature for the given data.
func (e *ECDSARawSigner) Sign(data []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, e.privateKey, data)
	if err != nil {
		return nil, fmt.Errorf("ecdsa_signer: signing failed: %s", err)
	}
	// format the signature
	sig := sigsubtle.NewECDSASignature(r, s)
	ret, err := sig.EncodeECDSASignature(e.encoding, e.privateKey.PublicKey.Curve.Params().Name)
	if err != nil {
		return nil, fmt.Errorf("ecdsa_signer: signing failed: %s", err)
	}
	return ret, nil
}
