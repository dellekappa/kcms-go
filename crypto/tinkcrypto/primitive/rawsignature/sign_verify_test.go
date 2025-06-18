package rawsignature

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"github.com/dellekappa/kcms-go/crypto/tinkcrypto"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
	"testing"
)

func TestRawECDSAP256Signature(t *testing.T) {

	keyTemplate := ECDSAP256KeyWithoutPrefixTemplate()

	// Create a new keyset handle with the key template.
	kh, err := keyset.NewHandle(keyTemplate)
	if err != nil {
		t.Fatalf("failed to create keyset handle: %v", err)
	}

	signerProvider := &tinkcrypto.SignerProvider{}
	priv, err := signerProvider.Signer(kh)
	if err != nil {
		t.Fatalf("failed to convert to private key: %v", err)
	}

	msg := []byte("test message")

	hash := sha256.New()
	_, err = hash.Write(msg)
	if err != nil {
		t.Fatalf("failed to hash message: %v", err)
	}
	digest := hash.Sum(nil)

	signature1, err := priv.Sign(rand.Reader, digest, nil)
	if err != nil {
		t.Fatalf("failed to sign message with private key: %v", err)
	}

	signer, err := signature.NewSigner(kh)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	signature2, err := signer.Sign(digest)
	if err != nil {
		t.Fatalf("failed to sign message with tink signer: %v", err)
	}

	pub := priv.Public().(*ecdsa.PublicKey)

	//Both signatures can be verified using the native ECDSA verification method.
	if !ecdsa.VerifyASN1(pub, digest, signature1) {
		t.Fatal("x509: ECDSA verification 1 failure")
	}

	if !ecdsa.VerifyASN1(pub, digest, signature2) {
		t.Fatal("x509: ECDSA verification 2 failure")
	}
}
