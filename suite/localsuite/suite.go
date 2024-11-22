/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package localsuite

import (
	"github.com/dellekappa/kcms-go/doc/jose/jwk"
	suiteapi "github.com/dellekappa/kcms-go/suite/api"
)

type suiteImpl struct {
	kms    keyManager
	cms    certManager
	crypto allCrypto
}

func (s *suiteImpl) KeyCreator() (suiteapi.KeyCreator, error) {
	return newKeyCreator(s.kms), nil
}

func (s *suiteImpl) RawKeyCreator() (suiteapi.RawKeyCreator, error) {
	return newKeyCreator(s.kms), nil
}

func (s *suiteImpl) KMSCrypto() (suiteapi.KMSCrypto, error) {
	return newKMSCrypto(s.kms, s.crypto), nil
}

func (s *suiteImpl) KMSCryptoSigner() (suiteapi.KMSCryptoSigner, error) {
	return newKMSCryptoSigner(s.kms, s.crypto), nil
}

func (s *suiteImpl) KMSCryptoMultiSigner() (suiteapi.KMSCryptoMultiSigner, error) {
	return newKMSCryptoMultiSigner(s.kms, s.crypto), nil
}

func (s *suiteImpl) KMSCryptoVerifier() (suiteapi.KMSCryptoVerifier, error) {
	return newKMSCrypto(s.kms, s.crypto), nil
}

func (s *suiteImpl) CMSCertIssuer() (suiteapi.CMSCertIssuer, error) {
	return newCMSCertIssuer(s.kms, s.cms), nil
}

func (s *suiteImpl) EncrypterDecrypter() (suiteapi.EncrypterDecrypter, error) {
	return newEncrypterDecrypter(s.kms, s.crypto), nil
}

func (s *suiteImpl) FixedKeyCrypto(pub *jwk.JWK) (suiteapi.FixedKeyCrypto, error) {
	return makeFixedKeyCrypto(s.kms, s.crypto, pub)
}

func (s *suiteImpl) FixedKeySigner(kid string) (suiteapi.FixedKeySigner, error) {
	return makeFixedKeySigner(s.kms, s.crypto, kid)
}

func (s *suiteImpl) FixedKeyMultiSigner(kid string) (suiteapi.FixedKeyMultiSigner, error) {
	return getFixedMultiSigner(s.kms, s.crypto, kid)
}

func (s *suiteImpl) FixedKeyCertIssuer(kid string) (suiteapi.FixedKeyCertIssuer, error) {
	return makeFixedKeyCertIssuer(s.kms, s.cms, kid)
}
