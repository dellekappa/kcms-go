/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package websuite provides a wrapper.Suite implemented using web kms and web crypto clients.
package websuite

import (
	"github.com/dellekappa/kcms-go/cms/webcms"
	"net/http"

	webcrypto "github.com/dellekappa/kcms-go/crypto/webkms"
	"github.com/dellekappa/kcms-go/doc/jose/jwk"
	"github.com/dellekappa/kcms-go/kms/webkms"
	suiteapi "github.com/dellekappa/kcms-go/suite/api"
)

// NewWebCryptoSuite initializes an api.Suite using web kms and crypto
// clients, supporting all Suite APIs.
func NewWebCryptoSuite(endpoint string, httpClient *http.Client) suiteapi.Suite {
	km := webkms.New(endpoint, httpClient)
	cr := webcrypto.New(endpoint, httpClient)
	cm := webcms.New()

	return &suite{
		km: km,
		cm: cm,
		cr: cr,
	}
}

type suite struct {
	km *webkms.RemoteKMS
	cm *webcms.RemoteCMS
	cr *webcrypto.RemoteCrypto
}

func (s *suite) KMSCryptoVerifier() (suiteapi.KMSCryptoVerifier, error) {
	return &kmsCrypto{
		km: s.km,
		cr: s.cr,
	}, nil
}

func (s *suite) KeyCreator() (suiteapi.KeyCreator, error) {
	return &kmsCrypto{
		km: s.km,
		cr: s.cr,
	}, nil
}

func (s *suite) KMSCrypto() (suiteapi.KMSCrypto, error) {
	return &kmsCrypto{
		km: s.km,
		cr: s.cr,
	}, nil
}

func (s *suite) FixedKeyCrypto(pub *jwk.JWK) (suiteapi.FixedKeyCrypto, error) {
	return makeFixedKeyKMSCrypto(pub.KeyID, s.km, s.cr)
}

func (s *suite) RawKeyCreator() (suiteapi.RawKeyCreator, error) {
	return &kmsCrypto{
		km: s.km,
		cr: s.cr,
	}, nil
}

func (s *suite) KMSCryptoSigner() (suiteapi.KMSCryptoSigner, error) {
	return &kmsCrypto{
		km: s.km,
		cr: s.cr,
	}, nil
}

func (s *suite) CMSCertIssuer() (suiteapi.CMSCertIssuer, error) {
	return &cmsImpl{
		km: s.km,
		cm: s.cm,
	}, nil
}

func (s *suite) FixedKeySigner(kid string) (suiteapi.FixedKeySigner, error) {
	return makeFixedKeyKMSCrypto(kid, s.km, s.cr)
}

func (s *suite) KMSCryptoMultiSigner() (suiteapi.KMSCryptoMultiSigner, error) {
	return &kmsCrypto{
		km: s.km,
		cr: s.cr,
	}, nil
}

func (s *suite) FixedKeyMultiSigner(kid string) (suiteapi.FixedKeyMultiSigner, error) {
	return makeFixedKeyKMSCrypto(kid, s.km, s.cr)
}

func (s *suite) FixedKeyCertIssuer(kid string) (suiteapi.FixedKeyCertIssuer, error) {
	return makeFixedKeyCMS(kid, s.km, s.cm)
}

func (s *suite) EncrypterDecrypter() (suiteapi.EncrypterDecrypter, error) {
	return &kmsCrypto{
		km: s.km,
		cr: s.cr,
	}, nil
}
