/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package suite contains mocks for kms+crypto wrapper suite.
package suite

import (
	"github.com/dellekappa/kcms-go/doc/jose/jwk"
	"github.com/dellekappa/kcms-go/mock/wrapper"
	"github.com/dellekappa/kcms-go/suite/api"
)

// MockSuite mocks api.Suite.
type MockSuite struct {
	KMS *wrapper.MockKMSCrypto
	CMS *wrapper.MockCMS
}

// KMSCrypto mock.
func (m *MockSuite) KMSCrypto() (api.KMSCrypto, error) {
	return m.KMS, nil
}

// KeyCreator mock.
func (m *MockSuite) KeyCreator() (api.KeyCreator, error) {
	return m.KMS, nil
}

// RawKeyCreator mock.
func (m *MockSuite) RawKeyCreator() (api.RawKeyCreator, error) {
	return m.KMS, nil
}

// KMSCryptoSigner mock.
func (m *MockSuite) KMSCryptoSigner() (api.KMSCryptoSigner, error) {
	return m.KMS, nil
}

// CMSCertIssuer mock.
func (m *MockSuite) CMSCertIssuer() (api.CMSCertIssuer, error) {
	return m.CMS, nil
}

// CMSCertGetter mock.
func (m *MockSuite) CMSCertGetter() (api.CMSCertGetter, error) {
	return m.CMS, nil
}

// KMSCryptoVerifier mock.
func (m *MockSuite) KMSCryptoVerifier() (api.KMSCryptoVerifier, error) {
	return m.KMS, nil
}

// KMSCryptoMultiSigner mock.
func (m *MockSuite) KMSCryptoMultiSigner() (api.KMSCryptoMultiSigner, error) {
	return m.KMS, nil
}

// EncrypterDecrypter mock.
func (m *MockSuite) EncrypterDecrypter() (api.EncrypterDecrypter, error) {
	return m.KMS, nil
}

// FixedKeyCrypto mock.
func (m *MockSuite) FixedKeyCrypto(pub *jwk.JWK) (api.FixedKeyCrypto, error) {
	return m.KMS.FixedKeyCrypto(pub)
}

// FixedKeySigner mock.
func (m *MockSuite) FixedKeySigner(kid string) (api.FixedKeySigner, error) {
	return m.KMS.FixedKeySigner(nil)
}

// FixedKeyMultiSigner mock.
func (m *MockSuite) FixedKeyMultiSigner(kid string) (api.FixedKeyMultiSigner, error) {
	return m.KMS.FixedKeyMultiSigner(nil)
}

// FixedKeyCertIssuer mock.
func (m *MockSuite) FixedKeyCertIssuer(kid string) (api.FixedKeyCertIssuer, error) {
	return m.CMS.FixedKeyCertIssuer(nil)
}

var _ api.Suite = &MockSuite{}
