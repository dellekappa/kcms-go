/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package websuite

import (
	"crypto/x509"
	"github.com/dellekappa/kcms-go/cms/webcms"
	webcrypto "github.com/dellekappa/kcms-go/crypto/webkms"
	"github.com/dellekappa/kcms-go/kms/webkms"
)

func makeFixedKeyKMSCrypto(
	keyID string,
	keyGetter *webkms.RemoteKMS,
	crypto *webcrypto.RemoteCrypto,
) (*fixedKeyKMSCrypto, error) {
	keyURL, err := keyGetter.Get(keyID)
	if err != nil {
		return nil, err
	}

	return &fixedKeyKMSCrypto{
		keyURL: keyURL,
		cr:     crypto,
	}, nil
}

type fixedKeyKMSCrypto struct {
	keyURL interface{}
	cr     *webcrypto.RemoteCrypto
}

func (f *fixedKeyKMSCrypto) Sign(msg []byte) ([]byte, error) {
	return f.cr.Sign(msg, f.keyURL)
}

func (f *fixedKeyKMSCrypto) SignMulti(msgs [][]byte) ([]byte, error) {
	return f.cr.SignMulti(msgs, f.keyURL)
}

func (f *fixedKeyKMSCrypto) Verify(sig, msg []byte) error {
	return f.cr.Verify(sig, msg, f.keyURL)
}

func makeFixedKeyCMS(
	keyID string,
	keyGetter *webkms.RemoteKMS,
	cms *webcms.RemoteCMS,
) (*fixedKeyCMS, error) {
	keyURL, err := keyGetter.Get(keyID)
	if err != nil {
		return nil, err
	}

	return &fixedKeyCMS{
		keyURL: keyURL,
		cms:    cms,
	}, nil
}

type fixedKeyCMS struct {
	keyURL interface{}
	cms    *webcms.RemoteCMS
}

func (f *fixedKeyCMS) IssueCertificate(template *x509.Certificate) (*x509.Certificate, error) {
	_, cert, err := f.cms.IssueCertificate(template, f.keyURL)
	return cert, err
}
