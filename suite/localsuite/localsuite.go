/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package localsuite provides an api.Suite using local kms and crypto implementations.
package localsuite

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/dellekappa/kcms-go/cms/localcms"
	"github.com/dellekappa/kcms-go/crypto/tinkcrypto"
	"github.com/dellekappa/kcms-go/kms/localkms"
	cmsapi "github.com/dellekappa/kcms-go/spi/cms"
	kmsapi "github.com/dellekappa/kcms-go/spi/kms"
	"github.com/dellekappa/kcms-go/spi/secretlock"
	"github.com/dellekappa/kcms-go/suite/api"
)

// NewLocalKCMSSuite initializes a wrapper.Suite using local kms and crypto
// implementations, supporting all Suite APIs.
func NewLocalKCMSSuite(
	primaryKeyURI string,
	keyStore kmsapi.Store,
	certStore kmsapi.Store,
	secretLock secretlock.Service,
) (api.Suite, error) {
	kms, err := localkms.New(primaryKeyURI, &kmsProv{
		store: keyStore,
		lock:  secretLock,
	})
	if err != nil {
		return nil, fmt.Errorf("initializing local key manager: %w", err)
	}

	crypto, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	caProvider, err := newHardCodedCAProvider()
	if err != nil {
		return nil, err
	}

	cms, err := localcms.New(&cmsProv{
		store:          certStore,
		signerProvider: &tinkcrypto.SignerProvider{},
		caProvider:     caProvider,
	})

	return &suiteImpl{
		kms:    kms,
		cms:    cms,
		crypto: crypto,
	}, nil
}

type kmsProv struct {
	store kmsapi.Store
	lock  secretlock.Service
}

func (k *kmsProv) StorageProvider() kmsapi.Store {
	return k.store
}

func (k *kmsProv) SecretLock() secretlock.Service {
	return k.lock
}

type cmsProv struct {
	store          cmsapi.Store
	signerProvider cmsapi.SignerProvider
	caProvider     cmsapi.CAProvider
}

func (c *cmsProv) Store() cmsapi.Store {
	return c.store
}

func (c *cmsProv) SignerProvider() cmsapi.SignerProvider {
	return c.signerProvider
}

func (c *cmsProv) CAProvider() cmsapi.CAProvider {
	return c.caProvider
}

type caProv struct {
	caCert *x509.Certificate
	caKey  any
}

func (c *caProv) CACert() *x509.Certificate {
	return c.caCert
}

func (c *caProv) CAKey() any {
	return c.caKey
}

func newHardCodedCAProvider() (cmsapi.CAProvider, error) {
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIBvDCCAWOgAwIBAgIUOv8yOzW+dDnX0HueNV8xIfutFMYwCgYIKoZIzj0EAwIw
LzELMAkGA1UEBhMCSVQxIDAeBgNVBAMMF1ZDUyBEZXZlbG9wbWVudCBSb290IENB
MB4XDTI1MDQwMTEyNTQxOFoXDTQ1MDMyNzEyNTQxOFowLzELMAkGA1UEBhMCSVQx
IDAeBgNVBAMMF1ZDUyBEZXZlbG9wbWVudCBSb290IENBMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAE6GB1s/0Nri74XkVdRylPoj09KszESg0Emkzm5tikZE80ag5T
pRakYkOPSEKa2CvbGhQLdAH0hyKcyBjK1IqH1KNdMFswDgYDVR0PAQH/BAQDAgEG
MBIGA1UdEwEB/wQIMAYBAf8CAQAwFgYDVR0lAQH/BAwwCgYIK4ECAgAAAQcwHQYD
VR0OBBYEFONzvKcJXQRz6QExwyN21rQKsRddMAoGCCqGSM49BAMCA0cAMEQCIGJd
NABpfbNvbHfhlxrIjlDu20fwjbAcTatol4u7N8wmAiAyFNqHgUm1H8stGCVGo5Ue
/sC+1i3zA6kt85Praqnt3A==
-----END CERTIFICATE-----`)

	keyPEM := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGkz10g5x71oISYkHQg4yqmojqLv+5PgCT8vR7qrpIAEoAoGCCqGSM49
AwEHoUQDQgAE6GB1s/0Nri74XkVdRylPoj09KszESg0Emkzm5tikZE80ag5TpRak
YkOPSEKa2CvbGhQLdAH0hyKcyBjK1IqH1A==
-----END EC PRIVATE KEY-----`)

	// Decodifica il certificato
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("certificato non valido")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Decodifica la chiave privata
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("chiave privata non valida")
	}
	var privateKey interface{}
	privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	}
	if err != nil {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, err
	}

	return &caProv{
		caCert: cert,
		caKey:  privateKey,
	}, nil
}
