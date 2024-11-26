package localsuite

import (
	"crypto/x509"
	"github.com/dellekappa/kcms-go/doc/jose/jwk"
	"github.com/dellekappa/kcms-go/spi/cms"
	"github.com/dellekappa/kcms-go/suite/api"
)

// newCMSCertIssuer creates a CMSCertIssuer using the given kms and certManager implementations.
func newCMSCertIssuer(kms keyGetter, manager certManager) api.CMSCertIssuer {
	return &cmsCertIssuerImpl{
		kms: kms,
		cms: manager,
	}
}

type cmsCertIssuerImpl struct {
	kms keyGetter
	cms certManager
}

func (k *cmsCertIssuerImpl) IssueCertificate(template *x509.Certificate, pub *jwk.JWK) (*x509.Certificate, error) {
	kh, err := k.kms.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	_, cert, err := k.cms.IssueCertificate(template, kh, cms.WithChainID(pub.KeyID))
	return cert, err
}

func (k *cmsCertIssuerImpl) FixedKeyCertIssuer(pub *jwk.JWK) (api.FixedKeyCertIssuer, error) {
	kh, err := k.kms.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	return &fixedKeyCertManagerImpl{
		cms: k.cms,
		kh:  kh,
	}, nil
}

type fixedKeyCertManagerImpl struct {
	cms certManager
	kh  interface{}
}

func (f *fixedKeyCertManagerImpl) IssueCertificate(template *x509.Certificate) (*x509.Certificate, error) {
	_, cert, err := f.cms.IssueCertificate(template, f.kh)
	return cert, err
}
