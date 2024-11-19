package localsuite

import (
	"crypto/x509"
	"github.com/trustbloc/kms-go/doc/jose/jwk"
	"github.com/trustbloc/kms-go/wrapper/api"
)

// newKMSCertManager creates a KMSCertManager using the given kms and certManager implementations.
func newKMSCertManager(kms keyGetter, manager certManager) api.KMSCertManager {
	return &kmsCertManagerImpl{
		kms: kms,
		cms: manager,
	}
}

type kmsCertManagerImpl struct {
	kms keyGetter
	cms certManager
}

func (k *kmsCertManagerImpl) IssueCertificate(template *x509.Certificate, pub *jwk.JWK) (*x509.Certificate, error) {
	kh, err := k.kms.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	return k.cms.IssueCertificate(template, kh)
}

func (k *kmsCertManagerImpl) FixedKeyCertManager(pub *jwk.JWK) (api.FixedKeyCertManager, error) {
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
	return f.cms.IssueCertificate(template, f.kh)
}
