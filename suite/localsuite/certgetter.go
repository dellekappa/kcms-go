package localsuite

import (
	"crypto/x509"
	"github.com/dellekappa/kcms-go/suite/api"
)

// newCMSCertGetter creates a CMSCertGetter using the given kms and certManager implementations.
func newCMSCertGetter(manager certManager) api.CMSCertGetter {
	return &cmsCertGetterImpl{
		cms: manager,
	}
}

type cmsCertGetterImpl struct {
	cms certManager
}

func (k *cmsCertGetterImpl) GetCertificates(chainID string) ([]*x509.Certificate, error) {
	return k.cms.Get(chainID)
}
