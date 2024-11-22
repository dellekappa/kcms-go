package websuite

import (
	"crypto/x509"
	"github.com/dellekappa/kcms-go/cms/webcms"
	"github.com/dellekappa/kcms-go/doc/jose/jwk"
	"github.com/dellekappa/kcms-go/kms/webkms"
	suiteapi "github.com/dellekappa/kcms-go/suite/api"
)

type cmsImpl struct {
	km *webkms.RemoteKMS
	cm *webcms.RemoteCMS
}

func (c *cmsImpl) IssueCertificate(template *x509.Certificate, pub *jwk.JWK) (*x509.Certificate, error) {
	kh, err := c.km.Get(pub.KeyID)
	if err != nil {
		return nil, err
	}

	_, cert, err := c.cm.IssueCertificate(template, kh)
	return cert, err
}

func (c *cmsImpl) FixedKeyCertIssuer(pub *jwk.JWK) (suiteapi.FixedKeyCertIssuer, error) {
	return makeFixedKeyCMS(pub.KeyID, c.km, c.cm)
}
