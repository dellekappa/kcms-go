package webcms

import (
	"crypto/x509"
	"errors"

	cmsapi "github.com/dellekappa/kcms-go/spi/cms"
)

// package localcms is the default CMS service implementation of pkg/cms.CertManager.

// RemoteCMS implementation of cms.CertManager api.
type RemoteCMS struct {
}

// New will create a new (remote) CMS service.
func New() *RemoteCMS {
	return &RemoteCMS{}
}

// HealthCheck check cms.
func (l *RemoteCMS) HealthCheck() error {
	return nil
}

// IssueCertificate creates and stores a new certificate signed by the key provided
// Returns:
//   - certID of the certificate
//   - the signed certificate
//   - error if failure
func (l *RemoteCMS) IssueCertificate(template *x509.Certificate, privateKey interface{}, opts ...cmsapi.CertOpt) (string, *x509.Certificate, error) {
	return "", nil, errors.New("not yet implemented")
}

// Get certs for the given chainID
// Returns:
//   - certificate chain
//   - error if failure
func (l *RemoteCMS) Get(chainID string) ([]*x509.Certificate, error) {
	return nil, errors.New("not yet implemented")
}

func (l *RemoteCMS) ImportChain(chain []*x509.Certificate, opts ...cmsapi.CertOpt) (string, error) {
	return "", errors.New("not yet implemented")
}
