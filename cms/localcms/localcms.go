package localcms

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	cmsapi "github.com/dellekappa/kcms-go/spi/cms"
	"github.com/google/uuid"
)

// package localcms is the default CMS service implementation of pkg/cms.CertManager.

// LocalCMS implements cms.CertManager to provide certificate management capabilities using a local db.
type LocalCMS struct {
	signerProvider cmsapi.SignerProvider
	store          cmsapi.Store
}

// New will create a new (local) CMS service.
func New(p cmsapi.Provider) (*LocalCMS, error) {
	return NewWithOpts(
		WithSignerProvider(p.SignerProvider()),
		WithStore(p.Store()),
	)
}

// NewWithOpts will create a new KMS service with options.
func NewWithOpts(opts ...CMSOpts) (*LocalCMS, error) {
	options := &cmsOpts{}

	for _, opt := range opts {
		opt(options)
	}

	return &LocalCMS{
			signerProvider: options.SignerProvider(),
			store:          options.Store(),
		},
		nil
}

// HealthCheck check cms.
func (l *LocalCMS) HealthCheck() error {
	return nil
}

// IssueCertificate creates and stores a new certificate signed by the key provided
// Returns:
//   - certID of the certificate
//   - the signed certificate
//   - error if failure
func (l *LocalCMS) IssueCertificate(template *x509.Certificate, privateKey interface{}, opts ...cmsapi.CertOpt) (string, *x509.Certificate, error) {
	if template == nil {
		return "", nil, fmt.Errorf("failed to create new cert, missing cert template")
	}

	if privateKey == nil {
		return "", nil, fmt.Errorf("failed to create new cert, missing private key")
	}

	signer, err := l.signerProvider.Signer(privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("cannot retrieve signer: %w", err)
	}

	// Genera un certificato autofirmato
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return "", nil, fmt.Errorf("create x509 certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", nil, fmt.Errorf("parse x509 certificate: %w", err)
	}

	chainID, err := l.storeChain([]*x509.Certificate{cert}, opts...)
	if err != nil {
		return "", nil, fmt.Errorf("create: failed to store keyset: %w", err)
	}

	return chainID, cert, nil
}

// Get certs for the given chainID
// Returns:
//   - certificate chain
//   - error if failure
func (l *LocalCMS) Get(chainID string) ([]*x509.Certificate, error) {
	certBytes, err := l.store.Get(chainID)
	if err != nil {
		return nil, err
	}

	return parsePEMCertificateChain(certBytes)
}

func (l *LocalCMS) ImportChain(chain []*x509.Certificate, opts ...cmsapi.CertOpt) (string, error) {
	return l.storeChain(chain, opts...)
}

func (l *LocalCMS) storeChain(certs []*x509.Certificate, opts ...cmsapi.CertOpt) (string, error) {
	cfg := cmsapi.NewCertOpts()

	for _, o := range opts {
		o(cfg)
	}

	chainID := cfg.ChainID()
	if chainID == "" {
		chainID = uuid.NewString()
	}

	certBytes, err := serializeCertificateChainToPEM(certs)
	if err != nil {
		return "", err
	}

	if err = l.store.Put(chainID, certBytes); err != nil {
		return "", err
	}

	return chainID, nil
}

// Funzione per serializzare una certificate chain in formato PEM
func serializeCertificateChainToPEM(chain []*x509.Certificate) ([]byte, error) {
	var pemData []byte
	for _, cert := range chain {
		if cert == nil {
			continue
		}
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(block)...)
	}
	return pemData, nil
}

// Funzione di utilità per decodificare una certificate chain in PEM
func parsePEMCertificateChain(pemData []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
		pemData = rest
	}
	return chain, nil
}
