package cms

import (
	"crypto"
	"crypto/x509"
	"errors"
)

// ErrCertNotFound is an error type that a CMS expects from the Store.Get method if no cert stored under the given
// cert ID could be found.
var ErrCertNotFound = errors.New("cert not found")

// CertManager manages certs and their storage.
type CertManager interface {
	// Create a new x509 certificate based on the template provided and signed with the provided key
	// The key must be asymmetric
	// Returns:
	//  - chainID for retrieval
	//  - the signed x509 certificate
	//  - error if failure
	Create(template *x509.Certificate, privateKey interface{}, opts ...CertOpt) (string, *x509.Certificate, error)
	// Get cert chain for the given chainID
	// Returns:
	//  - the x509 certificate
	//  - error if failure
	Get(chainID string) ([]*x509.Certificate, error)
	ImportChain(chain []*x509.Certificate, opts ...CertOpt) (string, error)
}

type SignerProvider interface {
	Signer(key interface{}) (crypto.Signer, error)
}

// Store defines the storage capability required by a CertManager Provider.
type Store interface {
	// Put stores the given cert under the given certID.
	Put(certID string, cert []byte) error
	// Get retrieves the cert stored under the given certID. If no cert is found, the returned error is expected
	// to wrap ErrCertNotFound. CMS implementations may check to see if the error wraps that error type for certain
	// operations.
	Get(certID string) (cert []byte, err error)
	// Delete deletes the cert stored under the given certID. A CertManager will assume that attempting to delete
	// a non-existent key will not return an error.
	Delete(certID string) error
}

// Provider for CertManager builder/constructor.
type Provider interface {
	Store() Store
	SignerProvider() SignerProvider
}
