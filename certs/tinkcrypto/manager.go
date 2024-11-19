package tinkcrypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/google/tink/go/keyset"
)

var errBadKeyHandleFormat = errors.New("bad key handle format")

type Manager struct{}

func New() *Manager {
	return &Manager{}
}

func (m *Manager) IssueCertificate(template *x509.Certificate, kh interface{}) (*x509.Certificate, error) {

	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, errBadKeyHandleFormat
	}

}
