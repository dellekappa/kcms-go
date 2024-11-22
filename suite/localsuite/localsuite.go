/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package localsuite provides an api.Suite using local kms and crypto implementations.
package localsuite

import (
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

	cms, err := localcms.New(&cmsProv{
		store:          certStore,
		signerProvider: &tinkcrypto.SignerProvider{},
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
}

func (c *cmsProv) Store() cmsapi.Store {
	return c.store
}

func (c *cmsProv) SignerProvider() cmsapi.SignerProvider {
	return c.signerProvider
}
