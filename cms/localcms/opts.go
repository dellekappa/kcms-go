/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package localcms

import (
	cmsapi "github.com/dellekappa/kcms-go/spi/cms"
)

type cmsOpts struct {
	signerProvider cmsapi.SignerProvider
	store          cmsapi.Store
	caProvider     cmsapi.CAProvider
}

func (k *cmsOpts) SignerProvider() cmsapi.SignerProvider {
	return k.signerProvider
}
func (k *cmsOpts) Store() cmsapi.Store {
	return k.store
}
func (k *cmsOpts) CAProvider() cmsapi.CAProvider {
	return k.caProvider
}

// CMSOpts are the create CMS option.
type CMSOpts func(opts *cmsOpts)

// WithSignerProvider option is for setting store for KMS.
func WithSignerProvider(signerProvider cmsapi.SignerProvider) CMSOpts {
	return func(opts *cmsOpts) {
		opts.signerProvider = signerProvider
	}
}

// WithStore option is for setting store for KMS.
func WithStore(store cmsapi.Store) CMSOpts {
	return func(opts *cmsOpts) {
		opts.store = store
	}
}

// WithCAProvider option is for setting store for KMS.
func WithCAProvider(caProvider cmsapi.CAProvider) CMSOpts {
	return func(opts *cmsOpts) {
		opts.caProvider = caProvider
	}
}
