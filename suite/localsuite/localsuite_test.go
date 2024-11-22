/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package localsuite

import (
	"testing"

	mockstorage "github.com/dellekappa/kcms-go/internal/mock/storage"
	"github.com/dellekappa/kcms-go/kms"
	"github.com/dellekappa/kcms-go/secretlock/noop"
	"github.com/stretchr/testify/require"
)

func TestNewLocalCryptoSuite(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		kmsStore, err := kms.NewAriesProviderWrapper(mockstorage.NewKMSMockStoreProvider())
		require.NoError(t, err)

		cmsStore := mockstorage.NewCMSMockStore()

		suite, err := NewLocalKCMSSuite("prefix://key/uri", kmsStore, cmsStore, &noop.NoLock{})
		require.NoError(t, err)
		require.NotNil(t, suite)
	})

	t.Run("fail to initialize localkms", func(t *testing.T) {
		kmsStore, err := kms.NewAriesProviderWrapper(mockstorage.NewKMSMockStoreProvider())
		require.NoError(t, err)

		cmsStore := mockstorage.NewCMSMockStore()

		suite, err := NewLocalKCMSSuite("", kmsStore, cmsStore, &noop.NoLock{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "initializing local key manager")
		require.Nil(t, suite)
	})
}
