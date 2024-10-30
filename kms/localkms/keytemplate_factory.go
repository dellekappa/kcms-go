/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/dellekappa/kms-go/spi/kms"
)

// getKeyTemplate returns tink KeyTemplate associated with the provided keyType.
func getKeyTemplate(keyType kms.KeyType, opts ...kms.KeyOpts) (*tinkpb.KeyTemplate, error) {
	return keyTemplate(keyType, opts...)
}
