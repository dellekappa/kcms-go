package rawsignature

import (
	"fmt"
	"github.com/tink-crypto/tink-go/v2/core/registry"
)

func init() {
	// ECDSA
	if err := registry.RegisterKeyManager(new(ecdsaRawSignerKeyManager)); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}
	if err := registry.RegisterKeyManager(new(ecdsaRawVerifierKeyManager)); err != nil {
		panic(fmt.Sprintf("signature.init() failed: %v", err))
	}
}
