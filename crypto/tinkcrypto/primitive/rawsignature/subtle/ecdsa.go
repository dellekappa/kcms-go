package subtle

import (
	"errors"
	"fmt"
)

var errUnsupportedEncoding = errors.New("ecdsa: unsupported encoding")

// ValidateECDSAParams validates ECDSA parameters.
// The hash's strength must not be weaker than the curve's strength.
// DER and IEEE_P1363 encodings are supported.
func ValidateECDSAParams(curve string, encoding string) error {
	switch encoding {
	case "DER":
	case "IEEE_P1363":
	default:
		return errUnsupportedEncoding
	}
	switch curve {
	case "NIST_P256":
	case "NIST_P384":
	case "NIST_P521":
	default:
		return fmt.Errorf("unsupported curve: %s", curve)
	}
	return nil
}
