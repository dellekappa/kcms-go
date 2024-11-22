/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aead_test

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/require"
	tinkaead "github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/core/cryptofmt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"github.com/tink-crypto/tink-go/v2/testkeyset"
	"github.com/tink-crypto/tink-go/v2/testutil"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/protobuf/proto"

	"github.com/dellekappa/kcms-go/crypto/tinkcrypto/primitive/aead"
	"github.com/dellekappa/kcms-go/crypto/tinkcrypto/primitive/aead/subtle"
	aescbcpb "github.com/dellekappa/kcms-go/crypto/tinkcrypto/primitive/proto/aes_cbc_go_proto"
	aeadpb "github.com/dellekappa/kcms-go/crypto/tinkcrypto/primitive/proto/aes_cbc_hmac_aead_go_proto"
)

func TestFactoryMultipleKeys(t *testing.T) {
	// encrypt with non-raw key
	ks := NewTestAESCBCHMACKeyset(t, tinkpb.OutputPrefixType_TINK)
	primaryKey := ks.Key[0]
	require.NotEqualf(t, tinkpb.OutputPrefixType_RAW, primaryKey.OutputPrefixType, "expect a non-raw key")

	keysetHandle, err := testkeyset.NewHandle(ks)
	require.NoError(t, err)

	a, err := tinkaead.New(keysetHandle)
	require.NoError(t, err)

	expectedPrefix, err := cryptofmt.OutputPrefix(primaryKey)
	require.NoError(t, err)

	validateAEADFactoryCipher(t, a, a, expectedPrefix, true)

	// encrypt with a non-primary RAW key and decrypt with the keyset
	rawKey := ks.Key[1]
	require.Equalf(t, tinkpb.OutputPrefixType_RAW, rawKey.OutputPrefixType, "expect a raw key")

	keyset2 := testutil.NewKeyset(rawKey.KeyId, []*tinkpb.Keyset_Key{rawKey})
	keysetHandle2, err := testkeyset.NewHandle(keyset2)
	require.NoError(t, err)

	a2, err := tinkaead.New(keysetHandle2)
	require.NoError(t, err)

	validateAEADFactoryCipher(t, a2, a, cryptofmt.RawPrefix, true)

	// encrypt with a random key not in the keyset, decrypt with the keyset should fail
	keyset2 = NewTestAESCBCHMACKeyset(t, tinkpb.OutputPrefixType_TINK)
	primaryKey = keyset2.Key[0]
	expectedPrefix, err = cryptofmt.OutputPrefix(primaryKey)
	require.NoError(t, err)

	keysetHandle2, err = testkeyset.NewHandle(keyset2)
	require.NoError(t, err)

	a2, err = tinkaead.New(keysetHandle2)
	require.NoErrorf(t, err, "aead.New failed")

	validateAEADFactoryCipher(t, a2, a, expectedPrefix, false)
}

func TestFactoryRawKeyAsPrimary(t *testing.T) {
	ks := NewTestAESCBCHMACKeyset(t, tinkpb.OutputPrefixType_RAW)
	require.Equalf(t, tinkpb.OutputPrefixType_RAW, ks.Key[0].OutputPrefixType, "primary key is not a raw key")

	keysetHandle, err := testkeyset.NewHandle(ks)
	require.NoError(t, err)

	a, err := tinkaead.New(keysetHandle)
	require.NoError(t, err)

	validateAEADFactoryCipher(t, a, a, cryptofmt.RawPrefix, true)
}

func validateAEADFactoryCipher(t *testing.T, encryptCipher tink.AEAD, decryptCipher tink.AEAD, expectedPrefix string,
	noError bool) {
	prefixSize := len(expectedPrefix)
	// regular plaintext
	pt := random.GetRandomBytes(20)
	ad := random.GetRandomBytes(20)
	ct, err := encryptCipher.Encrypt(pt, ad)
	require.NoErrorf(t, err, "encryption failed with regular plaintext")

	decrypted, err := decryptCipher.Decrypt(ct, ad)
	if !noError {
		require.Error(t, err)
		require.Contains(t, err.Error(), "decryption failed")

		return
	}

	require.NoError(t, err)
	require.EqualValues(t, pt, decrypted, "decryption not equal to plaintext: %s", pt)

	require.Equalf(t, expectedPrefix, string(ct[:prefixSize]), "incorrect prefix with regular plaintext")

	padding := aes.BlockSize - (len(pt) % aes.BlockSize)

	// Tink's CBC+HMAC ciphertext output is comprised of:
	// Tink Prefix +
	// plaintext +
	// AES Block padding +
	// IV/nonce +
	// authentication Tag +
	require.Equalf(t, len(ct), prefixSize+len(pt)+padding+subtle.AESCBCIVSize+subtle.AES128Size,
		"lengths of plaintext and ciphertext don't match with regular plaintext")

	// short plaintext
	pt = random.GetRandomBytes(1)
	ct, err = encryptCipher.Encrypt(pt, ad)
	require.NoError(t, err, "encryption failed with short plaintext")

	decrypted, err = decryptCipher.Decrypt(ct, ad)
	require.NoError(t, err)
	require.EqualValuesf(t, pt, decrypted, "decryption failed with short plaintext: %s", pt)

	require.Equalf(t, expectedPrefix, string(ct[:prefixSize]), "incorrect prefix with short plaintext")

	padding = aes.BlockSize - (len(pt) % aes.BlockSize)

	require.Equalf(t, len(ct), prefixSize+len(pt)+padding+subtle.AESCBCIVSize+subtle.AES128Size,
		"lengths of plaintext and ciphertext don't match with short plaintext")
}

func TestFactoryWithInvalidPrimitiveSetType(t *testing.T) {
	wrongKH, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("failed to build *keyset.Handle: %s", err)
	}

	_, err = tinkaead.New(wrongKH)
	if err == nil {
		t.Fatalf("calling New() with wrong *keyset.Handle should fail")
	}
}

func TestFactoryWithValidPrimitiveSetType(t *testing.T) {
	goodKH, err := keyset.NewHandle(aead.AES128CBCHMACSHA256KeyTemplate())
	require.NoError(t, err, "failed to build *keyset.Handle")

	_, err = tinkaead.New(goodKH)
	require.NoError(t, err, "calling New() with good *keyset.Handle failed")
}

func TestFactoryAndPrimitiveSetWithBadCiphertext(t *testing.T) {
	goodKH, err := keyset.NewHandle(aead.AES128CBCHMACSHA256KeyTemplate())
	require.NoError(t, err, "failed to build *keyset.Handle")

	aeadPrimitive, err := tinkaead.New(goodKH)
	require.NoError(t, err, "calling New() with good *keyset.Handle failed")

	pt := []byte("test plaintext")
	ad := []byte("aad")

	ct, err := aeadPrimitive.Encrypt(pt, ad)
	require.NoError(t, err)

	plaintext, err := aeadPrimitive.Decrypt(ct, ad)
	require.NoError(t, err)
	require.EqualValues(t, pt, plaintext)

	_, err = aeadPrimitive.Decrypt([]byte("bad ciphertext"), ad)
	require.EqualError(t, err, "aead_factory: decryption failed")
}

// NewTestAESCBCHMACKeyset creates a new Keyset containing an AESCBC+HMAC aead.
func NewTestAESCBCHMACKeyset(t *testing.T, primaryOutputPrefixType tinkpb.OutputPrefixType) *tinkpb.Keyset {
	keyData := NewCBCHMACKeyData(t, subtle.AES128Size, subtle.AES128Size, commonpb.HashType_SHA256)
	return testutil.NewTestKeyset(keyData, primaryOutputPrefixType)
}

// NewCBCHMACKeyData creates a KeyData containing a randomly generated AESCBC+HMAC key.
func NewCBCHMACKeyData(t *testing.T, keySize, tagSize uint32, hashType commonpb.HashType) *tinkpb.KeyData {
	serializedKey, err := proto.Marshal(NewCBCHMACKey(0, keySize, tagSize, hashType))
	require.NoError(t, err)

	return testutil.NewKeyData(AESCBCHMACAEADTypeURL, serializedKey, tinkpb.KeyData_SYMMETRIC)
}

// NewAESGCMKey creates a randomly generated AESCBC+HMAC key.
func NewCBCHMACKey(keyVersion, keySize, tagSize uint32, hashType commonpb.HashType) *aeadpb.AesCbcHmacAeadKey {
	cbcKeyValue := random.GetRandomBytes(keySize)
	hmacKeyValue := random.GetRandomBytes(keySize)

	return &aeadpb.AesCbcHmacAeadKey{
		Version: keyVersion,
		AesCbcKey: &aescbcpb.AesCbcKey{
			Version:  keyVersion,
			KeyValue: cbcKeyValue,
		},
		HmacKey: &hmacpb.HmacKey{
			Version: keyVersion,
			Params: &hmacpb.HmacParams{
				Hash:    hashType,
				TagSize: tagSize,
			},
			KeyValue: hmacKeyValue,
		},
	}
}
