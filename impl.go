// Copryright (C) 2019 Yawning Angel
//
// This work is licensed under the Creative Commons Attribution-NonCommercial-
// NoDerivatives 4.0 International License. To view a copy of this license,
// visit http://creativecommons.org/licenses/by-nc-nd/4.0/ or send a letter to
// Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.

// Package aegis implements the AEGIS-128 AEAD algorithm.
package aegis

import (
	"crypto/cipher"
	"errors"
	"math"

	"gitlab.com/yawning/aegis.git/internal/api"
	"gitlab.com/yawning/aegis.git/internal/hardware"
)

const (
	// KeySize is the AEGIS-128 key size in bytes.
	KeySize = 16

	// NonceSize is the AEGIS-128 nonce size in bytes.
	NonceSize = 16

	// TagSize is the AEGIS-128 authentication tag size in bytes.
	TagSize = 16

	maxBytes = math.MaxUint64 >> 3
)

var (
	// ErrNoImplementations is the error returned when there are no working
	// implementations.
	ErrNoImplementations = errors.New("aegis: no working implementations")

	// ErrInvalidKeySize is the error returned when the key size is invalid.
	ErrInvalidKeySize = errors.New("aegis: invalid key size")

	// ErrInvalidNonecSize is the error returned/paniced when the nonce size
	// is invalid.
	ErrInvalidNonceSize = errors.New("aegis: invalid nonce size")

	// ErrOpen is the error returned when the message authentication fails
	// durring an Open call.
	ErrOpen = errors.New("aegis: message authentication failure")

	// ErrOversized is the error returned/paniced when the plaintext,
	// ciphertext and or additional data are beyond the maximum allowed.
	ErrOversized = errors.New("aegis: data is over limit")

	chosenFactory      api.Factory
	supportedFactories []api.Factory
)

type aeadInstance struct {
	inner api.Instance
}

func (aead *aeadInstance) NonceSize() int {
	return NonceSize
}

func (aead *aeadInstance) Overhead() int {
	return TagSize
}

func (aead *aeadInstance) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic(ErrInvalidNonceSize)
	}
	if err := checkLimits(plaintext, additionalData); err != nil {
		panic(err)
	}

	return aead.inner.Seal(dst, nonce, plaintext, additionalData)
}

func (aead *aeadInstance) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, ErrInvalidNonceSize
	}
	if len(ciphertext) < TagSize {
		return nil, ErrOpen
	}
	// Yes, the tag comes at the end, but this is just a length check.
	if err := checkLimits(ciphertext[TagSize:], additionalData); err != nil {
		return nil, err
	}

	var ok bool
	dst, ok = aead.inner.Open(dst, nonce, ciphertext, additionalData)
	if !ok {
		for i := range dst {
			dst[i] = 0
		}
		return nil, ErrOpen
	}

	return dst, nil
}

func (aead *aeadInstance) Reset() {
	aead.inner.Reset()
}

// New creates a new AEGIS-128 instance with the provided key.
func New(key []byte) (cipher.AEAD, error) {
	if chosenFactory == nil {
		return nil, ErrNoImplementations
	}
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	return &aeadInstance{
		inner: chosenFactory.New(key),
	}, nil
}

func checkLimits(a, b []byte) error {
	// AEGIS encodes the message and ad length as uint64s, in bits.
	if uint64(len(a)) > maxBytes || uint64(len(b)) > maxBytes {
		return ErrOversized
	}

	return nil
}

func init() {
	if hardware.Factory != nil {
		supportedFactories = append([]api.Factory{hardware.Factory}, supportedFactories...)
	}

	if len(supportedFactories) > 0 {
		chosenFactory = supportedFactories[0]
	}
}
