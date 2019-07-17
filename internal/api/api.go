// Copryright (C) 2019 Yawning Angel
//
// This work is licensed under the Creative Commons Attribution-NonCommercial-
// NoDerivatives 4.0 International License. To view a copy of this license,
// visit http://creativecommons.org/licenses/by-nc-nd/4.0/ or send a letter to
// Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.

// Package api provides the AEGIS implementation abstract interface.
package api

// BlockSize is the AES block size in bytes.
const BlockSize = 16

// Const is the AEGIS initialization constant.
var Const = [32]byte{
	0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
	0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
}

// Factory is a Instance factory.
type Factory interface {
	// Name returns the name of the implementation.
	Name() string

	// New constructs a new keyed instance.
	New(key []byte) Instance
}

// Instance is a keyed AEGIS instance.
type Instance interface {
	// Reset attempts to clear the instance of sensitive data.
	Reset()

	// Seal encrypts and authenticates plaintext and additional data and
	// appends the result to dst, returning the updated slice.
	Seal(dst, nonce, plaintext, additionalData []byte) []byte

	// Open decrypts and authenticates ciphertext, authenticates the additional
	// data and, if successful, appends the resulting plaintext to dst.
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, bool)
}
