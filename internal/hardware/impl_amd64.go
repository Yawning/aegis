// Copryright (C) 2019 Yawning Angel
//
// This work is licensed under the Creative Commons Attribution-NonCommercial-
// NoDerivatives 4.0 International License. To view a copy of this license,
// visit http://creativecommons.org/licenses/by-nc-nd/4.0/ or send a letter to
// Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.

// +build amd64,!noasm

package hardware

import (
	"crypto/subtle"

	"golang.org/x/sys/cpu"

	"gitlab.com/yawning/aegis.git/internal/api"
	"gitlab.com/yawning/slice.git"
)

//go:noescape
func sealAVX2(constant, key, nonce *byte, dst, plaintext, additionalData []byte)

//go:noescape
func openAVX2(constant, key, nonce *byte, dst, ciphertext, additionalData []byte, tag *byte)

type aesniFactory struct{}

func (f *aesniFactory) Name() string {
	return "aesni"
}

func (f *aesniFactory) New(key []byte) api.Instance {
	var inst aesniInstance
	copy(inst.key[:], key)

	return &inst
}

type aesniInstance struct {
	key [16]byte
}

func (inst *aesniInstance) Reset() {
	for i := range inst.key {
		inst.key[i] = 0
	}
}

func (inst *aesniInstance) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	ret, out := slice.ForAppend(dst, len(plaintext)+api.BlockSize)

	sealAVX2(&api.Const[0], &inst.key[0], &nonce[0], out, plaintext, additionalData)

	return ret
}

func (inst *aesniInstance) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, bool) {
	ptLen := len(ciphertext) - api.BlockSize
	ret, out := slice.ForAppend(dst, ptLen)

	var tagCmp [api.BlockSize]byte
	openAVX2(&api.Const[0], &inst.key[0], &nonce[0], out, ciphertext, additionalData, &tagCmp[0])

	// Note: subtle.ConstantTimeCompare is kind of slow, this could use
	// something like VPCMPEQD, VPMOVMSKB, CMP to improve small message
	// performance.
	//
	// This is easier to read and AEGIS-128 still shits all over GCM-AES128,
	// so opt for maintainability for now.
	return ret, subtle.ConstantTimeCompare(ciphertext[ptLen:], tagCmp[:]) == 1
}

func init() {
	// TODO: AVX is nice in that it saves some register/register moves in
	// StateUpdate128, but sticking with SSE2 would be more compatible.
	if cpu.X86.HasAVX && cpu.X86.HasAES {
		Factory = &aesniFactory{}
	}
}
