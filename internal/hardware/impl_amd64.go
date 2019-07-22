// Copryright (C) 2019 Yawning Angel
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// +build amd64,!noasm

package hardware

import (
	"golang.org/x/sys/cpu"

	"gitlab.com/yawning/aegis.git/internal/api"
	"gitlab.com/yawning/slice.git"
)

//go:noescape
func sealAVX2(constant, key, nonce *byte, dst, plaintext, additionalData []byte)

//go:noescape
func openAVX2(constant, key, nonce *byte, dst, ciphertext, additionalData []byte, tagOk *bool)

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

	var tagOk bool
	openAVX2(&api.Const[0], &inst.key[0], &nonce[0], out, ciphertext, additionalData, &tagOk)

	return ret, tagOk
}

func init() {
	// TODO: AVX is nice in that it saves some register/register moves in
	// StateUpdate128, but sticking with SSE2 would be more compatible.
	if cpu.X86.HasAVX && cpu.X86.HasAES {
		Factory = &aesniFactory{}
	}
}
