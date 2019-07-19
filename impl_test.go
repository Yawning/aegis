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

package aegis

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"

	"gitlab.com/yawning/aegis.git/internal/api"

	"crypto/aes"
	"crypto/cipher"
)

func TestBasic(t *testing.T) {
	for _, v := range supportedFactories {
		t.Run("Impl_"+v.Name(), func(t *testing.T) {
			doTestBasic(t, v)
		})
	}
}

func doTestBasic(t *testing.T, factory api.Factory) {
	oldFactory := chosenFactory
	chosenFactory = factory
	defer func() {
		chosenFactory = oldFactory
	}()

	require := require.New(t)

	// Short key should fail.
	_, err := New([]byte("short key"))
	require.EqualError(err, ErrInvalidKeySize.Error(), "New() - short key")

	// Construct a random keyed instance to test things.
	key := make([]byte, KeySize)
	_, err = rand.Read(key)
	require.NoError(err, "Generate random key")
	aead, err := New(key)
	require.NoError(err, "New()")
	require.Equal(NonceSize, aead.NonceSize(), "NonceSize()")
	require.Equal(TagSize, aead.Overhead(), "Overhead()")

	// Construct a random nonce, plaintext and aad.
	nonce := make([]byte, NonceSize)
	_, err = rand.Read(nonce)
	require.NoError(err, "Generate random nonce")

	plaintext := make([]byte, 73)
	_, err = rand.Read(plaintext)
	require.NoError(err, "Generate random plaintext")

	aad := make([]byte, 42)
	_, err = rand.Read(aad)
	require.NoError(err, "Generate random aad")

	// Ensure it round trips.
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	require.Len(sealed, len(plaintext)+TagSize, "Seal() - length")
	opened, err := aead.Open(nil, nonce, sealed, aad)
	require.NoError(err, "Open()")
	require.EqualValues(plaintext, opened, "Seal()/Open() - round trips")

	// Ensure it fails on truncated nonce, ciphertext.
	require.Panics(func() { aead.Seal(nil, nil, plaintext, aad) }, "Seal() - truncated nonce")
	_, err = aead.Open(nil, nonce[:NonceSize-1], sealed, aad)
	require.EqualError(err, ErrInvalidNonceSize.Error(), "Open() - truncated nonce")
	_, err = aead.Open(nil, nonce, sealed[:TagSize-1], aad)
	require.EqualError(err, ErrOpen.Error(), "Open() - truncated ciphertext")

	// Ensure trivial alterations to nonce/ciphertext/tag/aad cause failures.
	badNonce := append([]byte{}, nonce...)
	badNonce[0] ^= 0xa5
	_, err = aead.Open(nil, badNonce, sealed, aad)
	require.EqualError(err, ErrOpen.Error(), "Open() - invalid nonce")

	badCiphertext := append([]byte{}, sealed...)
	badCiphertext[0] ^= 0xa5
	_, err = aead.Open(nil, nonce, badCiphertext, aad)
	require.EqualError(err, ErrOpen.Error(), "Open() - invalid ciphertext")

	badTag := append([]byte{}, sealed...)
	badTag[len(badTag)-1] ^= 0xa5
	_, err = aead.Open(nil, nonce, badTag, aad)
	require.EqualError(err, ErrOpen.Error(), "Open() - invalid tag")

	badAad := append([]byte{}, aad...)
	badAad[0] ^= 0xa5
	_, err = aead.Open(nil, nonce, sealed, badAad)
	require.EqualError(err, ErrOpen.Error(), "Open() - invalid aad")

	type resetAble interface {
		Reset()
	}

	rst, ok := aead.(resetAble)
	require.True(ok, "aead implements Reset()")
	rst.Reset()

	// Ensure the pesants without supported hardware get failures.
	chosenFactory = nil
	_, err = New(key)
	require.EqualError(err, ErrNoImplementations.Error(), "New() - no implementation")
}

func TestVectors(t *testing.T) {
	require := require.New(t)

	testVectors, err := loadTestVectors()
	require.NoError(err, "Load test vector file")

	for _, v := range supportedFactories {
		t.Run("Impl_"+v.Name(), func(t *testing.T) {
			doTestVectors(t, v, testVectors)
		})
	}
}

type testVector struct {
	Key            []byte
	IV             []byte
	AssociatedData []byte
	Plaintext      []byte
	Ciphertext     []byte
	Tag            []byte
}

func loadTestVectors() ([]*testVector, error) {
	type hexVector struct {
		Key            string
		IV             string
		AssociatedData string
		Plaintext      string
		Ciphertext     string
		Tag            string
	}

	b, err := ioutil.ReadFile("testdata/test-vectors.json")
	if err != nil {
		return nil, err
	}

	var hexVectors []*hexVector
	if err = json.Unmarshal(b, &hexVectors); err != nil {
		return nil, err
	}

	testVectors := make([]*testVector, 0, len(hexVectors))
	for _, v := range hexVectors {
		var b [][]byte
		for _, vv := range []string{
			v.Key,
			v.IV,
			v.AssociatedData,
			v.Plaintext,
			v.Ciphertext,
			v.Tag,
		} {
			bb, err := hex.DecodeString(vv)
			if err != nil {
				return nil, err
			}
			b = append(b, bb)
		}
		testVectors = append(testVectors, &testVector{b[0], b[1], b[2], b[3], b[4], b[5]})
	}

	return testVectors, nil
}

func doTestVectors(t *testing.T, factory api.Factory, vectors []*testVector) {
	oldFactory := chosenFactory
	chosenFactory = factory
	defer func() {
		chosenFactory = oldFactory
	}()

	require := require.New(t)

	for i, v := range vectors {
		aead, err := New(v.Key)
		require.NoError(err, "New()")

		sealed := aead.Seal(nil, v.IV, v.Plaintext, v.AssociatedData)
		ctLen := len(v.Plaintext)
		ciphertext, tag := sealed[:ctLen], sealed[ctLen:]
		require.EqualValues(v.Ciphertext, ciphertext, "Seal(%d) - ciphertext", i)
		require.EqualValues(v.Tag, tag, "Seal(%d) - tag", i)

		opened, err := aead.Open(nil, v.IV, sealed, v.AssociatedData)
		require.NoError(err, "Open(%d)", i)
		if len(v.Plaintext) > 0 {
			require.EqualValues(v.Plaintext, opened, "Opened(%d) - plaintext", i)
		} else {
			require.Len(opened, 0, "Opened(%d) - plaintext, i")
		}
	}
}

func BenchmarkAegis(b *testing.B) {
	for _, v := range supportedFactories {
		doBenchmarkAegis(b, v)
	}
}

func doBenchmarkAegis(b *testing.B, factory api.Factory) {
	oldFactory := chosenFactory
	chosenFactory = factory
	defer func() {
		chosenFactory = oldFactory
	}()

	benchSizes := []int{8, 32, 64, 576, 1536, 4096, 1024768}

	for _, sz := range benchSizes {
		bn := "AEGIS-128_" + factory.Name() + "_"
		sn := fmt.Sprintf("_%d", sz)
		b.Run(bn+"Encrypt"+sn, func(b *testing.B) { doBenchmarkAeadSeal(b, sz) })
		b.Run(bn+"Decrypt"+sn, func(b *testing.B) { doBenchmarkAeadOpen(b, sz) })
		b.Run("GCM_Encrypt"+sn, func(b *testing.B) { doBenchmarkGcmAes128(b, sz) })
	}
}

func doBenchmarkGcmAes128(b *testing.B, sz int) {
	b.StopTimer()
	b.SetBytes(int64(sz))

	nonce, key := make([]byte, 12), make([]byte, 16)
	m, c := make([]byte, sz), make([]byte, 0, sz+16)
	_, _ = rand.Read(nonce)
	_, _ = rand.Read(key)
	_, _ = rand.Read(m)
	aes, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(aes)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		c = c[:0]

		c = aead.Seal(c, nonce, m, nil)
		if len(c) != sz+TagSize {
			b.Fatalf("Seal failed")
		}
	}
}

func doBenchmarkAeadSeal(b *testing.B, sz int) {
	b.StopTimer()
	b.SetBytes(int64(sz))

	nonce, key := make([]byte, NonceSize), make([]byte, KeySize)
	m, c := make([]byte, sz), make([]byte, 0, sz+TagSize)
	_, _ = rand.Read(nonce)
	_, _ = rand.Read(key)
	_, _ = rand.Read(m)
	aead, _ := New(key)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		c = c[:0]

		c = aead.Seal(c, nonce, m, nil)
		if len(c) != sz+TagSize {
			b.Fatalf("Seal failed")
		}
	}
}

func doBenchmarkAeadOpen(b *testing.B, sz int) {
	b.StopTimer()
	b.SetBytes(int64(sz))

	nonce, key := make([]byte, NonceSize), make([]byte, KeySize)
	m, c, d := make([]byte, sz), make([]byte, 0, sz+TagSize), make([]byte, 0, sz)
	_, _ = rand.Read(nonce)
	_, _ = rand.Read(key)
	_, _ = rand.Read(m)
	aead, _ := New(key)

	c = aead.Seal(c, nonce, m, nil)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		d = d[:0]

		var err error
		d, err = aead.Open(d, nonce, c, nil)
		if err != nil {
			b.Fatalf("Open failed")
		}
	}
	b.StopTimer()

	if !bytes.Equal(m, d) {
		b.Fatalf("Open output mismatch")
	}
}
