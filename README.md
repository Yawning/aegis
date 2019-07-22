### AEGIS-128 Authenticated Cipher
#### Yawning Angel (yawning at schwanenlied dot me)

This package implements the [AEGIS-128][1] algorithm from the
[final CAESAR portfolio][2].

For now this implementation **REQUIRES** a 64 bit Intel target that supports
both AVX and AES-NI.  If a more compaitible AEAD primitive is needed, either
send patches or use [ChaCha20/Poly1305][3] or [Deoxys-II][4].

#### Notes

Performance is quite good, handily outperforming GCM-AES128 under most
conditions.

The gratuitous use of AVX is due to VEX coding being more pleasant to work
with, especially when implementing the `StateUpdate128(S_i, m_i)` function.
Performance with just SSE2 and AES-NI should still be quite good, if someone
feels the need to implement such a thing.

The spec as of v1.1 neglects to specify the byte order to be used when
encoding `adlen` and `msglen` during finalization.  The reference
implementation is likewise not endian-safe.  A little-endian host was
used when generating the official test vectors, so that is what is used here.

[1]: https://www3.ntu.edu.sg/home/wuhj/research/caesar/caesar.html
[2]: https://competitions.cr.yp.to/caesar-submissions.html
[3]: https://godoc.org/golang.org/x/crypto/chacha20poly1305
[4]: https://godoc.org/github.com/oasislabs/deoxysii
