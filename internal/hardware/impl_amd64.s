// +build !noasm

#include "textflag.h"

#define copy(dst, src, len) \
	MOVQ src, SI \
	MOVQ dst, DI \
	MOVQ len, CX \
	REP          \
	MOVSB

// StateUpdate128(S_i, m_i)
//  * S_i:     X0, .., X4
//  * m_i:     m (XMM register)
//  * Scratch: X15
#define state_update(m) \
	VMOVDQA X4, X15     \
	VAESENC X4, X3, X4  \ // S_(i+1,4) = AESRound(S_(i,3), S_(i,4))
	VAESENC X3, X2, X3  \ // S_(i+1,3) = AESRound(S_(i,2), S_(i,3))
	VAESENC X2, X1, X2  \ // S_(i+1,2) = AESRound(S_(i,1), S_(i,2))
	VAESENC X1, X0, X1  \ // S_(i+1,1) = AESRound(S_(i,0), S_(i,1))
	VAESENC X0, X15, X0 \ // S_(i+1,0) = AESRound(S_(i,4), S_(i,0) ^ m_i)
	VPXOR   X0, m, X0

// 2.3.2 The initialization of AEGIS-128
//  * function args: constant/key/nonce
//  * S_i:           X0, ..., X4
#define load_state() \
	MOVQ    constant+0(FP), R15 \ // constant
	MOVQ    key+8(FP), R14      \ // key
	MOVQ    nonce+16(FP), R13   \ // nonce
	                            \
	VMOVDQU (R14), X5           \ // K_128
	VMOVDQU (R13), X6           \ // IV_128
	VMOVDQA (R15), X7           \ // const_0
	VMOVDQA 16(R15), X8         \ // const_1
	                            \
	VPXOR   X5, X6, X0          \ // S_(-10,0) = K_128 ^ IV_128
	VMOVDQA X8, X1              \ // S_(-10,1) = const_1
	VMOVDQA X7, X2              \ // S_(-10,2) = const_0
	VPXOR   X5, X7, X3          \ // S_(-10,3) = K_128 ^ const_0
	VPXOR   X5, X8, X4          \ // S_(-10,4) = K_128 ^ const_1
	                            \
	VMOVDQA X0, X6              \ // X6 = K_128 ^ IV_128 (X5 has K_128 already).
	                            \
	state_update(X5)            \ // For i = -10 to -1, S_(i+1) = StateUpdate128(S_i, m_i)
	state_update(X6)            \
	state_update(X5)            \
	state_update(X6)            \
	state_update(X5)            \
	state_update(X6)            \
	state_update(X5)            \
	state_update(X6)            \
	state_update(X5)            \
	state_update(X6)

// 2.3.3 Processing the authenticated data
//  * function args: additionalData
//  * S_i:           X0, ..., X4
#define process_ad() \
	MOVQ additionalData+72(FP), R15 \ // &additionalData[0]
	MOVQ additionalData+80(FP), R14 \ // len(additionalData)
	MOVQ           R14, AX          \
	SHRQ           $4, AX           \
	JZ             absorbPartial    \
	loopAbsorb:                     \
	VMOVDQU        (R15), X5        \
	state_update(X5)                \ // S_(i+1) = StateUpdate128(S_i, AD_i)
	ADDQ           $16, R15         \
	SUBQ           $1, AX           \
	JNZ            loopAbsorb       \
	absorbPartial:                  \
	ANDQ           $15, R14         \ // Like `loopAbsorb` but the trailing partial block is padded with 0 bits.
	JZ             absorbDone       \
	VPXOR          X5, X5, X5       \
	VMOVDQU        X5, (BP)         \
	copy(BP, R15, R14)              \
	VMOVDQU        (BP), X5         \
	state_update(X5)                \
	absorbDone:

// 2.3.5 The finalization of AEGIS-128
//  * S_i:           X0, ..., X4
#define finalize(dst, adlen, msglen) \
	SHLQ    $3, adlen     \
	SHLQ    $3, msglen    \
	MOVQ    adlen, (BP)   \
	MOVQ    msglen, 8(BP) \
	VMOVDQU (BP), X5      \
	VPXOR   X5, X3, X5    \ // tmp = S_(u+v,3) ^ (adlen || msglen)
	                      \
	state_update(X5)      \ // For i = u + v to u + v + 6 we update the state: S_(i+1) = StateUpdate128(s_i, tmp)
	state_update(X5)      \
	state_update(X5)      \
	state_update(X5)      \
	state_update(X5)      \
	state_update(X5)      \
	state_update(X5)      \
	                      \
	VPXOR   X0, X1, X0    \ // T = S_(u+v+7,0) ^ ... ^ S_(u+v+7, 4)
	VPXOR   X0, X2, X0    \
	VPXOR   X0, X3, X0    \
	VPXOR   X0, X4, X0    \
	                      \
	VMOVDQU X0, (dst)

// func sealAVX2(constant, key, nonce *byte, dst, plaintext, additionalData []byte)
TEXT ·sealAVX2(SB), NOSPLIT|NOFRAME, $16-96
	MOVQ SP, BP

	load_state()
	process_ad()

	MOVQ dst+24(FP), R15       // &dst[0]
	MOVQ plaintext+48(FP), R14 // &plaintext[0]
	MOVQ plaintext+56(FP), R13 // len(plaintext)

	MOVQ R13, AX
	SHRQ $4, AX
	JZ   encryptPartial

loopEncrypt:
	// C_i = P_i ^ S_(u+i,1) ^ S_(u+i,4) ^ (S_(u+i,2) & S_(u+i,3))
	VMOVDQU (R14), X5
	VPAND   X2, X3, X6
	VPXOR   X6, X1, X6
	VPXOR   X6, X4, X6
	VPXOR   X6, X5, X6
	VMOVDQU X6, (R15)

	// S_(u+i+1) = StateUpdate128(S_(u+i), P_i)
	state_update(X5)

	ADDQ $16, R15
	ADDQ $16, R14
	SUBQ $1, AX
	JNZ  loopEncrypt

encryptPartial:
	// Like `loopEncrypt` but the trailing partial block is padded with 0 bits.
	ANDQ    $15, R13
	JZ      encryptDone
	VPXOR   X5, X5, X5
	VMOVDQU X5, (BP)
	copy(BP, R14, R13)
	VMOVDQU (BP), X5
	VPAND   X2, X3, X6
	VPXOR   X6, X1, X6
	VPXOR   X6, X4, X6
	VPXOR   X6, X5, X6
	VMOVDQU X6, (BP)
	state_update(X5)
	copy(R15, BP, R13)
	ADDQ    R13, R15

encryptDone:
	// Finalize and write tag.
	MOVQ additionalData+80(FP), R14
	MOVQ plaintext+56(FP), R13
	finalize(R15, R14, R13)

	VZEROALL
	RET

// func openAVX2(constant, key, nonce *byte, dst, ciphertext, additionalData []byte, tag *byte)
TEXT ·openAVX2(SB), NOSPLIT|NOFRAME, $16-104
	MOVQ SP, BP

	load_state()
	process_ad()

	MOVQ dst+24(FP), R15        // &dst[0]
	MOVQ ciphertext+48(FP), R14 // &ciphertext[0]
	MOVQ ciphertext+56(FP), R13 // len(ciphertext)
	SUBQ $16, R13
	MOVQ R13, R12

	MOVQ R13, AX
	SHRQ $4, AX
	JZ   decryptPartial

loopDecrypt:
	// P_i = C_i ^ S_(u+i,1) ^ S_(u+i,4) ^ (S_(u+i,2) & S_(u+i,3))
	VMOVDQU (R14), X5
	VPAND   X2, X3, X6
	VPXOR   X6, X1, X6
	VPXOR   X6, X4, X6
	VPXOR   X6, X5, X6
	VMOVDQU X6, (R15)

	// S_(u+i+1) = StateUpdate128(S_(u+i), P_i)
	state_update(X6)

	ADDQ $16, R15
	ADDQ $16, R14
	SUBQ $1, AX
	JNZ  loopDecrypt

decryptPartial:
	// Like `loopDecrypt` but the trailing partial block is padded with 0 bits.
	ANDQ    $15, R13
	JZ      decryptDone
	VPXOR   X5, X5, X5
	VMOVDQU X5, (BP)
	copy(BP, R14, R13)
	VMOVDQU (BP), X5
	VPAND   X2, X3, X6
	VPXOR   X6, X1, X6
	VPXOR   X6, X4, X6
	VPXOR   X6, X5, X6
	VMOVDQU X6, (BP)
	state_update(X6)
	copy(R15, BP, R13)

	// The state was updated with the encrypted padding, when it needs to be
	// updated with the plaintext padding.  Fix up the state with an XOR.
	MOVQ    $0, AX
	MOVQ    BP, DI
	MOVQ    R13, CX
	REP
	STOSB
	VMOVDQU (BP), X6
	VPXOR   X0, X6, X0

decryptDone:
	// Finalize and write tag.
	MOVQ additionalData+80(FP), R15
	MOVQ tag+96(FP), R14
	finalize(R14, R15, R12)

	VZEROALL
	VMOVDQU X0, (BP) // Probably unneeded.
	RET
