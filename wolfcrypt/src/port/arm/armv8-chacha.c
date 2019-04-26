/* armv8-chacha.c
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 */


#ifdef WOLFSSL_ARMASM

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_CHACHA

#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/cpuid.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef CHACHA_AEAD_TEST
    #include <stdio.h>
#endif

#ifdef BIG_ENDIAN_ORDER
    #define LITTLE32(x) ByteReverseWord32(x)
#else
    #define LITTLE32(x) (x)
#endif

/* Number of rounds */
#define ROUNDS  20

#define U32C(v) (v##U)
#define U32V(v) ((word32)(v) & U32C(0xFFFFFFFF))
#define U8TO32_LITTLE(p) LITTLE32(((word32*)(p))[0])

#define ROTATE(v,c) rotlFixed(v, c)
#define XOR(v,w)    ((v) ^ (w))
#define PLUS(v,w)   (U32V((v) + (w)))
#define PLUSONE(v)  (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  output[a] = PLUS(output[a],output[b]); output[d] = ROTATE(XOR(output[d],output[a]),16); \
  output[c] = PLUS(output[c],output[d]); output[b] = ROTATE(XOR(output[b],output[c]),12); \
  output[a] = PLUS(output[a],output[b]); output[d] = ROTATE(XOR(output[d],output[a]), 8); \
  output[c] = PLUS(output[c],output[d]); output[b] = ROTATE(XOR(output[b],output[c]), 7);

#define ARM_SIMD_LEN_BYTES 16

/**
  * Set up iv(nonce). Earlier versions used 64 bits instead of 96, this version
  * uses the typical AEAD 96 bit nonce and can do record sizes of 256 GB.
  */
int wc_Chacha_SetIV(ChaCha* ctx, const byte* inIv, word32 counter)
{
    word32 temp[CHACHA_IV_WORDS];/* used for alignment of memory */

#ifdef CHACHA_AEAD_TEST
    word32 i;
    printf("NONCE : ");
    for (i = 0; i < CHACHA_IV_BYTES; i++) {
        printf("%02x", inIv[i]);
    }
    printf("\n\n");
#endif

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    XMEMCPY(temp, inIv, CHACHA_IV_BYTES);

    ctx->X[CHACHA_IV_BYTES+0] = counter;           /* block counter */
    ctx->X[CHACHA_IV_BYTES+1] = LITTLE32(temp[0]); /* fixed variable from nonce */
    ctx->X[CHACHA_IV_BYTES+2] = LITTLE32(temp[1]); /* counter from nonce */
    ctx->X[CHACHA_IV_BYTES+3] = LITTLE32(temp[2]); /* counter from nonce */

    return 0;
}

/* "expand 32-byte k" as unsigned 32 byte */
static const word32 sigma[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
/* "expand 16-byte k" as unsigned 16 byte */
static const word32 tau[4] = {0x61707865, 0x3120646e, 0x79622d36, 0x6b206574};

/**
  * Key setup. 8 word iv (nonce)
  */
int wc_Chacha_SetKey(ChaCha* ctx, const byte* key, word32 keySz)
{
    const word32* constants;
    const byte*   k;

#ifdef XSTREAM_ALIGN
    word32 alignKey[8];
#endif

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    if (keySz != (CHACHA_MAX_KEY_SZ/2) && keySz != CHACHA_MAX_KEY_SZ)
        return BAD_FUNC_ARG;

#ifdef XSTREAM_ALIGN
    if ((wolfssl_word)key % 4) {
        WOLFSSL_MSG("wc_ChachaSetKey unaligned key");
        XMEMCPY(alignKey, key, keySz);
        k = (byte*)alignKey;
    }
    else {
        k = key;
    }
#else
    k = key;
#endif /* XSTREAM_ALIGN */

#ifdef CHACHA_AEAD_TEST
    word32 i;
    printf("ChaCha key used :\n");
    for (i = 0; i < keySz; i++) {
        printf("%02x", key[i]);
        if ((i + 1) % 8 == 0)
           printf("\n");
    }
    printf("\n\n");
#endif

    ctx->X[4] = U8TO32_LITTLE(k +  0);
    ctx->X[5] = U8TO32_LITTLE(k +  4);
    ctx->X[6] = U8TO32_LITTLE(k +  8);
    ctx->X[7] = U8TO32_LITTLE(k + 12);
    if (keySz == CHACHA_MAX_KEY_SZ) {
        k += 16;
        constants = sigma;
    }
    else {
        constants = tau;
    }
    ctx->X[ 8] = U8TO32_LITTLE(k +  0);
    ctx->X[ 9] = U8TO32_LITTLE(k +  4);
    ctx->X[10] = U8TO32_LITTLE(k +  8);
    ctx->X[11] = U8TO32_LITTLE(k + 12);
    ctx->X[ 0] = constants[0];
    ctx->X[ 1] = constants[1];
    ctx->X[ 2] = constants[2];
    ctx->X[ 3] = constants[3];

    return 0;
}

/**
  * Converts word into bytes with rotations having been done.
  */
static WC_INLINE int wc_Chacha_wordtobyte_320(const word32 input[CHACHA_CHUNK_WORDS], const byte* m, byte* c, word32 bytes)
{
#ifdef __aarch64__
    __asm__ __volatile__ (
            // The paper NEON crypto by Daniel J. Bernstein and Peter Schwabe was used to optimize for ARM
            // https://cryptojedi.org/papers/neoncrypto-20120320.pdf

            "LD1 { v24.4S-v27.4S }, [%[input]] \n"

            "outer_loop_320_%=: \n"
            "SUB %[outer_rounds], %[outer_rounds], #1 \n"

            // fifth chacha block is stored in w1-w16 regular registers
            "MOV x1, v24.D[0] \n"
            "MOV x3, v24.D[1] \n"
            "MOV x5, v25.D[0] \n"
            "MOV x7, v25.D[1] \n"
            "MOV x9, v26.D[0] \n"
            "MOV x11, v26.D[1] \n"
            "MOV x13, v27.D[0] \n"
            "MOV x15, v27.D[1] \n"

            // the i'th element of the n'th block is the vi SIMD register
            //
            //     the first number is the i'th element
            //     the second number is the n'th block
            // v0  00  01  02  03
            // v1  10  11  12  13
            // v2  20  21  22  23
            // v3  30  31  32  33
            // ...
            // v0-v15 4 blocks of chacha
            // v16-v19 helper registers
            "MOV w0,  v27.S[0] \n"
            "DUP v0.4S,  v24.S[0] \n"
            "LSR x2, x1, #32 \n"
            "DUP v1.4S,  v24.S[1] \n"
            "LSR x4, x3, #32 \n"
            "DUP v2.4S,  v24.S[2] \n"
            "LSR x6, x5, #32 \n"
            "DUP v3.4S,  v24.S[3] \n"
            "LSR x8, x7, #32 \n"
            "DUP v4.4S,  v25.S[0] \n"
            "LSR x10, x9, #32 \n"
            "DUP v5.4S,  v25.S[1] \n"
            "LSR x12, x11, #32 \n"
            "DUP v6.4S,  v25.S[2] \n"
            "LSR x14, x13, #32 \n"
            "DUP v7.4S,  v25.S[3] \n"
            "LSR x16, x15, #32 \n"
            "DUP v8.4S,  v26.S[0] \n"
            "ADD w17, w0, #1 \n"
            "DUP v9.4S,  v26.S[1] \n"
            "ADD w18, w0, #2 \n"
            "DUP v10.4S, v26.S[2] \n"
            "ADD w19, w0, #3 \n"
            "DUP v11.4S, v26.S[3] \n"
            "ADD w20, w0, #4 \n"
            "DUP v12.4S, v27.S[0] \n"
            "DUP v13.4S, v27.S[1] \n"
            "DUP v14.4S, v27.S[2] \n"
            "DUP v15.4S, v27.S[3] \n"

            "MOV v12.S[1], w17 \n"
            "MOV v12.S[2], w18 \n"
            "MOV v12.S[3], w19 \n"
            "MOV w13, w20 \n"

            "MOV x0, %[rounds] \n" // Load loop counter

            "loop_320_%=: \n"
            "SUB x0, x0, #1 \n"

            // odd round

            "ADD v0.4S, v0.4S, v4.4S \n"
            "ADD w1, w1, w5 \n"
            "ADD v1.4S, v1.4S, v5.4S \n"
            "ADD w2, w2, w6 \n"
            "ADD v2.4S, v2.4S, v6.4S \n"
            "ADD w3, w3, w7 \n"
            "ADD v3.4S, v3.4S, v7.4S \n"
            "ADD w4, w4, w8 \n"

            "EOR v12.16b, v12.16b, v0.16b \n"
            "EOR w13, w13, w1 \n"
            "EOR v13.16b, v13.16b, v1.16b \n"
            "EOR w14, w14, w2 \n"
            "EOR v14.16b, v14.16b, v2.16b \n"
            "EOR w15, w15, w3 \n"
            "EOR v15.16b, v15.16b, v3.16b \n"
            "EOR w16, w16, w4 \n"

            "REV32 v12.8H, v12.8H \n"
            "ROR w13, w13, #16 \n"
            "REV32 v13.8H, v13.8H \n"
            "ROR w14, w14, #16 \n"
            "REV32 v14.8H, v14.8H \n"
            "ROR w15, w15, #16 \n"
            "REV32 v15.8H, v15.8H \n"
            "ROR w16, w16, #16 \n"

            "ADD v8.4S, v8.4S, v12.4S \n"
            "ADD w9, w9, w13 \n"
            "ADD v9.4S, v9.4S, v13.4S \n"
            "ADD w10, w10, w14 \n"
            "ADD v10.4S, v10.4S, v14.4S \n"
            "ADD w11, w11, w15 \n"
            "ADD v11.4S, v11.4S, v15.4S \n"
            "ADD w12, w12, w16 \n"

            "EOR v16.16b, v4.16b, v8.16b \n"
            "EOR w5, w5, w9 \n"
            "EOR v17.16b, v5.16b, v9.16b \n"
            "EOR w6, w6, w10 \n"
            "EOR v18.16b, v6.16b, v10.16b \n"
            "EOR w7, w7, w11 \n"
            "EOR v19.16b, v7.16b, v11.16b \n"
            "EOR w8, w8, w12 \n"

            "SHL v4.4S, v16.4S, #12 \n"
            "ROR w5, w5, #20 \n"
            "SHL v5.4S, v17.4S, #12 \n"
            "ROR w6, w6, #20 \n"
            "SHL v6.4S, v18.4S, #12 \n"
            "ROR w7, w7, #20 \n"
            "SHL v7.4S, v19.4S, #12 \n"
            "ROR w8, w8, #20 \n"

            "SRI v4.4S, v16.4S, #20 \n"
            "SRI v5.4S, v17.4S, #20 \n"
            "SRI v6.4S, v18.4S, #20 \n"
            "SRI v7.4S, v19.4S, #20 \n"

            "ADD v0.4S, v0.4S, v4.4S \n"
            "ADD w1, w1, w5 \n"
            "ADD v1.4S, v1.4S, v5.4S \n"
            "ADD w2, w2, w6 \n"
            "ADD v2.4S, v2.4S, v6.4S \n"
            "ADD w3, w3, w7 \n"
            "ADD v3.4S, v3.4S, v7.4S \n"
            "ADD w4, w4, w8 \n"

            "EOR v16.16b, v12.16b, v0.16b \n"
            "EOR w13, w13, w1 \n"
            "EOR v17.16b, v13.16b, v1.16b \n"
            "EOR w14, w14, w2 \n"
            "EOR v18.16b, v14.16b, v2.16b \n"
            "EOR w15, w15, w3 \n"
            "EOR v19.16b, v15.16b, v3.16b \n"
            "EOR w16, w16, w4 \n"

            "SHL v12.4S, v16.4S, #8 \n"
            "ROR w13, w13, #24 \n"
            "SHL v13.4S, v17.4S, #8 \n"
            "ROR w14, w14, #24 \n"
            "SHL v14.4S, v18.4S, #8 \n"
            "ROR w15, w15, #24 \n"
            "SHL v15.4S, v19.4S, #8 \n"
            "ROR w16, w16, #24 \n"

            "SRI v12.4S, v16.4S, #24 \n"
            "SRI v13.4S, v17.4S, #24 \n"
            "SRI v14.4S, v18.4S, #24 \n"
            "SRI v15.4S, v19.4S, #24 \n"

            "ADD v8.4S, v8.4S, v12.4S \n"
            "ADD w9, w9, w13 \n"
            "ADD v9.4S, v9.4S, v13.4S \n"
            "ADD w10, w10, w14 \n"
            "ADD v10.4S, v10.4S, v14.4S \n"
            "ADD w11, w11, w15 \n"
            "ADD v11.4S, v11.4S, v15.4S \n"
            "ADD w12, w12, w16 \n"

            "EOR v16.16b, v4.16b, v8.16b \n"
            "EOR w5, w5, w9 \n"
            "EOR v17.16b, v5.16b, v9.16b \n"
            "EOR w6, w6, w10 \n"
            "EOR v18.16b, v6.16b, v10.16b \n"
            "EOR w7, w7, w11 \n"
            "EOR v19.16b, v7.16b, v11.16b \n"
            "EOR w8, w8, w12 \n"

            "SHL v4.4S, v16.4S, #7 \n"
            "ROR w5, w5, #25 \n"
            "SHL v5.4S, v17.4S, #7 \n"
            "ROR w6, w6, #25 \n"
            "SHL v6.4S, v18.4S, #7 \n"
            "ROR w7, w7, #25 \n"
            "SHL v7.4S, v19.4S, #7 \n"
            "ROR w8, w8, #25 \n"

            "SRI v4.4S, v16.4S, #25 \n"
            "SRI v5.4S, v17.4S, #25 \n"
            "SRI v6.4S, v18.4S, #25 \n"
            "SRI v7.4S, v19.4S, #25 \n"

            // even round

            "ADD v0.4S, v0.4S, v5.4S \n"
            "ADD w1, w1, w6 \n"
            "ADD v1.4S, v1.4S, v6.4S \n"
            "ADD w2, w2, w7 \n"
            "ADD v2.4S, v2.4S, v7.4S \n"
            "ADD w3, w3, w8 \n"
            "ADD v3.4S, v3.4S, v4.4S \n"
            "ADD w4, w4, w5 \n"

            "EOR v15.16b, v15.16b, v0.16b \n"
            "EOR w16, w16, w1 \n"
            "EOR v12.16b, v12.16b, v1.16b \n"
            "EOR w13, w13, w2 \n"
            "EOR v13.16b, v13.16b, v2.16b \n"
            "EOR w14, w14, w3 \n"
            "EOR v14.16b, v14.16b, v3.16b \n"
            "EOR w15, w15, w4 \n"

            "REV32 v15.8H, v15.8H \n"
            "ROR w16, w16, #16 \n"
            "REV32 v12.8H, v12.8H \n"
            "ROR w13, w13, #16 \n"
            "REV32 v13.8H, v13.8H \n"
            "ROR w14, w14, #16 \n"
            "REV32 v14.8H, v14.8H \n"
            "ROR w15, w15, #16 \n"

            "ADD v10.4S, v10.4S, v15.4S \n"
            "ADD w11, w11, w16 \n"
            "ADD v11.4S, v11.4S, v12.4S \n"
            "ADD w12, w12, w13 \n"
            "ADD v8.4S, v8.4S, v13.4S \n"
            "ADD w9, w9, w14 \n"
            "ADD v9.4S, v9.4S, v14.4S \n"
            "ADD w10, w10, w15 \n"

            "EOR v16.16b, v5.16b, v10.16b \n"
            "EOR w6, w6, w11 \n"
            "EOR v17.16b, v6.16b, v11.16b \n"
            "EOR w7, w7, w12 \n"
            "EOR v18.16b, v7.16b, v8.16b \n"
            "EOR w8, w8, w9 \n"
            "EOR v19.16b, v4.16b, v9.16b \n"
            "EOR w5, w5, w10 \n"

            "SHL v5.4S, v16.4S, #12 \n"
            "ROR w6, w6, #20 \n"
            "SHL v6.4S, v17.4S, #12 \n"
            "ROR w7, w7, #20 \n"
            "SHL v7.4S, v18.4S, #12 \n"
            "ROR w8, w8, #20 \n"
            "SHL v4.4S, v19.4S, #12 \n"
            "ROR w5, w5, #20 \n"

            "SRI v5.4S, v16.4S, #20 \n"
            "SRI v6.4S, v17.4S, #20 \n"
            "SRI v7.4S, v18.4S, #20 \n"
            "SRI v4.4S, v19.4S, #20 \n"

            "ADD v0.4S, v0.4S, v5.4S \n"
            "ADD w1, w1, w6 \n"
            "ADD v1.4S, v1.4S, v6.4S \n"
            "ADD w2, w2, w7 \n"
            "ADD v2.4S, v2.4S, v7.4S \n"
            "ADD w3, w3, w8 \n"
            "ADD v3.4S, v3.4S, v4.4S \n"
            "ADD w4, w4, w5 \n"

            "EOR v16.16b, v15.16b, v0.16b \n"
            "EOR w16, w16, w1 \n"
            "EOR v17.16b, v12.16b, v1.16b \n"
            "EOR w13, w13, w2 \n"
            "EOR v18.16b, v13.16b, v2.16b \n"
            "EOR w14, w14, w3 \n"
            "EOR v19.16b, v14.16b, v3.16b \n"
            "EOR w15, w15, w4 \n"

            "SHL v15.4S, v16.4S, #8 \n"
            "ROR w16, w16, #24 \n"
            "SHL v12.4S, v17.4S, #8 \n"
            "ROR w13, w13, #24 \n"
            "SHL v13.4S, v18.4S, #8 \n"
            "ROR w14, w14, #24 \n"
            "SHL v14.4S, v19.4S, #8 \n"
            "ROR w15, w15, #24 \n"

            "SRI v15.4S, v16.4S, #24 \n"
            "SRI v12.4S, v17.4S, #24 \n"
            "SRI v13.4S, v18.4S, #24 \n"
            "SRI v14.4S, v19.4S, #24 \n"

            "ADD v10.4S, v10.4S, v15.4S \n"
            "ADD w11, w11, w16 \n"
            "ADD v11.4S, v11.4S, v12.4S \n"
            "ADD w12, w12, w13 \n"
            "ADD v8.4S, v8.4S, v13.4S \n"
            "ADD w9, w9, w14 \n"
            "ADD v9.4S, v9.4S, v14.4S \n"
            "ADD w10, w10, w15 \n"

            "EOR v16.16b, v5.16b, v10.16b \n"
            "EOR w6, w6, w11 \n"
            "EOR v17.16b, v6.16b, v11.16b \n"
            "EOR w7, w7, w12 \n"
            "EOR v18.16b, v7.16b, v8.16b \n"
            "EOR w8, w8, w9 \n"
            "EOR v19.16b, v4.16b, v9.16b \n"
            "EOR w5, w5, w10 \n"

            "SHL v5.4S, v16.4S, #7 \n"
            "ROR w6, w6, #25 \n"
            "SHL v6.4S, v17.4S, #7 \n"
            "ROR w7, w7, #25 \n"
            "SHL v7.4S, v18.4S, #7 \n"
            "ROR w8, w8, #25 \n"
            "SHL v4.4S, v19.4S, #7 \n"
            "ROR w5, w5, #25 \n"

            "SRI v5.4S, v16.4S, #25 \n"
            "SRI v6.4S, v17.4S, #25 \n"
            "SRI v7.4S, v18.4S, #25 \n"
            "SRI v4.4S, v19.4S, #25 \n"

            "CBNZ x0, loop_320_%= \n"

            "LD1 { v28.4S-v31.4S }, [%[m]] \n"
            "ADD %[m], %[m], %[chacha_chunk_bytes] \n"

            // Transpose to have words in the same registers
            //
            //    the first number is the i'th element
            //    the second number is the n'th block
            // v0 00 10 20 30
            // v1 01 11 21 31
            // v2 02 12 22 32
            // v3 03 13 23 33
            // ...
            "TRN1 v16.4S, v0.4S, v1.4S \n"
            "TRN2 v17.4S, v0.4S, v1.4S \n"
            "TRN1 v18.4S, v2.4S, v3.4S \n"
            "TRN2 v19.4S, v2.4S, v3.4S \n"
            "TRN1 v0.2D, v16.2D, v18.2D \n"
            "TRN2 v2.2D, v16.2D, v18.2D \n"
            "TRN1 v1.2D, v17.2D, v19.2D \n"
            "TRN2 v3.2D, v17.2D, v19.2D \n"

            "TRN1 v16.4S, v4.4S, v5.4S \n"
            "TRN2 v17.4S, v4.4S, v5.4S \n"
            "TRN1 v18.4S, v6.4S, v7.4S \n"
            "TRN2 v19.4S, v6.4S, v7.4S \n"
            "TRN1 v4.2D, v16.2D, v18.2D \n"
            "TRN2 v6.2D, v16.2D, v18.2D \n"
            "TRN1 v5.2D, v17.2D, v19.2D \n"
            "TRN2 v7.2D, v17.2D, v19.2D \n"

            "TRN1 v16.4S, v8.4S, v9.4S \n"
            "TRN2 v17.4S, v8.4S, v9.4S \n"
            "TRN1 v18.4S, v10.4S, v11.4S \n"
            "TRN2 v19.4S, v10.4S, v11.4S \n"
            "TRN1 v8.2D, v16.2D, v18.2D \n"
            "TRN2 v10.2D, v16.2D, v18.2D \n"
            "TRN1 v9.2D, v17.2D, v19.2D \n"
            "TRN2 v11.2D, v17.2D, v19.2D \n"

            "TRN1 v16.4S, v12.4S, v13.4S \n"
            "TRN2 v17.4S, v12.4S, v13.4S \n"
            "TRN1 v18.4S, v14.4S, v15.4S \n"
            "TRN2 v19.4S, v14.4S, v15.4S \n"
            "TRN1 v12.2D, v16.2D, v18.2D \n"
            "TRN2 v14.2D, v16.2D, v18.2D \n"
            "TRN1 v13.2D, v17.2D, v19.2D \n"
            "TRN2 v15.2D, v17.2D, v19.2D \n"


            "ADD v16.4S, v0.4S, v24.4S \n"
            "ADD v17.4S, v4.4S, v25.4S \n"
            "ADD v18.4S, v8.4S, v26.4S \n"
            "ADD v19.4S, v12.4S, v27.4S \n"
            "EOR v16.16B, v16.16B, v28.16B \n"
            "EOR v17.16B, v17.16B, v29.16B \n"
            "EOR v18.16B, v18.16B, v30.16B \n"
            "EOR v19.16B, v19.16B, v31.16B \n"
            "LD1 { v28.4S-v31.4S }, [%[m]] \n"
            "ADD %[m], %[m], %[chacha_chunk_bytes] \n"
            "ST1 { v16.4S-v19.4S }, [%[c]] \n"
            "ADD %[c], %[c], %[chacha_chunk_bytes] \n"

            // increment counter
            "MOV v27.S[0], w17 \n"
            "ADD v16.4S, v1.4S, v24.4S \n"
            "ADD v17.4S, v5.4S, v25.4S \n"
            "ADD v18.4S, v9.4S, v26.4S \n"
            "ADD v19.4S, v13.4S, v27.4S \n"
            "EOR v16.16B, v16.16B, v28.16B \n"
            "EOR v17.16B, v17.16B, v29.16B \n"
            "EOR v18.16B, v18.16B, v30.16B \n"
            "EOR v19.16B, v19.16B, v31.16B \n"
            "LD1 { v28.4S-v31.4S }, [%[m]] \n"
            "ADD %[m], %[m], %[chacha_chunk_bytes] \n"
            "ST1 { v16.4S-v19.4S }, [%[c]] \n"
            "ADD %[c], %[c], %[chacha_chunk_bytes] \n"

            // increment counter
            "MOV v27.S[0], w18 \n"
            "ADD v16.4S, v2.4S, v24.4S \n"
            "ADD v17.4S, v6.4S, v25.4S \n"
            "ADD v18.4S, v10.4S, v26.4S \n"
            "ADD v19.4S, v14.4S, v27.4S \n"
            "EOR v16.16B, v16.16B, v28.16B \n"
            "EOR v17.16B, v17.16B, v29.16B \n"
            "EOR v18.16B, v18.16B, v30.16B \n"
            "EOR v19.16B, v19.16B, v31.16B \n"
            "LD1 { v28.4S-v31.4S }, [%[m]] \n"
            "ADD %[m], %[m], %[chacha_chunk_bytes] \n"
            "ST1 { v16.4S-v19.4S }, [%[c]] \n"
            "ADD %[c], %[c], %[chacha_chunk_bytes] \n"

            // increment counter
            "MOV v27.S[0], w19 \n"
            "ADD v16.4S, v3.4S, v24.4S \n"
            "ADD v17.4S, v7.4S, v25.4S \n"
            "ADD v18.4S, v11.4S, v26.4S \n"
            "ADD v19.4S, v15.4S, v27.4S \n"
            "EOR v16.16B, v16.16B, v28.16B \n"
            "EOR v17.16B, v17.16B, v29.16B \n"
            "EOR v18.16B, v18.16B, v30.16B \n"
            "EOR v19.16B, v19.16B, v31.16B \n"
            "LD1 { v28.4S-v31.4S }, [%[m]] \n"
            "ADD %[m], %[m], %[chacha_chunk_bytes] \n"
            "ST1 { v16.4S-v19.4S }, [%[c]] \n"
            "ADD %[c], %[c], %[chacha_chunk_bytes] \n"

            // increment counter
            "MOV v27.S[0], w20 \n"

            // move block from regular arm registers to v20-v23
            "ORR x1, x1, x2, LSL #32 \n"
            "ORR x3, x3, x4, LSL #32 \n"
            "ORR x5, x5, x6, LSL #32 \n"
            "MOV v20.D[0], x1 \n"
            "ORR x7, x7, x8, LSL #32 \n"
            "MOV v20.D[1], x3 \n"
            "ORR x9, x9, x10, LSL #32 \n"
            "MOV v21.D[0], x5 \n"
            "ORR x11, x11, x12, LSL #32 \n"
            "MOV v21.D[1], x7 \n"
            "ORR x13, x13, x14, LSL #32 \n"
            "MOV v22.D[0], x9 \n"
            "ORR x15, x15, x16, LSL #32 \n"
            "MOV v22.D[1], x11 \n"
            "MOV v23.D[0], x13 \n"
            "MOV v23.D[1], x15 \n"

            "ADD v20.4S, v20.4S, v24.4S \n"
            "ADD v21.4S, v21.4S, v25.4S \n"
            "ADD v22.4S, v22.4S, v26.4S \n"
            "ADD v23.4S, v23.4S, v27.4S \n"
            "EOR v20.16B, v20.16B, v28.16B \n"
            "EOR v21.16B, v21.16B, v29.16B \n"
            "EOR v22.16B, v22.16B, v30.16B \n"
            "EOR v23.16B, v23.16B, v31.16B \n"
            "ST1 { v20.4S-v23.4S }, [%[c]] \n"
            "ADD %[c], %[c], %[chacha_chunk_bytes] \n"

            "ADD w0, w20, #1 \n"
            "MOV v27.S[0], w0 \n"

            "CBNZ %[outer_rounds], outer_loop_320_%= \n"

            : [c] "=r" (c), [m] "=r" (m)
            : "0" (c), "1" (m), [rounds] "I" (ROUNDS/2), [input] "r" (input), [chacha_chunk_bytes] "I" (CHACHA_CHUNK_BYTES),
              [outer_rounds] "r" (bytes / (CHACHA_CHUNK_BYTES * MAX_CHACHA_BLOCKS))
            : "memory", "cc",
              "x0",
              "x1",  "x2",  "x3",  "x4",
              "x5",  "x6",  "x7",  "x8",
              "x9",  "x10", "x11", "x12",
              "x13", "x14", "x15", "x16",
              "x17", "x18", "x19", "x20",
              "v0",  "v1",  "v2",  "v3",  "v4",
              "v5",  "v6",  "v7",  "v8",  "v9",
              "v10", "v11", "v12", "v13", "v14",
              "v15", "v16", "v17", "v18", "v19",
              "v20", "v21", "v22", "v23",
              "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
    );
#endif /* __aarch64__ */

    return (bytes / (CHACHA_CHUNK_BYTES * MAX_CHACHA_BLOCKS)) * CHACHA_CHUNK_BYTES * MAX_CHACHA_BLOCKS;
}


/**
  * Converts word into bytes with rotations having been done.
  */
static WC_INLINE int wc_Chacha_wordtobyte_256(const word32 input[CHACHA_CHUNK_WORDS], const byte* m, byte* c)
{
#ifdef __aarch64__
    __asm__ __volatile__ (
            // The paper NEON crypto by Daniel J. Bernstein and Peter Schwabe was used to optimize for ARM
            // https://cryptojedi.org/papers/neoncrypto-20120320.pdf


            // v0-v3 - first block
            // v12 first block helper
            // v4-v7 - second block
            // v13 second block helper
            // v8-v11 - third block
            // v14 third block helper
            // w1-w16 - fourth block

            // v0  0  1  2  3
            // v1  4  5  6  7
            // v2  8  9 10 11
            // v3 12 13 14 15
            // load CHACHA state as shown above
            "LD1 { v0.4S-v3.4S }, [%[input]] \n"

            // get counter value
            "MOV w0, v3.S[0] \n"
            "ADD w17, w0, #2 \n"
            "ADD w0, w0, #1 \n"

            // load other registers with regular arm registers interleaved
            // final chacha block is stored in w1-w16 regular registers
            "MOV v4.16B, v0.16B \n"
            "MOV x1, v0.D[0] \n"
            "MOV v5.16B, v1.16B \n"
            "MOV x3, v0.D[1] \n"
            "MOV v6.16B, v2.16B \n"
            "LSR x2, x1, #32 \n"
            "MOV v7.16B, v3.16B \n"
            "LSR x4, x3, #32 \n"

            "MOV v8.16B, v0.16B \n"
            "MOV x5, v1.D[0] \n"
            "MOV v9.16B, v1.16B \n"
            "MOV x7, v1.D[1] \n"
            "MOV v10.16B, v2.16B \n"
            "LSR x6, x5, #32 \n"
            "MOV v11.16B, v3.16B \n"
            "LSR x8, x7, #32 \n"

            "MOV x9, v2.D[0] \n"
            "MOV x11, v2.D[1] \n"
            "MOV x13, v3.D[0] \n"
            "MOV x15, v3.D[1] \n"

            "LSR x10, x9, #32 \n"
            "LSR x12, x11, #32 \n"

            "LSR x14, x13, #32 \n"
            "LSR x16, x15, #32 \n"

            // set counter
            "ADD w13, w13, #3 \n"

            // load correct counter values
            "MOV v7.S[0], w0 \n"
            "MOV v11.S[0], w17 \n"

            "MOV x0, %[rounds] \n" // Load loop counter


            "loop_256_%=: \n"
            "SUB x0, x0, #1 \n"

            // ODD ROUND

            "ADD w1, w1, w5 \n"
            "ADD v0.4S, v0.4S, v1.4S \n"
            "ADD w2, w2, w6 \n"
            "ADD v4.4S, v4.4S, v5.4S \n"
            "ADD w3, w3, w7 \n"
            "ADD v8.4S, v8.4S, v9.4S \n"
            "ADD w4, w4, w8 \n"
            "EOR v12.16B, v3.16B, v0.16B \n"
            "EOR w13, w13, w1 \n"
            "EOR v13.16B, v7.16B, v4.16B \n"
            "EOR w14, w14, w2 \n"
            "EOR v14.16B, v11.16B, v8.16B \n"
            "EOR w15, w15, w3 \n"
            // rotation by 16 bits may be done by reversing the 16 bit elements in 32 bit words
            "REV32 v3.8H, v12.8H \n"
            "EOR w16, w16, w4 \n"
            "REV32 v7.8H, v13.8H \n"
            "ROR w13, w13, #16 \n"
            "REV32 v11.8H, v14.8H \n"
            "ROR w14, w14, #16 \n"

            "ADD v2.4S, v2.4S, v3.4S \n"
            "ROR w15, w15, #16 \n"
            "ADD v6.4S, v6.4S, v7.4S \n"
            "ROR w16, w16, #16 \n"
            "ADD v10.4S, v10.4S, v11.4S \n"
            "ADD w9, w9, w13 \n"
            "EOR v12.16B, v1.16B, v2.16B \n"
            "ADD w10, w10, w14 \n"
            "EOR v13.16B, v5.16B, v6.16B \n"
            "ADD w11, w11, w15 \n"
            "EOR v14.16B, v9.16B, v10.16B \n"
            "ADD w12, w12, w16 \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v1.4S, v12.4S, #12 \n"
            "EOR w5, w5, w9 \n"
            "SHL v5.4S, v13.4S, #12 \n"
            "EOR w6, w6, w10 \n"
            "SHL v9.4S, v14.4S, #12 \n"
            "EOR w7, w7, w11 \n"
            "SRI v1.4S, v12.4S, #20 \n"
            "EOR w8, w8, w12 \n"
            "SRI v5.4S, v13.4S, #20 \n"
            "ROR w5, w5, #20 \n"
            "SRI v9.4S, v14.4S, #20 \n"
            "ROR w6, w6, #20 \n"

            "ADD v0.4S, v0.4S, v1.4S \n"
            "ROR w7, w7, #20 \n"
            "ADD v4.4S, v4.4S, v5.4S \n"
            "ROR w8, w8, #20 \n"
            "ADD v8.4S, v8.4S, v9.4S \n"
            "ADD w1, w1, w5 \n"
            "EOR v12.16B, v3.16B, v0.16B \n"
            "ADD w2, w2, w6 \n"
            "EOR v13.16B, v7.16B, v4.16B \n"
            "ADD w3, w3, w7 \n"
            "EOR v14.16B, v11.16B, v8.16B \n"
            "ADD w4, w4, w8 \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v3.4S, v12.4S, #8 \n"
            "EOR w13, w13, w1 \n"
            "SHL v7.4S, v13.4S, #8 \n"
            "EOR w14, w14, w2 \n"
            "SHL v11.4S, v14.4S, #8 \n"
            "EOR w15, w15, w3 \n"
            "SRI v3.4S, v12.4S, #24 \n"
            "EOR w16, w16, w4 \n"
            "SRI v7.4S, v13.4S, #24 \n"
            "ROR w13, w13, #24 \n"
            "SRI v11.4S, v14.4S, #24 \n"
            "ROR w14, w14, #24 \n"

            "ADD v2.4S, v2.4S, v3.4S \n"
            "ROR w15, w15, #24 \n"
            "ADD v6.4S, v6.4S, v7.4S \n"
            "ROR w16, w16, #24 \n"
            "ADD v10.4S, v10.4S, v11.4S \n"
            "ADD w9, w9, w13 \n"
            "EOR v12.16B, v1.16B, v2.16B \n"
            "ADD w10, w10, w14 \n"
            "EOR v13.16B, v5.16B, v6.16B \n"
            "ADD w11, w11, w15 \n"
            "EOR v14.16B, v9.16B, v10.16B \n"
            "ADD w12, w12, w16 \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v1.4S, v12.4S, #7 \n"
            "EOR w5, w5, w9 \n"
            "SHL v5.4S, v13.4S, #7 \n"
            "EOR w6, w6, w10 \n"
            "SHL v9.4S, v14.4S, #7 \n"
            "EOR w7, w7, w11 \n"
            "SRI v1.4S, v12.4S, #25 \n"
            "EOR w8, w8, w12 \n"
            "SRI v5.4S, v13.4S, #25 \n"
            "ROR w5, w5, #25 \n"
            "SRI v9.4S, v14.4S, #25 \n"
            "ROR w6, w6, #25 \n"

            // EVEN ROUND

            // v0   0  1  2  3
            // v1   5  6  7  4
            // v2  10 11  8  9
            // v3  15 12 13 14
            // CHACHA block vector elements shifted as shown above

            "EXT v1.16B, v1.16B, v1.16B, #4 \n" // permute elements left by one
            "EXT v2.16B, v2.16B, v2.16B, #8 \n" // permute elements left by two
            "ROR w7, w7, #25 \n"
            "EXT v3.16B, v3.16B, v3.16B, #12 \n" // permute elements left by three

            "EXT v5.16B, v5.16B, v5.16B, #4 \n" // permute elements left by one
            "ROR w8, w8, #25 \n"
            "EXT v6.16B, v6.16B, v6.16B, #8 \n" // permute elements left by two
            "EXT v7.16B, v7.16B, v7.16B, #12 \n" // permute elements left by three

            "EXT v9.16B, v9.16B, v9.16B, #4 \n" // permute elements left by one
            "EXT v10.16B, v10.16B, v10.16B, #8 \n" // permute elements left by two
            "EXT v11.16B, v11.16B, v11.16B, #12 \n" // permute elements left by three

            "ADD v0.4S, v0.4S, v1.4S \n"
            "ADD w1, w1, w6 \n"
            "ADD v4.4S, v4.4S, v5.4S \n"
            "ADD w2, w2, w7 \n"
            "ADD v8.4S, v8.4S, v9.4S \n"
            "ADD w3, w3, w8 \n"
            "EOR v12.16B, v3.16B, v0.16B \n"
            "ADD w4, w4, w5 \n"
            "EOR v13.16B, v7.16B, v4.16B \n"
            "EOR w16, w16, w1 \n"
            "EOR v14.16B, v11.16B, v8.16B \n"
            "EOR w13, w13, w2 \n"
            // rotation by 16 bits may be done by reversing the 16 bit elements in 32 bit words
            "REV32 v3.8H, v12.8H \n"
            "EOR w14, w14, w3 \n"
            "REV32 v7.8H, v13.8H \n"
            "EOR w15, w15, w4 \n"
            "REV32 v11.8H, v14.8H \n"
            "ROR w16, w16, #16 \n"

            "ADD v2.4S, v2.4S, v3.4S \n"
            "ROR w13, w13, #16 \n"
            "ADD v6.4S, v6.4S, v7.4S \n"
            "ROR w14, w14, #16 \n"
            "ADD v10.4S, v10.4S, v11.4S \n"
            "ROR w15, w15, #16 \n"
            "EOR v12.16B, v1.16B, v2.16B \n"
            "ADD w11, w11, w16 \n"
            "EOR v13.16B, v5.16B, v6.16B \n"
            "ADD w12, w12, w13 \n"
            "EOR v14.16B, v9.16B, v10.16B \n"
            "ADD w9, w9, w14 \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v1.4S, v12.4S, #12 \n"
            "ADD w10, w10, w15 \n"
            "SHL v5.4S, v13.4S, #12 \n"
            "EOR w6, w6, w11 \n"
            "SHL v9.4S, v14.4S, #12 \n"
            "EOR w7, w7, w12 \n"
            "SRI v1.4S, v12.4S, #20 \n"
            "EOR w8, w8, w9 \n"
            "SRI v5.4S, v13.4S, #20 \n"
            "EOR w5, w5, w10 \n"
            "SRI v9.4S, v14.4S, #20 \n"
            "ROR w6, w6, #20 \n"

            "ADD v0.4S, v0.4S, v1.4S \n"
            "ROR w7, w7, #20 \n"
            "ADD v4.4S, v4.4S, v5.4S \n"
            "ROR w8, w8, #20 \n"
            "ADD v8.4S, v8.4S, v9.4S \n"
            "ROR w5, w5, #20 \n"
            "EOR v12.16B, v3.16B, v0.16B \n"
            "ADD w1, w1, w6 \n"
            "EOR v13.16B, v7.16B, v4.16B \n"
            "ADD w2, w2, w7 \n"
            "EOR v14.16B, v11.16B, v8.16B \n"
            "ADD w3, w3, w8 \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v3.4S, v12.4S, #8 \n"
            "ADD w4, w4, w5 \n"
            "SHL v7.4S, v13.4S, #8 \n"
            "EOR w16, w16, w1 \n"
            "SHL v11.4S, v14.4S, #8 \n"
            "EOR w13, w13, w2 \n"
            "SRI v3.4S, v12.4S, #24 \n"
            "EOR w14, w14, w3 \n"
            "SRI v7.4S, v13.4S, #24 \n"
            "EOR w15, w15, w4 \n"
            "SRI v11.4S, v14.4S, #24 \n"
            "ROR w16, w16, #24 \n"

            "ADD v2.4S, v2.4S, v3.4S \n"
            "ROR w13, w13, #24 \n"
            "ADD v6.4S, v6.4S, v7.4S \n"
            "ROR w14, w14, #24 \n"
            "ADD v10.4S, v10.4S, v11.4S \n"
            "ROR w15, w15, #24 \n"
            "EOR v12.16B, v1.16B, v2.16B \n"
            "ADD w11, w11, w16 \n"
            "EOR v13.16B, v5.16B, v6.16B \n"
            "ADD w12, w12, w13 \n"
            "EOR v14.16B, v9.16B, v10.16B \n"
            "ADD w9, w9, w14 \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v1.4S, v12.4S, #7 \n"
            "ADD w10, w10, w15 \n"
            "SHL v5.4S, v13.4S, #7 \n"
            "EOR w6, w6, w11 \n"
            "SHL v9.4S, v14.4S, #7 \n"
            "EOR w7, w7, w12 \n"
            "SRI v1.4S, v12.4S, #25 \n"
            "EOR w8, w8, w9 \n"
            "SRI v5.4S, v13.4S, #25 \n"
            "EOR w5, w5, w10 \n"
            "SRI v9.4S, v14.4S, #25 \n"
            "ROR w6, w6, #25 \n"

            "EXT v1.16B, v1.16B, v1.16B, #12 \n" // permute elements left by three
            "EXT v2.16B, v2.16B, v2.16B, #8 \n" // permute elements left by two
            "ROR w7, w7, #25 \n"
            "EXT v3.16B, v3.16B, v3.16B, #4 \n" // permute elements left by one

            "EXT v5.16B, v5.16B, v5.16B, #12 \n" // permute elements left by three
            "ROR w8, w8, #25 \n"
            "EXT v6.16B, v6.16B, v6.16B, #8 \n" // permute elements left by two
            "EXT v7.16B, v7.16B, v7.16B, #4 \n" // permute elements left by one
            "ROR w5, w5, #25 \n"

            "EXT v9.16B, v9.16B, v9.16B, #12 \n" // permute elements left by three
            "EXT v10.16B, v10.16B, v10.16B, #8 \n" // permute elements left by two
            "EXT v11.16B, v11.16B, v11.16B, #4 \n" // permute elements left by one

            "CBNZ x0, loop_256_%= \n"

            "LD1 { v24.4S-v27.4S }, [%[input]] \n"

            // counter
            "MOV w0, v27.S[0] \n"
            "ADD w0, w0, 1 \n"
            "LD1 { v28.4S-v31.4S }, [%[m]] \n"
            "ADD %[m], %[m], %[chacha_chunk_bytes] \n"

            "ADD v0.4S, v0.4S, v24.4S \n"
            "ADD v1.4S, v1.4S, v25.4S \n"
            "ADD v2.4S, v2.4S, v26.4S \n"
            "ADD v3.4S, v3.4S, v27.4S \n"
            "EOR v0.16B, v0.16B, v28.16B \n"
            "EOR v1.16B, v1.16B, v29.16B \n"
            "EOR v2.16B, v2.16B, v30.16B \n"
            "EOR v3.16B, v3.16B, v31.16B \n"
            "ST1 { v0.4S-v3.4S }, [%[c]] \n"
            "ADD %[c], %[c], %[chacha_chunk_bytes] \n"
            "LD1 { v28.4S-v31.4S }, [%[m]] \n"
            "ADD %[m], %[m], %[chacha_chunk_bytes] \n"

            // increment counter
            "MOV v27.S[0], w0 \n"
            "ADD w0, w0, 1 \n"
            "ADD v4.4S, v4.4S, v24.4S \n"
            "ADD v5.4S, v5.4S, v25.4S \n"
            "ADD v6.4S, v6.4S, v26.4S \n"
            "ADD v7.4S, v7.4S, v27.4S \n"
            "EOR v4.16B, v4.16B, v28.16B \n"
            "EOR v5.16B, v5.16B, v29.16B \n"
            "EOR v6.16B, v6.16B, v30.16B \n"
            "EOR v7.16B, v7.16B, v31.16B \n"
            "ST1 { v4.4S-v7.4S }, [%[c]] \n"
            "ADD %[c], %[c], %[chacha_chunk_bytes] \n"
            "LD1 { v28.4S-v31.4S }, [%[m]] \n"
            "ADD %[m], %[m], %[chacha_chunk_bytes] \n"

            // increment counter
            "MOV v27.S[0], w0 \n"
            "ADD w0, w0, 1 \n"
            "ADD v8.4S, v8.4S, v24.4S \n"
            "ADD v9.4S, v9.4S, v25.4S \n"
            "ADD v10.4S, v10.4S, v26.4S \n"
            "ADD v11.4S, v11.4S, v27.4S \n"
            "EOR v8.16B, v8.16B, v28.16B \n"
            "EOR v9.16B, v9.16B, v29.16B \n"
            "EOR v10.16B, v10.16B, v30.16B \n"
            "EOR v11.16B, v11.16B, v31.16B \n"
            "ST1 { v8.4S-v11.4S }, [%[c]] \n"
            "ADD %[c], %[c], %[chacha_chunk_bytes] \n"
            "LD1 { v28.4S-v31.4S }, [%[m]] \n"

            // increment counter
            "MOV v27.S[0], w0 \n"
            // move block from regular arm registers to v0-v3
            "ORR x1, x1, x2, LSL #32 \n"
            "ORR x3, x3, x4, LSL #32 \n"
            "MOV v0.D[0], x1 \n"
            "MOV v0.D[1], x3 \n"
            "ORR x5, x5, x6, LSL #32 \n"
            "ORR x7, x7, x8, LSL #32 \n"
            "MOV v1.D[0], x5 \n"
            "MOV v1.D[1], x7 \n"
            "ORR x9, x9, x10, LSL #32 \n"
            "ORR x11, x11, x12, LSL #32 \n"
            "MOV v2.D[0], x9 \n"
            "MOV v2.D[1], x11 \n"
            "ORR x13, x13, x14, LSL #32 \n"
            "ORR x15, x15, x16, LSL #32 \n"
            "MOV v3.D[0], x13 \n"
            "MOV v3.D[1], x15 \n"

            "ADD v0.4S, v0.4S, v24.4S \n"
            "ADD v1.4S, v1.4S, v25.4S \n"
            "ADD v2.4S, v2.4S, v26.4S \n"
            "ADD v3.4S, v3.4S, v27.4S \n"
            "EOR v0.16B, v0.16B, v28.16B \n"
            "EOR v1.16B, v1.16B, v29.16B \n"
            "EOR v2.16B, v2.16B, v30.16B \n"
            "EOR v3.16B, v3.16B, v31.16B \n"
            "ST1 { v0.4S-v3.4S }, [%[c]] \n"

            : [c] "=r" (c), [m] "=r" (m)
            : "0" (c), "1" (m), [rounds] "I" (ROUNDS/2), [input] "r" (input), [chacha_chunk_bytes] "I" (CHACHA_CHUNK_BYTES)
            : "memory", "cc",
              "x0",
              "x1",  "x2",  "x3",  "x4",
              "x5",  "x6",  "x7",  "x8",
              "x9",  "x10", "x11", "x12",
              "x13", "x14", "x15", "x16",
              "x17", "x18", "x19", "x20",
              "v0",  "v1",  "v2",  "v3",  "v4",
              "v5",  "v6",  "v7",  "v8",  "v9",
              "v10", "v11", "v12", "v13", "v14",
              "v15", "v16", "v17", "v18", "v19",
              "v20", "v21", "v22", "v23", "v24",
              "v25", "v26", "v27", "v28", "v29", "v30", "v31"
    );

    return CHACHA_CHUNK_BYTES * 4;
#endif /* __aarch64__ */
}


static WC_INLINE int wc_Chacha_wordtobyte_128(const word32 input[CHACHA_CHUNK_WORDS], const byte* m, byte* c)
{
#ifdef __aarch64__
    __asm__ __volatile__ (
            // The paper NEON crypto by Daniel J. Bernstein and Peter Schwabe was used to optimize for ARM
            // https://cryptojedi.org/papers/neoncrypto-20120320.pdf

            // v0-v3 - first block
            // v12 first block helper

            "LD1 { v24.4S-v27.4S }, [%[input]] \n"
            // get counter value
            "MOV w17, v27.S[0] \n"
            "ADD w17, w17, #1 \n"

            "LD1 { v28.4S-v31.4S }, [%[m]] \n"
            "ADD %[m], %[m], %[chacha_chunk_bytes] \n"


            // v0  0  1  2  3
            // v1  4  5  6  7
            // v2  8  9 10 11
            // v3 12 13 14 15
            // load CHACHA state as shown above
            "MOV v0.16B, v24.16B \n"
            "MOV v1.16B, v25.16B \n"
            "MOV v2.16B, v26.16B \n"
            "MOV v3.16B, v27.16B \n"
            "MOV v4.16B, v24.16B \n"
            "MOV v5.16B, v25.16B \n"
            "MOV v6.16B, v26.16B \n"
            "MOV v7.16B, v27.16B \n"
            "MOV v7.S[0], w17 \n"

            "loop_128_%=: \n"
            "SUB %[rounds], %[rounds], #1 \n"

            // ODD ROUND
            "ADD v0.4S, v0.4S, v1.4S \n"
            "ADD v4.4S, v4.4S, v5.4S \n"
            "EOR v12.16B, v3.16B, v0.16B \n"
            "EOR v13.16B, v7.16B, v4.16B \n"
            // rotation by 16 bits may be done by reversing the 16 bit elements in 32 bit words
            "REV32 v3.8H, v12.8H \n"
            "REV32 v7.8H, v13.8H \n"

            "ADD v2.4S, v2.4S, v3.4S \n"
            "ADD v6.4S, v6.4S, v7.4S \n"
            "EOR v12.16B, v1.16B, v2.16B \n"
            "EOR v13.16B, v5.16B, v6.16B \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v1.4S, v12.4S, #12 \n"
            "SHL v5.4S, v13.4S, #12 \n"
            "SRI v1.4S, v12.4S, #20 \n"
            "SRI v5.4S, v13.4S, #20 \n"

            "ADD v0.4S, v0.4S, v1.4S \n"
            "ADD v4.4S, v4.4S, v5.4S \n"
            "EOR v12.16B, v3.16B, v0.16B \n"
            "EOR v13.16B, v7.16B, v4.16B \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v3.4S, v12.4S, #8 \n"
            "SHL v7.4S, v13.4S, #8 \n"
            "SRI v3.4S, v12.4S, #24 \n"
            "SRI v7.4S, v13.4S, #24 \n"

            "ADD v2.4S, v2.4S, v3.4S \n"
            "ADD v6.4S, v6.4S, v7.4S \n"
            "EOR v12.16B, v1.16B, v2.16B \n"
            "EOR v13.16B, v5.16B, v6.16B \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v1.4S, v12.4S, #7 \n"
            "SHL v5.4S, v13.4S, #7 \n"
            "SRI v1.4S, v12.4S, #25 \n"
            "SRI v5.4S, v13.4S, #25 \n"

            // EVEN ROUND

            // v0   0  1  2  3
            // v1   5  6  7  4
            // v2  10 11  8  9
            // v3  15 12 13 14
            // CHACHA block vector elements shifted as shown above

            "EXT v1.16B, v1.16B, v1.16B, #4 \n" // permute elements left by one
            "EXT v2.16B, v2.16B, v2.16B, #8 \n" // permute elements left by two
            "EXT v3.16B, v3.16B, v3.16B, #12 \n" // permute elements left by three

            "EXT v5.16B, v5.16B, v5.16B, #4 \n" // permute elements left by one
            "EXT v6.16B, v6.16B, v6.16B, #8 \n" // permute elements left by two
            "EXT v7.16B, v7.16B, v7.16B, #12 \n" // permute elements left by three


            "ADD v0.4S, v0.4S, v1.4S \n"
            "ADD v4.4S, v4.4S, v5.4S \n"
            "EOR v12.16B, v3.16B, v0.16B \n"
            "EOR v13.16B, v7.16B, v4.16B \n"
            // rotation by 16 bits may be done by reversing the 16 bit elements in 32 bit words
            "REV32 v3.8H, v12.8H \n"
            "REV32 v7.8H, v13.8H \n"

            "ADD v2.4S, v2.4S, v3.4S \n"
            "ADD v6.4S, v6.4S, v7.4S \n"
            "EOR v12.16B, v1.16B, v2.16B \n"
            "EOR v13.16B, v5.16B, v6.16B \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v1.4S, v12.4S, #12 \n"
            "SHL v5.4S, v13.4S, #12 \n"
            "SRI v1.4S, v12.4S, #20 \n"
            "SRI v5.4S, v13.4S, #20 \n"

            "ADD v0.4S, v0.4S, v1.4S \n"
            "ADD v4.4S, v4.4S, v5.4S \n"
            "EOR v12.16B, v3.16B, v0.16B \n"
            "EOR v13.16B, v7.16B, v4.16B \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v3.4S, v12.4S, #8 \n"
            "SHL v7.4S, v13.4S, #8 \n"
            "SRI v3.4S, v12.4S, #24 \n"
            "SRI v7.4S, v13.4S, #24 \n"

            "ADD v2.4S, v2.4S, v3.4S \n"
            "ADD v6.4S, v6.4S, v7.4S \n"
            "EOR v12.16B, v1.16B, v2.16B \n"
            "EOR v13.16B, v5.16B, v6.16B \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v1.4S, v12.4S, #7 \n"
            "SHL v5.4S, v13.4S, #7 \n"
            "SRI v1.4S, v12.4S, #25 \n"
            "SRI v5.4S, v13.4S, #25 \n"

            "EXT v1.16B, v1.16B, v1.16B, #12 \n" // permute elements left by three
            "EXT v2.16B, v2.16B, v2.16B, #8 \n" // permute elements left by two
            "EXT v3.16B, v3.16B, v3.16B, #4 \n" // permute elements left by one

            "EXT v5.16B, v5.16B, v5.16B, #12 \n" // permute elements left by three
            "EXT v6.16B, v6.16B, v6.16B, #8 \n" // permute elements left by two
            "EXT v7.16B, v7.16B, v7.16B, #4 \n" // permute elements left by one

            "EXT v11.16B, v11.16B, v11.16B, #4 \n" // permute elements left by one

            "CBNZ %[rounds], loop_128_%= \n"

            "ADD v0.4S, v0.4S, v24.4S \n"
            "ADD v1.4S, v1.4S, v25.4S \n"
            "ADD v2.4S, v2.4S, v26.4S \n"
            "ADD v3.4S, v3.4S, v27.4S \n"
            "EOR v0.16B, v0.16B, v28.16B \n"
            "EOR v1.16B, v1.16B, v29.16B \n"
            "EOR v2.16B, v2.16B, v30.16B \n"
            "EOR v3.16B, v3.16B, v31.16B \n"
            "LD1 { v28.4S-v31.4S }, [%[m]] \n"
            "MOV v27.S[0], w17 \n"
            "ST1 { v0.4S-v3.4S }, [%[c]] \n"
            "ADD %[c], %[c], %[chacha_chunk_bytes] \n"

            "ADD v4.4S, v4.4S, v24.4S \n"
            "ADD v5.4S, v5.4S, v25.4S \n"
            "ADD v6.4S, v6.4S, v26.4S \n"
            "ADD v7.4S, v7.4S, v27.4S \n"
            "EOR v4.16B, v4.16B, v28.16B \n"
            "EOR v5.16B, v5.16B, v29.16B \n"
            "EOR v6.16B, v6.16B, v30.16B \n"
            "EOR v7.16B, v7.16B, v31.16B \n"
            "ST1 { v4.4S-v7.4S }, [%[c]] \n"


            : [c] "=r" (c), [m] "=r" (m)
            : "0" (c), "1" (m), [rounds] "r" (ROUNDS/2), [input] "r" (input), [chacha_chunk_bytes] "I" (CHACHA_CHUNK_BYTES)
            : "memory", "cc",
              "x17",
              "v0",  "v1",  "v2",  "v3",  "v4",
              "v5",  "v6",  "v7",
              "v12", "v13",
              "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
    );

    return CHACHA_CHUNK_BYTES * 2;
#endif /* __aarch64__ */
}

static WC_INLINE void wc_Chacha_wordtobyte_64(word32 output[CHACHA_CHUNK_WORDS],
    const word32 input[CHACHA_CHUNK_WORDS])
{
#ifdef __aarch64__
    __asm__ __volatile__ (
            "LDP x1, x3, [%[input]], #16 \n"
            "LDP x5, x7, [%[input]], #16 \n"
            "LDP x9, x11, [%[input]], #16 \n"
            "LDP x13, x15, [%[input]], #16 \n"

            "MOV x17, x1 \n"
            "LSR x2, x1, #32 \n"
            "MOV x18, x3 \n"
            "LSR x4, x3, #32 \n"
            "MOV x19, x5 \n"
            "LSR x6, x5, #32 \n"
            "MOV x20, x7 \n"
            "LSR x8, x7, #32 \n"
            "MOV x21, x9 \n"
            "LSR x10, x9, #32 \n"
            "MOV x22, x11 \n"
            "LSR x12, x11, #32 \n"
            "MOV x23, x13 \n"
            "LSR x14, x13, #32 \n"
            "MOV x24, x15 \n"
            "LSR x16, x15, #32 \n"

            "loop_64_%=:"
            "SUB %[rounds], %[rounds], #1 \n"

            // odd

            "ADD w1, w1, w5 \n"
            "ADD w2, w2, w6 \n"
            "ADD w3, w3, w7 \n"
            "ADD w4, w4, w8 \n"

            "EOR w13, w13, w1 \n"
            "EOR w14, w14, w2 \n"
            "EOR w15, w15, w3 \n"
            "EOR w16, w16, w4 \n"

            "ROR w13, w13, #16 \n"
            "ROR w14, w14, #16 \n"
            "ROR w15, w15, #16 \n"
            "ROR w16, w16, #16 \n"

            "ADD w9, w9, w13 \n"
            "ADD w10, w10, w14 \n"
            "ADD w11, w11, w15 \n"
            "ADD w12, w12, w16 \n"

            "EOR w5, w5, w9 \n"
            "EOR w6, w6, w10 \n"
            "EOR w7, w7, w11 \n"
            "EOR w8, w8, w12 \n"

            "ROR w5, w5, #20 \n"
            "ROR w6, w6, #20 \n"
            "ROR w7, w7, #20 \n"
            "ROR w8, w8, #20 \n"

            "ADD w1, w1, w5 \n"
            "ADD w2, w2, w6 \n"
            "ADD w3, w3, w7 \n"
            "ADD w4, w4, w8 \n"

            "EOR w13, w13, w1 \n"
            "EOR w14, w14, w2 \n"
            "EOR w15, w15, w3 \n"
            "EOR w16, w16, w4 \n"

            "ROR w13, w13, #24 \n"
            "ROR w14, w14, #24 \n"
            "ROR w15, w15, #24 \n"
            "ROR w16, w16, #24 \n"

            "ADD w9, w9, w13 \n"
            "ADD w10, w10, w14 \n"
            "ADD w11, w11, w15 \n"
            "ADD w12, w12, w16 \n"

            "EOR w5, w5, w9 \n"
            "EOR w6, w6, w10 \n"
            "EOR w7, w7, w11 \n"
            "EOR w8, w8, w12 \n"

            "ROR w5, w5, #25 \n"
            "ROR w6, w6, #25 \n"
            "ROR w7, w7, #25 \n"
            "ROR w8, w8, #25 \n"

            // even

            "ADD w1, w1, w6 \n"
            "ADD w2, w2, w7 \n"
            "ADD w3, w3, w8 \n"
            "ADD w4, w4, w5 \n"

            "EOR w16, w16, w1 \n"
            "EOR w13, w13, w2 \n"
            "EOR w14, w14, w3 \n"
            "EOR w15, w15, w4 \n"

            "ROR w16, w16, #16 \n"
            "ROR w13, w13, #16 \n"
            "ROR w14, w14, #16 \n"
            "ROR w15, w15, #16 \n"

            "ADD w11, w11, w16 \n"
            "ADD w12, w12, w13 \n"
            "ADD w9, w9, w14 \n"
            "ADD w10, w10, w15 \n"

            "EOR w6, w6, w11 \n"
            "EOR w7, w7, w12 \n"
            "EOR w8, w8, w9 \n"
            "EOR w5, w5, w10 \n"

            "ROR w6, w6, #20 \n"
            "ROR w7, w7, #20 \n"
            "ROR w8, w8, #20 \n"
            "ROR w5, w5, #20 \n"

            "ADD w1, w1, w6 \n"
            "ADD w2, w2, w7 \n"
            "ADD w3, w3, w8 \n"
            "ADD w4, w4, w5 \n"

            "EOR w16, w16, w1 \n"
            "EOR w13, w13, w2 \n"
            "EOR w14, w14, w3 \n"
            "EOR w15, w15, w4 \n"

            "ROR w16, w16, #24 \n"
            "ROR w13, w13, #24 \n"
            "ROR w14, w14, #24 \n"
            "ROR w15, w15, #24 \n"

            "ADD w11, w11, w16 \n"
            "ADD w12, w12, w13 \n"
            "ADD w9, w9, w14 \n"
            "ADD w10, w10, w15 \n"

            "EOR w6, w6, w11 \n"
            "EOR w7, w7, w12 \n"
            "EOR w8, w8, w9 \n"
            "EOR w5, w5, w10 \n"

            "ROR w6, w6, #25 \n"
            "ROR w7, w7, #25 \n"
            "ROR w8, w8, #25 \n"
            "ROR w5, w5, #25 \n"

            "CBNZ %[rounds], loop_64_%= \n"

            "ADD w1, w1, w17 \n"
            "ADD x2, x2, x17, LSR #32 \n"
            "ADD w3, w3, w18 \n"
            "ADD x4, x4, x18, LSR #32 \n"
            "ADD w5, w5, w19 \n"
            "ADD x6, x6, x19, LSR #32 \n"
            "ADD w7, w7, w20 \n"
            "ADD x8, x8, x20, LSR #32 \n"

            "ADD w9, w9, w21 \n"
            "ADD x10, x10, x21, LSR #32 \n"
            "ADD w11, w11, w22 \n"
            "ADD x12, x12, x22, LSR #32 \n"
            "ADD w13, w13, w23 \n"
            "ADD x14, x14, x23, LSR #32 \n"
            "ADD w15, w15, w24 \n"
            "ADD x16, x16, x24, LSR #32 \n"

            "ORR x1, x1, x2, LSL #32 \n"
            "ORR x3, x3, x4, LSL #32 \n"
            "ORR x5, x5, x6, LSL #32 \n"
            "STP x1, x3, [%[x]], #16 \n"
            "ORR x7, x7, x8, LSL #32 \n"
            "ORR x9, x9, x10, LSL #32 \n"
            "STP x5, x7, [%[x]], #16 \n"
            "ORR x11, x11, x12, LSL #32 \n"
            "ORR x13, x13, x14, LSL #32 \n"
            "STP x9, x11, [%[x]], #16 \n"
            "ORR x15, x15, x16, LSL #32 \n"
            "STP x13, x15, [%[x]], #16 \n"

            : [x] "=r" (output), [input] "=r" (input)
            : "0" (output), "1" (input), [rounds] "r" (ROUNDS/2)
            : "memory",
              "x1",  "x2",  "x3",  "x4",
              "x5",  "x6",  "x7",  "x8",
              "x9",  "x10", "x11", "x12",
              "x13", "x14", "x15", "x16",
              "x17", "x18", "x19", "x20",
              "x21", "x22", "x23", "x24"
    );
#else
    word32 i;
    word32 temp0, temp1, temp2, temp3;

    for (i = 0; i < CHACHA_CHUNK_WORDS; i++) {
        output[i] = input[i];
    }

    for (i = (ROUNDS); i > 0; i -= 2) {

        __asm__ __volatile__ (
                // QUARTERROUND(0, 4,  8, 12)

                "LDM %[output], { r0-r7 } \n"
                // r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12
                //  0  1  2  3  4  5  6  7

                "ADD r0, r0, r4 \n" // 0 0 4
                "ADD r1, r1, r5 \n" // 1 1 5
                "ADD r2, r2, r6 \n" // 2 2 6
                "ADD r3, r3, r7 \n" // 3 3 7

                // 0-7

                "ADD %[output], %[output], #48 \n"
                "LDM %[output], { r8-r11 } \n"
                "SUB %[output], %[output], #48 \n"
                // r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12
                //  0  1  2  3  4  5  6  7 12 13  14  15

                "EOR r8, r8, r0 \n" // 12 12 0
                "EOR r9, r9, r1 \n" // 13 13 1
                "EOR r10, r10, r2 \n" // 14 14 2
                "EOR r11, r11, r3 \n" // 15 15 3

                // 0-3 12-15

                "ROR r8, r8, #16 \n" // 12 12
                "ROR r9, r9, #16 \n" // 13 13
                "ROR r10, r10, #16 \n" // 14 14
                "ROR r11, r11, #16 \n" // 15 15

                // 12-15

                "STM %[output], { r0-r3 } \n"
                "ADD %[output], %[output], #32 \n"
                "LDM %[output], { r0-r3 } \n"
                "SUB %[output], %[output], #32 \n"
                // r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12
                //  8  9 10 11  4  5  6  7 12 13  14  15

                "ADD r0, r0, r8 \n" // 8 8 12
                "ADD r1, r1, r9 \n" //  9 9 13
                "ADD r2, r2, r10 \n" // 10 10 14
                "ADD r3, r3, r11 \n" // 11 11 15

                // 8-15

                "EOR r4, r4, r0 \n" // 4 4 8
                "EOR r5, r5, r1 \n" // 5 5 9
                "EOR r6, r6, r2 \n" // 6 6 10
                "EOR r7, r7, r3 \n" // 7 7 11

                // 4-11

                "ROR r4, r4, #20 \n" // 4 4
                "ROR r5, r5, #20 \n" // 5 5
                "ROR r6, r6, #20 \n" // 6 6
                "ROR r7, r7, #20 \n" // 7 7

                // 4-7

                "ADD %[output], %[output], #32 \n"
                "STM %[output], { r0-r3 } \n"
                "SUB %[output], %[output], #32 \n"
                "LDM %[output], { r0-r3 } \n"
                // r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12
                //  0  1  2  3  4  5  6  7 12 13  14  15

                "ADD r0, r0, r4 \n" // 0 0 4
                "ADD r1, r1, r5 \n" // 1 1 5
                "ADD r2, r2, r6 \n" // 2 2 6
                "ADD r3, r3, r7 \n" // 3 3 7

                // 0-7

                "EOR r8, r8, r0 \n" // 12 12 0
                "EOR r9, r9, r1 \n" // 13 13 1
                "EOR r10, r10, r2 \n" // 14 14 2
                "EOR r11, r11, r3 \n" // 15 15 3

                // 0-3 12-15

                "ROR r8, r8, #24 \n" // 12 12
                "ROR r9, r9, #24 \n" // 13 13
                "ROR r10, r10, #24 \n" // 14 14
                "ROR r11, r11, #24 \n" // 15 15

                // 12-15

                "STM %[output], { r0-r3 } \n"
                "ADD %[output], %[output], #32 \n"
                "LDM %[output], { r0-r3 } \n"
                "SUB %[output], %[output], #32 \n"
                // r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12
                //  8  9 10 11  4  5  6  7 12 13  14  15

                "ADD r0, r0, r8 \n" // 8 8 12
                "ADD r1, r1, r9 \n" // 9 9 13
                "ADD r2, r2, r10 \n" // 10 10 14
                "ADD r3, r3, r11 \n" // 11 11 15

                // 8-15

                "EOR r4, r4, r0 \n" // 4 4 8
                "EOR r5, r5, r1 \n" // 5 5 9
                "EOR r6, r6, r2 \n" // 6 6 10
                "EOR r7, r7, r3 \n" // 7 7 11

                // 4-11

                "ROR r4, r4, #25 \n" // 4 4
                "ROR r5, r5, #25 \n" // 5 5
                "ROR r6, r6, #25 \n" // 6 6
                "ROR r7, r7, #25 \n" // 7 7

                "ADD %[output], %[output], #32 \n"
                "STM %[output], { r0-r3 } \n"
                "SUB %[output], %[output], #32 \n"
                "LDM %[output], { r0-r3 } \n"

                "ADD %[output], %[output], #48 \n"
                "STM %[output], { r8-r11 } \n"
                "SUB %[output], %[output], #16 \n"
                "LDM %[output], { r8-r11 } \n"
                "SUB %[output], %[output], #32 \n"
                "LDR r12, [%[output], #60] \n"
                // r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12
                //  0  1  2  3  4  5  6  7  8  9  10  11  12

                // ODD ROUND

                // QUARTERROUND(0, 5, 10, 15)

                "ADD r0, r0, r5 \n"
                "EOR r12, r12, r0 \n"
                "ROR r12, r12, #16 \n"

                "ADD r10, r10, r12 \n"
                "EOR r5, r5, r10 \n"
                "ROR r5, r5, #20 \n"

                "ADD r0, r0, r5 \n"
                "EOR r12, r12, r0 \n"
                "ROR r12, r12, #24 \n"

                "ADD r10, r10, r12 \n"
                "EOR r5, r5, r10 \n"
                "ROR r5, r5, #25 \n"

                "STR r12, [%[output], #60] \n"
                "LDR r12, [%[output], #48] \n"
                // r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12
                //  0  1  2  3  4  5  6  7  8  9  10  11  12

                // QUARTERROUND(1, 6, 11, 12)

                "ADD r1, r1, r6 \n"
                "EOR r12, r12, r1 \n"
                "ROR r12, r12, #16 \n"

                "ADD r11, r11, r12 \n"
                "EOR r6, r6, r11 \n"
                "ROR r6, r6, #20 \n"

                "ADD r1, r1, r6 \n"
                "EOR r12, r12, r1 \n"
                "ROR r12, r12, #24 \n"

                "ADD r11, r11, r12 \n"
                "EOR r6, r6, r11 \n"
                "ROR r6, r6, #25 \n"

                "STRD r11, r12, [%[output], #44] \n"
                "LDRD r11, r12, [%[output], #52] \n"
                // r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12
                //  0  1  2  3  4  5  6  7  8  9  10  13  14

                // QUARTERROUND(2, 7,  8, 13)

                "ADD r2, r2, r7 \n"
                "EOR r11, r11, r2 \n"
                "ROR r11, r11, #16 \n"

                "ADD r8, r8, r11 \n"
                "EOR r7, r7, r8 \n"
                "ROR r7, r7, #20 \n"

                "ADD r2, r2, r7 \n"
                "EOR r11, r11, r2 \n"
                "ROR r11, r11, #24 \n"

                "ADD r8, r8, r11 \n"
                "EOR r7, r7, r8 \n"
                "ROR r7, r7, #25 \n"


                // QUARTERROUND(3, 4,  9, 14)

                "ADD r3, r3, r4 \n"
                "EOR r12, r12, r3 \n"
                "ROR r12, r12, #16 \n"

                "ADD r9, r9, r12 \n"
                "EOR r4, r4, r9 \n"
                "ROR r4, r4, #20 \n"

                "ADD r3, r3, r4 \n"
                "EOR r12, r12, r3 \n"
                "ROR r12, r12, #24 \n"

                "ADD r9, r9, r12 \n"
                "EOR r4, r4, r9 \n"
                "ROR r4, r4, #25 \n"

                "STM %[output], { r0-r10 } \n"
                "STRD r11, r12, [%[output], #52] \n"

                :
                [output] "=r" (output)
//                [temp0] "+m" (temp0)
                :
                "0" (output)
                : "memory",
                "r0", "r1", "r2", "r3",
                "r4", "r5", "r6", "r7",
                "r8", "r9", "r10", "r11",
                "r12"
        );

//        QUARTERROUND(0, 4,  8, 12)
//        QUARTERROUND(1, 5,  9, 13)
//        QUARTERROUND(2, 6, 10, 14)
//        QUARTERROUND(3, 7, 11, 15)
//        QUARTERROUND(0, 5, 10, 15)
//        QUARTERROUND(1, 6, 11, 12)
//        QUARTERROUND(2, 7,  8, 13)
//        QUARTERROUND(3, 4,  9, 14)
    }

    for (i = 0; i < CHACHA_CHUNK_WORDS; i++) {
        output[i] = PLUS(output[i], input[i]);
    }

    for (i = 0; i < CHACHA_CHUNK_WORDS; i++) {
        output[i] = LITTLE32(output[i]);
    }
#endif /* __aarch64__ */
}

/**
  * Encrypt a stream of bytes
  */
static void wc_Chacha_encrypt_bytes(ChaCha* ctx, const byte* m, byte* c,
                                    word32 bytes)
{
    byte*  output;
    word32 temp[CHACHA_CHUNK_WORDS * MAX_CHACHA_BLOCKS]; /* used to make sure aligned */
    word32 i;
    int    processed;

#ifdef __aarch64__
    if (bytes >= CHACHA_CHUNK_BYTES * MAX_CHACHA_BLOCKS) {
        processed = wc_Chacha_wordtobyte_320(ctx->X, m, c, bytes);

        bytes -= processed;
        c += processed;
        m += processed;
        ctx->X[CHACHA_IV_BYTES] = PLUS(ctx->X[CHACHA_IV_BYTES], processed / CHACHA_CHUNK_BYTES);
    }
    if (bytes >= CHACHA_CHUNK_BYTES * 4) {
        processed = wc_Chacha_wordtobyte_256(ctx->X, m, c);

        bytes -= processed;
        c += processed;
        m += processed;
        ctx->X[CHACHA_IV_BYTES] = PLUS(ctx->X[CHACHA_IV_BYTES], processed / CHACHA_CHUNK_BYTES);
    } else if (bytes >= CHACHA_CHUNK_BYTES * 2) {
        processed = wc_Chacha_wordtobyte_128(ctx->X, m, c);

        bytes -= processed;
        c += processed;
        m += processed;
        ctx->X[CHACHA_IV_BYTES] = PLUS(ctx->X[CHACHA_IV_BYTES], processed / CHACHA_CHUNK_BYTES);
    }

    for (; bytes > 0;) {
        output = (byte*)temp;
        wc_Chacha_wordtobyte_64(temp, ctx->X);

        if (bytes >= CHACHA_CHUNK_BYTES) {
            // assume CHACHA_CHUNK_BYTES == 64
            __asm__ __volatile__ (
                    "LD1 { v0.16B-v3.16B }, [%[m]] \n"
                    "LD1 { v4.16B-v7.16B }, [%[output]] \n"
                    "EOR v0.16B, v0.16B, v4.16B \n"
                    "EOR v1.16B, v1.16B, v5.16B \n"
                    "EOR v2.16B, v2.16B, v6.16B \n"
                    "EOR v3.16B, v3.16B, v7.16B \n"
                    "ST1 { v0.16B-v3.16B }, [%[c]] \n"
                    : [c] "=r" (c)
                    : "0" (c), [m] "r" (m), [output] "r" (output)
                    : "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"
            );

            bytes -= CHACHA_CHUNK_BYTES;
            c += CHACHA_CHUNK_BYTES;
            m += CHACHA_CHUNK_BYTES;
            ctx->X[CHACHA_IV_BYTES] = PLUSONE(ctx->X[CHACHA_IV_BYTES]);
        } else {
            while (bytes >= ARM_SIMD_LEN_BYTES * 2) {
                __asm__ __volatile__ (
                        "LD1 { v0.16B-v1.16B }, [%[m]] \n"
                        "LD1 { v2.16B-v3.16B }, [%[output]] \n"
                        "EOR v0.16B, v0.16B, v2.16B \n"
                        "EOR v1.16B, v1.16B, v3.16B \n"
                        "ST1 { v0.16B-v1.16B }, [%[c]] \n"
                        : [c] "=r" (c)
                        : "0" (c), [m] "r" (m), [output] "r" (output)
                        : "memory", "v0", "v1"
                );

                bytes -= ARM_SIMD_LEN_BYTES * 2;
                c += ARM_SIMD_LEN_BYTES * 2;
                m += ARM_SIMD_LEN_BYTES * 2;
                output += ARM_SIMD_LEN_BYTES * 2;
            }
            if (bytes >= ARM_SIMD_LEN_BYTES) {
                __asm__ __volatile__ (
                        "LD1 { v0.16B }, [%[m]] \n"
                        "LD1 { v1.16B }, [%[output]] \n"
                        "EOR v0.16B, v0.16B, v1.16B \n"
                        "ST1 { v0.16B }, [%[c]] \n"
                        : [c] "=r" (c)
                        : "0" (c), [m] "r" (m), [output] "r" (output)
                        : "memory", "v0", "v1"
                );

                bytes -= ARM_SIMD_LEN_BYTES;
                c += ARM_SIMD_LEN_BYTES;
                m += ARM_SIMD_LEN_BYTES;
                output += ARM_SIMD_LEN_BYTES;
            }
            if (bytes >= ARM_SIMD_LEN_BYTES / 2) {
                __asm__ __volatile__ (
                        "LD1 { v0.8B }, [%[m]] \n"
                        "LD1 { v1.8B }, [%[output]] \n"
                        "EOR v0.8B, v0.8B, v1.8B \n"
                        "ST1 { v0.8B }, [%[c]] \n"
                        : [c] "=r" (c)
                        : "0" (c), [m] "r" (m), [output] "r" (output)
                        : "memory", "v0", "v1"
                );

                bytes -= ARM_SIMD_LEN_BYTES / 2;
                c += ARM_SIMD_LEN_BYTES / 2;
                m += ARM_SIMD_LEN_BYTES / 2;
                output += ARM_SIMD_LEN_BYTES / 2;
            }

            for (i = 0; i < bytes; ++i) {
                c[i] = m[i] ^ output[i];
            }

            ctx->X[CHACHA_IV_BYTES] = PLUSONE(ctx->X[CHACHA_IV_BYTES]);
            return;
        }
    }
#else
    output = (byte*)temp;
    for (; bytes > 0;) {
        wc_Chacha_wordtobyte_64(temp, ctx->X);
        ctx->X[CHACHA_IV_BYTES] = PLUSONE(ctx->X[CHACHA_IV_BYTES]);
        if (bytes <= CHACHA_CHUNK_BYTES) {
            for (i = 0; i < bytes; ++i) {
                c[i] = m[i] ^ output[i];
            }
            return;
        }
        for (i = 0; i < CHACHA_CHUNK_BYTES; ++i) {
            c[i] = m[i] ^ output[i];
        }
        bytes -= CHACHA_CHUNK_BYTES;
        c += CHACHA_CHUNK_BYTES;
        m += CHACHA_CHUNK_BYTES;
    }
#endif /*__aarch64__ */
}

/**
  * API to encrypt/decrypt a message of any size.
  */
int wc_Chacha_Process(ChaCha* ctx, byte* output, const byte* input,
                      word32 msglen)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    wc_Chacha_encrypt_bytes(ctx, input, output, msglen);

    return 0;
}

#endif /* HAVE_CHACHA*/

#endif /* WOLFSSL_ARMASM */
