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
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

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
static WC_INLINE int wc_Chacha_wordtobyte_big(const word32 input[CHACHA_CHUNK_WORDS], const byte* m, byte* c, word32 bytes)
{
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

            "LD1 { v24.4S-v27.4S }, [%[input]] \n"

            "outer_loop: \n"
            "SUB %[outer_rounds], %[outer_rounds], #1 \n"

            // v0  0  1  2  3
            // v1  4  5  6  7
            // v2  8  9 10 11
            // v3 12 13 14 15
            // load CHACHA state as shown above
            "MOV v0.16B, v24.16B \n"
            "MOV v1.16B, v25.16B \n"
            "MOV v2.16B, v26.16B \n"
            "MOV v3.16B, v27.16B \n"

            // get counter value
            "MOV w0, v27.S[0] \n"

            // load other registers with regular arm registers interleaved
            // final chacha block is stored in w1-w16 regular registers
            "MOV v4.16B, v24.16B \n"
            "MOV x1, v24.D[0] \n"
            "MOV v5.16B, v25.16B \n"
            "MOV x3, v24.D[1] \n"
            "MOV v6.16B, v26.16B \n"
            "LSR x2, x1, #32 \n"
            "MOV v7.16B, v27.16B \n"
            "LSR x4, x3, #32 \n"

            "MOV v8.16B, v24.16B \n"
            "MOV x5, v25.D[0] \n"
            "MOV v9.16B, v25.16B \n"
            "MOV x7, v25.D[1] \n"
            "MOV v10.16B, v26.16B \n"
            "LSR x6, x5, #32 \n"
            "MOV v11.16B, v27.16B \n"
            "LSR x8, x7, #32 \n"

            "ADD w17, w0, #2 \n"
            "ADD w0, w0, #1 \n"

            "MOV x9, v26.D[0] \n"
            "MOV x11, v26.D[1] \n"
            "MOV x13, v27.D[0] \n"
            "MOV x15, v27.D[1] \n"

            "LSR x10, x9, #32 \n"
            "LSR x12, x11, #32 \n"

            "LSR x14, x13, #32 \n"
            "LSR x16, x15, #32 \n"

            // set counter
            "ADD w13, w13, #3 \n"

            // load correct counter values
            "MOV v7.S[0], w0 \n"
            "MOV x0, %[rounds] \n" // Load loop counter
            "MOV v11.S[0], w17 \n"

            "loop: \n"
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

            "CBNZ x0, loop \n"

            // counter
            "MOV w0, v27.S[0] \n"
            "LD1 { v28.4S-v31.4S }, [%[m]] \n"
            "ADD %[m], %[m], %[chacha_chunk_bytes] \n"
            "ADD w0, w0, 1 \n"

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
            "ADD %[m], %[m], %[chacha_chunk_bytes] \n"

            // increment counter
            "MOV v27.S[0], w0 \n"
            "ADD w0, w0, 1 \n"
            // move block from regular arm registers to v0-v3
            "ORR x1, x1, x2, LSL #32 \n"
            "ORR x3, x3, x4, LSL #32 \n"
            "ORR x5, x5, x6, LSL #32 \n"
            "ORR x7, x7, x8, LSL #32 \n"
            "ORR x9, x9, x10, LSL #32 \n"
            "ORR x11, x11, x12, LSL #32 \n"
            "ORR x13, x13, x14, LSL #32 \n"
            "ORR x15, x15, x16, LSL #32 \n"
            "MOV v0.D[0], x1 \n"
            "MOV v0.D[1], x3 \n"
            "MOV v1.D[0], x5 \n"
            "MOV v1.D[1], x7 \n"
            "MOV v2.D[0], x9 \n"
            "MOV v2.D[1], x11 \n"
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
            "ADD %[c], %[c], %[chacha_chunk_bytes] \n"

            // increment counter
            "MOV v27.S[0], w0 \n"

            "CBNZ %[outer_rounds], outer_loop \n"

            : [c] "=r" (c), [m] "=r" (m)
            : "0" (c), "1" (m), [rounds] "I" (ROUNDS/2), [input] "r" (input), [chacha_chunk_bytes] "I" (CHACHA_CHUNK_BYTES),
              [outer_rounds] "r" (bytes / (CHACHA_CHUNK_BYTES * MAX_CHACHA_BLOCKS))
            : "memory",
              "x0",
              "x1",  "x2",  "x3",  "x4",
              "x5",  "x6",  "x7",  "x8",
              "x9",  "x10", "x11", "x12",
              "x13", "x14", "x15", "x16",
              "x17",
              "v0",  "v1",  "v2",  "v3",  "v4",
              "v5",  "v6",  "v7",  "v8",  "v9",
              "v10", "v11", "v12", "v13", "v14",
//              "v15", "v16", "v17", "v18", "v19",
//              "v20", "v21", "v22", "v23",
              "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
    );

    return (bytes / (CHACHA_CHUNK_BYTES * MAX_CHACHA_BLOCKS)) * CHACHA_CHUNK_BYTES * MAX_CHACHA_BLOCKS;
}

static WC_INLINE int wc_Chacha_wordtobyte_med(const word32 input[CHACHA_CHUNK_WORDS], const byte* m, byte* c) {
    __asm__ __volatile__ (
            // The paper NEON crypto by Daniel J. Bernstein and Peter Schwabe was used to optimize for ARM
            // https://cryptojedi.org/papers/neoncrypto-20120320.pdf

            // v0-v3 - first block
            // v12 first block helper

            "LD1 { v24.4S-v27.4S }, [%[input]] \n"
            "LD1 { v28.4S-v31.4S }, [%[m]] \n"
            "ADD %[m], %[m], %[chacha_chunk_bytes] \n"
            // get counter value
            "MOV w0, v27.S[0] \n"
            "ADD w0, w0, #1 \n"


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
            "MOV v7.S[0], w0 \n"

            "MOV x0, %[rounds] \n" // Load loop counter

            "med_loop: \n"
            "SUB x0, x0, #1 \n"

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

            "CBNZ x0, med_loop \n"

            "MOV w0, v27.S[0] \n"
            "ADD w0, w0, 1 \n"

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
            "MOV v27.S[0], w0 \n"

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
            : "0" (c), "1" (m), [rounds] "I" (ROUNDS/2), [input] "r" (input), [chacha_chunk_bytes] "I" (CHACHA_CHUNK_BYTES)
            : "memory",
              "x0",
              "v0",  "v1",  "v2",  "v3",  "v4",
              "v5",  "v6",  "v7",
              "v12", "v13",
              "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
    );

    return CHACHA_CHUNK_BYTES * 2;
}

static WC_INLINE void wc_Chacha_wordtobyte_small(word32 output[CHACHA_CHUNK_WORDS],
    const word32 input[CHACHA_CHUNK_WORDS])
{
    word32 x[CHACHA_CHUNK_WORDS];
    word32 i;

    for (i = 0; i < CHACHA_CHUNK_WORDS; i++) {
        x[i] = input[i];
    }

    for (i = (ROUNDS); i > 0; i -= 2) {
        QUARTERROUND(0, 4,  8, 12)
        QUARTERROUND(1, 5,  9, 13)
        QUARTERROUND(2, 6, 10, 14)
        QUARTERROUND(3, 7, 11, 15)
        QUARTERROUND(0, 5, 10, 15)
        QUARTERROUND(1, 6, 11, 12)
        QUARTERROUND(2, 7,  8, 13)
        QUARTERROUND(3, 4,  9, 14)
    }

    for (i = 0; i < CHACHA_CHUNK_WORDS; i++) {
        x[i] = PLUS(x[i], input[i]);
    }

    for (i = 0; i < CHACHA_CHUNK_WORDS; i++) {
        output[i] = LITTLE32(x[i]);
    }
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

#ifndef BIG_ENDIAN_ORDER
    if (bytes >= CHACHA_CHUNK_BYTES * MAX_CHACHA_BLOCKS) {
        processed = wc_Chacha_wordtobyte_big(ctx->X, m, c, bytes);

        bytes -= processed;
        c += processed;
        m += processed;
        ctx->X[CHACHA_IV_BYTES] = PLUS(ctx->X[CHACHA_IV_BYTES], processed / CHACHA_CHUNK_BYTES);
    }
    if (bytes >= CHACHA_CHUNK_BYTES * 2) {
        processed = wc_Chacha_wordtobyte_med(ctx->X, m, c);

        bytes -= processed;
        c += processed;
        m += processed;
        ctx->X[CHACHA_IV_BYTES] = PLUS(ctx->X[CHACHA_IV_BYTES], processed / CHACHA_CHUNK_BYTES);
    }
#endif /* BIG_ENDIAN_ORDER */

    for (; bytes > 0;) {
        output = (byte*)temp;
        wc_Chacha_wordtobyte_small(temp, ctx->X);
        processed = min(CHACHA_CHUNK_BYTES, bytes);

        for (i = 0; i < processed; ++i) {
            c[i] = m[i] ^ output[i];
        }

        bytes -= processed;
        c += processed;
        m += processed;
        ctx->X[CHACHA_IV_BYTES] = PLUSONE(ctx->X[CHACHA_IV_BYTES]);

    }
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
