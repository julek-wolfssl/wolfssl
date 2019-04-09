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
static WC_INLINE void wc_Chacha_wordtobyte(word32 output[CHACHA_CHUNK_WORDS * MAX_CHACHA_BLOCKS],
    const word32 input[CHACHA_CHUNK_WORDS])
{
    word32 x[CHACHA_CHUNK_WORDS * MAX_CHACHA_BLOCKS]; // process multiple blocks at a time
    word32 i;

    XMEMCPY(x, input, CHACHA_CHUNK_BYTES);
    XMEMCPY(x + CHACHA_CHUNK_WORDS, input, CHACHA_CHUNK_BYTES);
    XMEMCPY(x + CHACHA_CHUNK_WORDS*2, input, CHACHA_CHUNK_BYTES);
    XMEMCPY(x + CHACHA_CHUNK_WORDS*3, input, CHACHA_CHUNK_BYTES);
    XMEMCPY(x + CHACHA_CHUNK_WORDS*4, input, CHACHA_CHUNK_BYTES);
    XMEMCPY(x + CHACHA_CHUNK_WORDS*5, input, CHACHA_CHUNK_BYTES);
    XMEMCPY(x + CHACHA_CHUNK_WORDS*6, input, CHACHA_CHUNK_BYTES);
    x[CHACHA_CHUNK_WORDS + CHACHA_IV_BYTES] += 1;
    x[CHACHA_CHUNK_WORDS*2 + CHACHA_IV_BYTES] += 2;
    x[CHACHA_CHUNK_WORDS*3 + CHACHA_IV_BYTES] += 3;
    x[CHACHA_CHUNK_WORDS*4 + CHACHA_IV_BYTES] += 4;
    x[CHACHA_CHUNK_WORDS*5 + CHACHA_IV_BYTES] += 5;
    x[CHACHA_CHUNK_WORDS*6 + CHACHA_IV_BYTES] += 6;

    __asm__ __volatile__ (
            // The paper NEON crypto by Daniel J. Bernstein and Peter Schwabe was used to optimize for ARM
            // https://cryptojedi.org/papers/neoncrypto-20120320.pdf

            // Load counter
            "MOV x0, %[rounds] \n"

            // v0-v3 - first block
            // v24 first block helper
            // v4-v7 - second block
            // v25 second block helper
            // v8-v11 - third block
            // v26 third block helper
            // v12-v15 - fourth block
            // v27 fourth block helper
            // v16-v19 - fifth block
            // v28 fifth block helper
            // v20-v23 - sixth block
            // v29 sixth block helper
            // w1-w16 - seventh block

            // v0  0  1  2  3
            // v1  4  5  6  7
            // v2  8  9 10 11
            // v3 12 13 14 15
            // load CHACHA state as shown above
            "LD1 { v0.4S-v3.4S }, [%[x_in]] \n"
            "ADD %[x_in], %[x_in], %[chacha_chunk_bytes] \n"
            "LD1 { v4.4S-v7.4S }, [%[x_in]] \n"
            "ADD %[x_in], %[x_in], %[chacha_chunk_bytes] \n"
            "LD1 { v8.4S-v11.4S }, [%[x_in]] \n"
            "ADD %[x_in], %[x_in], %[chacha_chunk_bytes] \n"
            "LD1 { v12.4S-v15.4S }, [%[x_in]] \n"
            "ADD %[x_in], %[x_in], %[chacha_chunk_bytes] \n"
            "LD1 { v16.4S-v19.4S }, [%[x_in]] \n"
            "ADD %[x_in], %[x_in], %[chacha_chunk_bytes] \n"
            "LD1 { v20.4S-v23.4S }, [%[x_in]] \n"

            // load final block to regular ARM registers
            "LDP x1, x3, [%[x_in]], #16 \n"
            "LSR x2, x1, #32 \n"
            "LSR x4, x3, #32 \n"

            "LDP x5, x7, [%[x_in]], #16 \n"
            "LSR x6, x5, #32 \n"
            "LSR x8, x7, #32 \n"

            "LDP x9, x11, [%[x_in]], #16 \n"
            "LSR x10, x9, #32 \n"
            "LSR x12, x11, #32 \n"

            "LDP x13, x15, [%[x_in]], #16 \n"
            "LSR x14, x13, #32 \n"
            "LSR x16, x15, #32 \n"

            "loop: \n"

            // ODD ROUND

            "ADD w1, w1, w5 \n"
            "ADD v0.4S, v0.4S, v1.4S \n"
            "ADD v4.4S, v4.4S, v5.4S \n"
            "EOR w13, w13, w1 \n"
            "ADD v8.4S, v8.4S, v9.4S \n"
            "ADD v12.4S, v12.4S, v13.4S \n"
            "ROR w13, w13, #16 \n"
            "ADD v16.4S, v16.4S, v17.4S \n"
            "ADD v20.4S, v20.4S, v21.4S \n"
            "ADD w9, w9, w13 \n"
            "EOR v24.16B, v3.16B, v0.16B \n"
            "EOR v25.16B, v7.16B, v4.16B \n"
            "EOR w5, w5, w9 \n"
            "EOR v26.16B, v11.16B, v8.16B \n"
            "EOR v27.16B, v15.16B, v12.16B \n"
            "ROR w5, w5, #20 \n"
            "EOR v28.16B, v19.16B, v16.16B \n"
            "EOR v29.16B, v23.16B, v20.16B \n"
            "ADD w1, w1, w5 \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v3.4S, v24.4S, #16 \n"
            "SHL v7.4S, v25.4S, #16 \n"
            "EOR w13, w13, w1 \n"
            "SHL v11.4S, v26.4S, #16 \n"
            "SHL v15.4S, v27.4S, #16 \n"
            "ROR w13, w13, #24 \n"
            "SHL v19.4S, v28.4S, #16 \n"
            "SHL v23.4S, v29.4S, #16 \n"
            "ADD w9, w9, w13 \n"
            "SRI v3.4S, v24.4S, #16 \n"
            "SRI v7.4S, v25.4S, #16 \n"
            "EOR w5, w5, w9 \n"
            "SRI v11.4S, v26.4S, #16 \n"
            "SRI v15.4S, v27.4S, #16 \n"
            "ROR w5, w5, #25 \n"
            "SRI v19.4S, v28.4S, #16 \n"
            "SRI v23.4S, v29.4S, #16 \n"

            "ADD w2, w2, w6 \n"
            "ADD v2.4S, v2.4S, v3.4S \n"
            "ADD v6.4S, v6.4S, v7.4S \n"
            "EOR w14, w14, w2 \n"
            "ADD v10.4S, v10.4S, v11.4S \n"
            "ADD v14.4S, v14.4S, v15.4S \n"
            "ROR w14, w14, #16 \n"
            "ADD v18.4S, v18.4S, v19.4S \n"
            "ADD v22.4S, v22.4S, v23.4S \n"
            "ADD w10, w10, w14 \n"
            "EOR v24.16B, v1.16B, v2.16B \n"
            "EOR v25.16B, v5.16B, v6.16B \n"
            "EOR w6, w6, w10 \n"
            "EOR v26.16B, v9.16B, v10.16B \n"
            "EOR v27.16B, v13.16B, v14.16B \n"
            "ROR w6, w6, #20 \n"
            "EOR v28.16B, v17.16B, v18.16B \n"
            "EOR v29.16B, v21.16B, v22.16B \n"
            "ADD w2, w2, w6 \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v1.4S, v24.4S, #12 \n"
            "SHL v5.4S, v25.4S, #12 \n"
            "EOR w14, w14, w2 \n"
            "SHL v9.4S, v26.4S, #12 \n"
            "SHL v13.4S, v27.4S, #12 \n"
            "ROR w14, w14, #24 \n"
            "SHL v17.4S, v28.4S, #12 \n"
            "SHL v21.4S, v29.4S, #12 \n"
            "ADD w10, w10, w14 \n"
            "SRI v1.4S, v24.4S, #20 \n"
            "SRI v5.4S, v25.4S, #20 \n"
            "EOR w6, w6, w10 \n"
            "SRI v9.4S, v26.4S, #20 \n"
            "SRI v13.4S, v27.4S, #20 \n"
            "ROR w6, w6, #25 \n"
            "SRI v17.4S, v28.4S, #20 \n"
            "SRI v21.4S, v29.4S, #20 \n"

            "ADD w3, w3, w7 \n"
            "ADD v0.4S, v0.4S, v1.4S \n"
            "ADD v4.4S, v4.4S, v5.4S \n"
            "EOR w15, w15, w3 \n"
            "ADD v8.4S, v8.4S, v9.4S \n"
            "ADD v12.4S, v12.4S, v13.4S \n"
            "ROR w15, w15, #16 \n"
            "ADD v16.4S, v16.4S, v17.4S \n"
            "ADD v20.4S, v20.4S, v21.4S \n"
            "ADD w11, w11, w15 \n"
            "EOR v24.16B, v3.16B, v0.16B \n"
            "EOR v25.16B, v7.16B, v4.16B \n"
            "EOR w7, w7, w11 \n"
            "EOR v26.16B, v11.16B, v8.16B \n"
            "EOR v27.16B, v15.16B, v12.16B \n"
            "ROR w7, w7, #20 \n"
            "EOR v28.16B, v19.16B, v16.16B \n"
            "EOR v29.16B, v23.16B, v20.16B \n"
            "ADD w3, w3, w7 \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v3.4S, v24.4S, #8 \n"
            "SHL v7.4S, v25.4S, #8 \n"
            "EOR w15, w15, w3 \n"
            "SHL v11.4S, v26.4S, #8 \n"
            "SHL v15.4S, v27.4S, #8 \n"
            "ROR w15, w15, #24 \n"
            "SHL v19.4S, v28.4S, #8 \n"
            "SHL v23.4S, v29.4S, #8 \n"
            "ADD w11, w11, w15 \n"
            "SRI v3.4S, v24.4S, #24 \n"
            "SRI v7.4S, v25.4S, #24 \n"
            "EOR w7, w7, w11 \n"
            "SRI v11.4S, v26.4S, #24 \n"
            "SRI v15.4S, v27.4S, #24 \n"
            "ROR w7, w7, #25 \n"
            "SRI v19.4S, v28.4S, #24 \n"
            "SRI v23.4S, v29.4S, #24 \n"

            "ADD w4, w4, w8 \n"
            "ADD v2.4S, v2.4S, v3.4S \n"
            "ADD v6.4S, v6.4S, v7.4S \n"
            "EOR w16, w16, w4 \n"
            "ADD v10.4S, v10.4S, v11.4S \n"
            "ADD v14.4S, v14.4S, v15.4S \n"
            "ROR w16, w16, #16 \n"
            "ADD v18.4S, v18.4S, v19.4S \n"
            "ADD v22.4S, v22.4S, v23.4S \n"
            "ADD w12, w12, w16 \n"
            "EOR v24.16B, v1.16B, v2.16B \n"
            "EOR v25.16B, v5.16B, v6.16B \n"
            "EOR w8, w8, w12 \n"
            "EOR v26.16B, v9.16B, v10.16B \n"
            "EOR v27.16B, v13.16B, v14.16B \n"
            "ROR w8, w8, #20 \n"
            "EOR v28.16B, v17.16B, v18.16B \n"
            "EOR v29.16B, v21.16B, v22.16B \n"
            "ADD w4, w4, w8 \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v1.4S, v24.4S, #7 \n"
            "SHL v5.4S, v25.4S, #7 \n"
            "EOR w16, w16, w4 \n"
            "SHL v9.4S, v26.4S, #7 \n"
            "SHL v13.4S, v27.4S, #7 \n"
            "ROR w16, w16, #24 \n"
            "SHL v17.4S, v28.4S, #7 \n"
            "SHL v21.4S, v29.4S, #7 \n"
            "ADD w12, w12, w16 \n"
            "SRI v1.4S, v24.4S, #25 \n"
            "SRI v5.4S, v25.4S, #25 \n"
            "EOR w8, w8, w12 \n"
            "SRI v9.4S, v26.4S, #25 \n"
            "SRI v13.4S, v27.4S, #25 \n"
            "ROR w8, w8, #25 \n"
            "SRI v17.4S, v28.4S, #25 \n"
            "SRI v21.4S, v29.4S, #25 \n"

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

            "EXT v9.16B, v9.16B, v9.16B, #4 \n" // permute elements left by one
            "EXT v10.16B, v10.16B, v10.16B, #8 \n" // permute elements left by two
            "EXT v11.16B, v11.16B, v11.16B, #12 \n" // permute elements left by three

            "EXT v13.16B, v13.16B, v13.16B, #4 \n" // permute elements left by one
            "EXT v14.16B, v14.16B, v14.16B, #8 \n" // permute elements left by two
            "EXT v15.16B, v15.16B, v15.16B, #12 \n" // permute elements left by three

            "EXT v17.16B, v17.16B, v17.16B, #4 \n" // permute elements left by one
            "EXT v18.16B, v18.16B, v18.16B, #8 \n" // permute elements left by two
            "EXT v19.16B, v19.16B, v19.16B, #12 \n" // permute elements left by three

            "EXT v21.16B, v21.16B, v21.16B, #4 \n" // permute elements left by one
            "EXT v22.16B, v22.16B, v22.16B, #8 \n" // permute elements left by two
            "EXT v23.16B, v23.16B, v23.16B, #12 \n" // permute elements left by three

            "ADD w1, w1, w6 \n"
            "ADD v0.4S, v0.4S, v1.4S \n"
            "ADD v4.4S, v4.4S, v5.4S \n"
            "EOR w16, w16, w1 \n"
            "ADD v8.4S, v8.4S, v9.4S \n"
            "ADD v12.4S, v12.4S, v13.4S \n"
            "ROR w16, w16, #16 \n"
            "ADD v16.4S, v16.4S, v17.4S \n"
            "ADD v20.4S, v20.4S, v21.4S \n"
            "ADD w11, w11, w16 \n"
            "EOR v24.16B, v3.16B, v0.16B \n"
            "EOR v25.16B, v7.16B, v4.16B \n"
            "EOR w6, w6, w11 \n"
            "EOR v26.16B, v11.16B, v8.16B \n"
            "EOR v27.16B, v15.16B, v12.16B \n"
            "ROR w6, w6, #20 \n"
            "EOR v28.16B, v19.16B, v16.16B \n"
            "EOR v29.16B, v23.16B, v20.16B \n"
            "ADD w1, w1, w6 \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v3.4S, v24.4S, #16 \n"
            "SHL v7.4S, v25.4S, #16 \n"
            "EOR w16, w16, w1 \n"
            "SHL v11.4S, v26.4S, #16 \n"
            "SHL v15.4S, v27.4S, #16 \n"
            "ROR w16, w16, #24 \n"
            "SHL v19.4S, v28.4S, #16 \n"
            "SHL v23.4S, v29.4S, #16 \n"
            "ADD w11, w11, w16 \n"
            "SRI v3.4S, v24.4S, #16 \n"
            "SRI v7.4S, v25.4S, #16 \n"
            "EOR w6, w6, w11 \n"
            "SRI v11.4S, v26.4S, #16 \n"
            "SRI v15.4S, v27.4S, #16 \n"
            "ROR w6, w6, #25 \n"
            "SRI v19.4S, v28.4S, #16 \n"
            "SRI v23.4S, v29.4S, #16 \n"

            "ADD w2, w2, w7 \n"
            "ADD v2.4S, v2.4S, v3.4S \n"
            "ADD v6.4S, v6.4S, v7.4S \n"
            "EOR w13, w13, w2 \n"
            "ADD v10.4S, v10.4S, v11.4S \n"
            "ADD v14.4S, v14.4S, v15.4S \n"
            "ROR w13, w13, #16 \n"
            "ADD v18.4S, v18.4S, v19.4S \n"
            "ADD v22.4S, v22.4S, v23.4S \n"
            "ADD w12, w12, w13 \n"
            "EOR v24.16B, v1.16B, v2.16B \n"
            "EOR v25.16B, v5.16B, v6.16B \n"
            "EOR w7, w7, w12 \n"
            "EOR v26.16B, v9.16B, v10.16B \n"
            "EOR v27.16B, v13.16B, v14.16B \n"
            "ROR w7, w7, #20 \n"
            "EOR v28.16B, v17.16B, v18.16B \n"
            "EOR v29.16B, v21.16B, v22.16B \n"
            "ADD w2, w2, w7 \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v1.4S, v24.4S, #12 \n"
            "SHL v5.4S, v25.4S, #12 \n"
            "EOR w13, w13, w2 \n"
            "SHL v9.4S, v26.4S, #12 \n"
            "SHL v13.4S, v27.4S, #12 \n"
            "ROR w13, w13, #24 \n"
            "SHL v17.4S, v28.4S, #12 \n"
            "SHL v21.4S, v29.4S, #12 \n"
            "ADD w12, w12, w13 \n"
            "SRI v1.4S, v24.4S, #20 \n"
            "SRI v5.4S, v25.4S, #20 \n"
            "EOR w7, w7, w12 \n"
            "SRI v9.4S, v26.4S, #20 \n"
            "SRI v13.4S, v27.4S, #20 \n"
            "ROR w7, w7, #25 \n"
            "SRI v17.4S, v28.4S, #20 \n"
            "SRI v21.4S, v29.4S, #20 \n"

            "ADD w3, w3, w8 \n"
            "ADD v0.4S, v0.4S, v1.4S \n"
            "ADD v4.4S, v4.4S, v5.4S \n"
            "EOR w14, w14, w3 \n"
            "ADD v8.4S, v8.4S, v9.4S \n"
            "ADD v12.4S, v12.4S, v13.4S \n"
            "ROR w14, w14, #16 \n"
            "ADD v16.4S, v16.4S, v17.4S \n"
            "ADD v20.4S, v20.4S, v21.4S \n"
            "ADD w9, w9, w14 \n"
            "EOR v24.16B, v3.16B, v0.16B \n"
            "EOR v25.16B, v7.16B, v4.16B \n"
            "EOR w8, w8, w9 \n"
            "EOR v26.16B, v11.16B, v8.16B \n"
            "EOR v27.16B, v15.16B, v12.16B \n"
            "ROR w8, w8, #20 \n"
            "EOR v28.16B, v19.16B, v16.16B \n"
            "EOR v29.16B, v23.16B, v20.16B \n"
            "ADD w3, w3, w8 \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v3.4S, v24.4S, #8 \n"
            "SHL v7.4S, v25.4S, #8 \n"
            "EOR w14, w14, w3 \n"
            "SHL v11.4S, v26.4S, #8 \n"
            "SHL v15.4S, v27.4S, #8 \n"
            "ROR w14, w14, #24 \n"
            "SHL v19.4S, v28.4S, #8 \n"
            "SHL v23.4S, v29.4S, #8 \n"
            "ADD w9, w9, w14 \n"
            "SRI v3.4S, v24.4S, #24 \n"
            "SRI v7.4S, v25.4S, #24 \n"
            "EOR w8, w8, w9 \n"
            "SRI v11.4S, v26.4S, #24 \n"
            "SRI v15.4S, v27.4S, #24 \n"
            "ROR w8, w8, #25 \n"
            "SRI v19.4S, v28.4S, #24 \n"
            "SRI v23.4S, v29.4S, #24 \n"

            "ADD w4, w4, w5 \n"
            "ADD v2.4S, v2.4S, v3.4S \n"
            "ADD v6.4S, v6.4S, v7.4S \n"
            "EOR w15, w15, w4 \n"
            "ADD v10.4S, v10.4S, v11.4S \n"
            "ADD v14.4S, v14.4S, v15.4S \n"
            "ROR w15, w15, #16 \n"
            "ADD v18.4S, v18.4S, v19.4S \n"
            "ADD v22.4S, v22.4S, v23.4S \n"
            "ADD w10, w10, w15 \n"
            "EOR v24.16B, v1.16B, v2.16B \n"
            "EOR v25.16B, v5.16B, v6.16B \n"
            "EOR w5, w5, w10 \n"
            "EOR v26.16B, v9.16B, v10.16B \n"
            "EOR v27.16B, v13.16B, v14.16B \n"
            "ROR w5, w5, #20 \n"
            "EOR v28.16B, v17.16B, v18.16B \n"
            "EOR v29.16B, v21.16B, v22.16B \n"
            "ADD w4, w4, w5 \n"
            // SIMD instructions don't support rotation so we have to cheat using shifts and a help register
            "SHL v1.4S, v24.4S, #7 \n"
            "SHL v5.4S, v25.4S, #7 \n"
            "EOR w15, w15, w4 \n"
            "SHL v9.4S, v26.4S, #7 \n"
            "SHL v13.4S, v27.4S, #7 \n"
            "ROR w15, w15, #24 \n"
            "SHL v17.4S, v28.4S, #7 \n"
            "SHL v21.4S, v29.4S, #7 \n"
            "ADD w10, w10, w15 \n"
            "SRI v1.4S, v24.4S, #25 \n"
            "SRI v5.4S, v25.4S, #25 \n"
            "EOR w5, w5, w10 \n"
            "SRI v9.4S, v26.4S, #25 \n"
            "SRI v13.4S, v27.4S, #25 \n"
            "ROR w5, w5, #25 \n"
            "SRI v17.4S, v28.4S, #25 \n"
            "SRI v21.4S, v29.4S, #25 \n"

            "EXT v1.16B, v1.16B, v1.16B, #12 \n" // permute elements left by three
            "EXT v2.16B, v2.16B, v2.16B, #8 \n" // permute elements left by two
            "EXT v3.16B, v3.16B, v3.16B, #4 \n" // permute elements left by one

            "EXT v5.16B, v5.16B, v5.16B, #12 \n" // permute elements left by three
            "EXT v6.16B, v6.16B, v6.16B, #8 \n" // permute elements left by two
            "EXT v7.16B, v7.16B, v7.16B, #4 \n" // permute elements left by one

            "EXT v9.16B, v9.16B, v9.16B, #12 \n" // permute elements left by three
            "EXT v10.16B, v10.16B, v10.16B, #8 \n" // permute elements left by two
            "EXT v11.16B, v11.16B, v11.16B, #4 \n" // permute elements left by one

            "EXT v13.16B, v13.16B, v13.16B, #12 \n" // permute elements left by three
            "EXT v14.16B, v14.16B, v14.16B, #8 \n" // permute elements left by two
            "EXT v15.16B, v15.16B, v15.16B, #4 \n" // permute elements left by one

            "EXT v17.16B, v17.16B, v17.16B, #12 \n" // permute elements left by three
            "EXT v18.16B, v18.16B, v18.16B, #8 \n" // permute elements left by two
            "EXT v19.16B, v19.16B, v19.16B, #4 \n" // permute elements left by one

            "EXT v21.16B, v21.16B, v21.16B, #12 \n" // permute elements left by three
            "EXT v22.16B, v22.16B, v22.16B, #8 \n" // permute elements left by two
            "EXT v23.16B, v23.16B, v23.16B, #4 \n" // permute elements left by one

            "SUB x0, x0, #1 \n"
            "CBNZ x0, loop \n"

            "LD1 { v24.4S-v27.4S }, [%[in]] \n"

            "ADD v0.4S, v0.4S, v24.4S \n"
            "ADD v1.4S, v1.4S, v25.4S \n"
            "ADD v2.4S, v2.4S, v26.4S \n"
            "ADD v3.4S, v3.4S, v27.4S \n"
            "ST1 { v0.4S-v3.4S }, [%[x_out]] \n"

            "ADD %[x_out], %[x_out], %[chacha_chunk_bytes] \n"
            // increment counter
            "MOV w0, v27.S[0] \n"
            "ADD w0, w0, 1 \n"
            "MOV v27.S[0], w0 \n"
            "ADD v4.4S, v4.4S, v24.4S \n"
            "ADD v5.4S, v5.4S, v25.4S \n"
            "ADD v6.4S, v6.4S, v26.4S \n"
            "ADD v7.4S, v7.4S, v27.4S \n"
            "ST1 { v4.4S-v7.4S }, [%[x_out]] \n"

            "ADD %[x_out], %[x_out], %[chacha_chunk_bytes] \n"
            // increment counter
            "MOV w0, v27.S[0] \n"
            "ADD w0, w0, 1 \n"
            "MOV v27.S[0], w0 \n"
            "ADD v8.4S, v8.4S, v24.4S \n"
            "ADD v9.4S, v9.4S, v25.4S \n"
            "ADD v10.4S, v10.4S, v26.4S \n"
            "ADD v11.4S, v11.4S, v27.4S \n"
            "ST1 { v8.4S-v11.4S }, [%[x_out]] \n"

            "ADD %[x_out], %[x_out], %[chacha_chunk_bytes] \n"
            // increment counter
            "MOV w0, v27.S[0] \n"
            "ADD w0, w0, 1 \n"
            "MOV v27.S[0], w0 \n"
            "ADD v12.4S, v12.4S, v24.4S \n"
            "ADD v13.4S, v13.4S, v25.4S \n"
            "ADD v14.4S, v14.4S, v26.4S \n"
            "ADD v15.4S, v15.4S, v27.4S \n"
            "ST1 { v12.4S-v15.4S }, [%[x_out]] \n"

            "ADD %[x_out], %[x_out], %[chacha_chunk_bytes] \n"
            // increment counter
            "MOV w0, v27.S[0] \n"
            "ADD w0, w0, 1 \n"
            "MOV v27.S[0], w0 \n"
            "ADD v16.4S, v16.4S, v24.4S \n"
            "ADD v17.4S, v17.4S, v25.4S \n"
            "ADD v18.4S, v18.4S, v26.4S \n"
            "ADD v19.4S, v19.4S, v27.4S \n"
            "ST1 { v16.4S-v19.4S }, [%[x_out]] \n"

            "ADD %[x_out], %[x_out], %[chacha_chunk_bytes] \n"
            // increment counter
            "MOV w0, v27.S[0] \n"
            "ADD w0, w0, 1 \n"
            "MOV v27.S[0], w0 \n"
            "ADD v20.4S, v20.4S, v24.4S \n"
            "ADD v21.4S, v21.4S, v25.4S \n"
            "ADD v22.4S, v22.4S, v26.4S \n"
            "ADD v23.4S, v23.4S, v27.4S \n"
            "ST1 { v20.4S-v23.4S }, [%[x_out]] \n"

            // store final block from regular ARM registers
            "ORR x1, x1, x2, LSL #32 \n"
            "ORR x3, x3, x4, LSL #32 \n"
            "STP x1, x3, [%[x_out]], #16 \n"

            "ORR x5, x5, x6, LSL #32 \n"
            "ORR x7, x7, x8, LSL #32 \n"
            "STP x5, x7, [%[x_out]], #16 \n"

            "ORR x9, x9, x10, LSL #32 \n"
            "ORR x11, x11, x12, LSL #32 \n"
            "STP x9, x11, [%[x_out]], #16 \n"

            "ORR x13, x13, x14, LSL #32 \n"
            "ORR x15, x15, x16, LSL #32 \n"
            "STP x13, x15, [%[x_out]], #16 \n"

            :
            : [x_out] "r" (x), [x_in] "r" (x), [rounds] "I" (ROUNDS/2), [in] "r" (input), [chacha_chunk_bytes] "I" (CHACHA_CHUNK_BYTES)
            : "memory",
              "x0",
              "x1",  "x2",  "x3",  "x4",
              "x5",  "x6",  "x7",  "x8",
              "x9",  "x10", "x11", "x12",
              "x13", "x14", "x15", "x16",
              "v0",  "v1",  "v2",  "v3",  "v4",
              "v5",  "v6",  "v7",  "v8",  "v9",
              "v10", "v11", "v12", "v13", "v14",
              "v15", "v16", "v17", "v18", "v19",
              "v20", "v21", "v22", "v23", "v24",
              "v25", "v26", "v27", "v28", "v29"
    );

    for (i = 0; i < CHACHA_CHUNK_WORDS * MAX_CHACHA_BLOCKS; i++) {
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
    word32 blk;

    for (; bytes > 0;) {
        output = (byte*)temp;
        wc_Chacha_wordtobyte(temp, ctx->X);

        for (blk = 0; blk < MAX_CHACHA_BLOCKS && bytes > CHACHA_CHUNK_BYTES; ++blk) {
            // assume CHACHA_CHUNK_BYTES == 64
            __asm__ __volatile__ (
                    "LD1 { v0.16B-v3.16B }, [%[m]] \n"
                    "LD1 { v4.16B-v7.16B }, [%[output]] \n"
                    "EOR v0.16B, v0.16B, v4.16B \n"
                    "EOR v1.16B, v1.16B, v5.16B \n"
                    "EOR v2.16B, v2.16B, v6.16B \n"
                    "EOR v3.16B, v3.16B, v7.16B \n"
                    "ST1 { v0.16B-v3.16B }, [%[c]] \n"
                    :
                    : [c] "r" (c), [m] "r" (m), [output] "r" (output)
                    : "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"
            );

            bytes -= CHACHA_CHUNK_BYTES;
            c += CHACHA_CHUNK_BYTES;
            m += CHACHA_CHUNK_BYTES;
            output += CHACHA_CHUNK_BYTES;

            ctx->X[CHACHA_IV_BYTES] = PLUSONE(ctx->X[CHACHA_IV_BYTES]);
        }

        if (bytes <= CHACHA_CHUNK_BYTES && blk < MAX_CHACHA_BLOCKS) {

            while (bytes >= ARM_SIMD_LEN_BYTES) {
                __asm__ __volatile__ (
                        "LD1 { v0.16B }, [%[m]] \n"
                        "LD1 { v1.16B }, [%[output]] \n"
                        "EOR v0.16B, v0.16B, v1.16B \n"
                        "ST1 { v0.16B }, [%[c]] \n"
                        :
                        : [c] "r" (c), [m] "r" (m), [output] "r" (output)
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
                        :
                        : [c] "r" (c), [m] "r" (m), [output] "r" (output)
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
