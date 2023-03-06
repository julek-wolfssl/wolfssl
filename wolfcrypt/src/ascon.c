/* ascon.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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
 */

#ifdef HAVE_ASCON
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/ascon.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/*
 * Implementation of the ASCON AEAD and HASH algorithms. Based on the NIST
 * submission https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf and the
 * reference implementation at https://github.com/ascon/ascon-c.
 */

/* TODO Implement for big endian */

#define MAX_ROUNDS 12

/* Table 4 */
static const byte round_constants[MAX_ROUNDS] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};

static byte start_index(byte rounds)
{
    switch (rounds) {
        case 6:
            return 6;
        case 8:
            return 4;
        case 12:
            return 0;
        default:
            WOLFSSL_MSG("Something went wrong in wolfCrypt logic. Wrong ASCON "
                        "rounds value.");
            return MAX_ROUNDS;
    }
}

static WC_INLINE void ascon_round(AsconState* a, byte round)
{
    AsconState tmp;
    /* 2.6.1 Addition of Constants */
    a->s64[2] ^= round_constants[round];
    /* 2.6.2 Substitution Layer */
    a->s64[0] ^= a->s64[4];
    a->s64[4] ^= a->s64[3];
    a->s64[2] ^= a->s64[1];
    tmp.s64[0] = a->s64[0] ^ (~a->s64[1] & a->s64[2]);
    tmp.s64[2] = a->s64[2] ^ (~a->s64[3] & a->s64[4]);
    tmp.s64[4] = a->s64[4] ^ (~a->s64[0] & a->s64[1]);
    tmp.s64[1] = a->s64[1] ^ (~a->s64[2] & a->s64[3]);
    tmp.s64[3] = a->s64[3] ^ (~a->s64[4] & a->s64[0]);
    tmp.s64[1] ^= tmp.s64[0];
    tmp.s64[3] ^= tmp.s64[2];
    tmp.s64[0] ^= tmp.s64[4];
    tmp.s64[2] = ~tmp.s64[2];
    /* 2.6.3 Linear Diffusion Layer */
    a->s64[4] = tmp.s64[4] ^ rotrFixed64(tmp.s64[4],  7) ^ rotrFixed64(tmp.s64[4], 41);
    a->s64[1] = tmp.s64[1] ^ rotrFixed64(tmp.s64[1], 61) ^ rotrFixed64(tmp.s64[1], 39);
    a->s64[3] = tmp.s64[3] ^ rotrFixed64(tmp.s64[3], 10) ^ rotrFixed64(tmp.s64[3], 17);
    a->s64[0] = tmp.s64[0] ^ rotrFixed64(tmp.s64[0], 19) ^ rotrFixed64(tmp.s64[0], 28);
    a->s64[2] = tmp.s64[2] ^ rotrFixed64(tmp.s64[2],  1) ^ rotrFixed64(tmp.s64[2],  6);
}

static void permutation(AsconState* a, byte rounds)
{
    byte i = start_index(rounds);
    for (; i < MAX_ROUNDS; i++) {
        ascon_round(a, i);
    }
}

int wc_AsconHash_Init(wc_AsconHash* a)
{
    if (a == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(a, 0, sizeof(*a));

    a->state.s64[0] = ASCON_HASH_IV;
    permutation(&a->state, ASCON_HASH_ROUNDS_PA);

    return 0;
}

int wc_AsconHash_Update(wc_AsconHash* a, const byte* data, word32 dataSz)
{
    word64 tmp;

    if (a == NULL || (data == NULL && dataSz != 0))
        return BAD_FUNC_ARG;

    if (dataSz == 0)
        return 0;

    /* Process leftover block */
    if (a->lastBlkSz != 0) {
        word32 toProcess = min(ASCON_HASH_RATE - a->lastBlkSz, dataSz);
        tmp = 0;
        XMEMCPY(&tmp, data, toProcess);
        a->state.s64[0] ^= ByteReverseWord64(tmp) >>
                                (a->lastBlkSz * WOLFSSL_BIT_SIZE);
        data += toProcess;
        dataSz -= toProcess;
        a->lastBlkSz += toProcess;
        if (a->lastBlkSz == ASCON_HASH_RATE) {
            permutation(&a->state, ASCON_HASH_ROUNDS_PB);
            /* Reset the counter */
            a->lastBlkSz = 0;
        }
        else {
            /* We need more data to process */
            return 0;
        }
    }

    while (dataSz > ASCON_HASH_RATE) {
        /* Read in input as big endian numbers */
        XMEMCPY(&tmp, data, ASCON_HASH_RATE);
        a->state.s64[0] ^= ByteReverseWord64(tmp);
        permutation(&a->state, ASCON_HASH_ROUNDS_PB);
        data += ASCON_HASH_RATE;
        dataSz -= ASCON_HASH_RATE;
    }

    tmp = 0;
    XMEMCPY(&tmp, data, dataSz);
    a->state.s64[0] ^= ByteReverseWord64(tmp);
    a->lastBlkSz = dataSz;

    return 0;
}

int wc_AsconHash_Final(wc_AsconHash* a, byte* hash)
{
    byte i;

    if (a == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    /* Process last block */
    a->state.s64[0] ^= ByteReverseWord64(0x80) >>
                            (a->lastBlkSz * WOLFSSL_BIT_SIZE);
    permutation(&a->state, ASCON_HASH_ROUNDS_PA);

    XMEMCPY(hash, &a->state, ASCON_HASH_RATE);
    *(word64*)hash = ByteReverseWord64(a->state.s64[0]);
    hash += ASCON_HASH_RATE;
    for (i = ASCON_HASH_RATE; i < ASCON_HASH_SZ; i += ASCON_HASH_RATE) {
        permutation(&a->state, ASCON_HASH_ROUNDS_PB);
        *(word64*)hash = ByteReverseWord64(a->state.s64[0]);
        hash += ASCON_HASH_RATE;
    }
    return 0;
}


#endif /* HAVE_ASCON */
