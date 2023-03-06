/* ascon.h
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

#ifndef WOLF_CRYPT_ASCON_H
#define WOLF_CRYPT_ASCON_H

#ifdef HAVE_ASCON

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ASCON_HASH_SZ 32
/* Data block size in bytes */
#define ASCON_HASH_RATE 8
#define ASCON_HASH_ROUNDS_PA 12
#define ASCON_HASH_ROUNDS_PB 12
#define ASCON_HASH_IV 0x00400c0000000100ULL

typedef union AsconState {
  word64 s64[5];
} AsconState;

typedef struct wc_AsconHash {
    AsconState state;
    byte lastBlkSz;
} wc_AsconHash;

WOLFSSL_API int wc_AsconHash_Init(wc_AsconHash* a);
WOLFSSL_API int wc_AsconHash_Update(wc_AsconHash* a, const byte* data, word32 dataSz);
WOLFSSL_API int wc_AsconHash_Final(wc_AsconHash* a, byte* hash);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* HAVE_ASCON */

#endif /* WOLF_CRYPT_ASCON_H */
