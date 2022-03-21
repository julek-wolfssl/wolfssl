/* dtls13.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_DTLS13

#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/wolfcrypt/aes.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

WOLFSSL_METHOD* wolfDTLSv1_3_client_method_ex(void* heap)
{
    WOLFSSL_METHOD* method;

    WOLFSSL_ENTER("DTLSv1_3_client_method_ex");

    method = (WOLFSSL_METHOD *)XMALLOC(
        sizeof(WOLFSSL_METHOD), heap, DYNAMIC_TYPE_METHOD);
    if (method)
        InitSSL_Method(method, MakeDTLSv1_3());

    return method;
}

WOLFSSL_METHOD* wolfDTLSv1_3_server_method_ex(void* heap)
{
    WOLFSSL_METHOD* method;

    WOLFSSL_ENTER("DTLSv1_3_server_method_ex");

    method = (WOLFSSL_METHOD *)XMALLOC(
        sizeof(WOLFSSL_METHOD), heap, DYNAMIC_TYPE_METHOD);
    if (method) {
        InitSSL_Method(method, MakeDTLSv1_3());
        method->side = WOLFSSL_SERVER_END;
    }

    return method;
}

/**
 * Dtls13DoLegacyVersion() - check client legacy version field
 * @ssl: ssl object
 * @pv: ProtocolVersion to check against
 * @wantDowngrade: client ask for a version smaller than DTLS1.2
 *
 * DTLSv1.3 (as TLSv1.3) uses an extension to negotiate the version. This legacy
 * version field can be used only to negotiate DTLSv1.2 or DTLSv1.0.  This
 * function set wantDowngrade if client sent minor < DTLSv1.2. It also set
 * ssl->version accordingly.
 */
void Dtls13DoLegacyVersion(
    WOLFSSL *ssl, ProtocolVersion *pv, int *wantDowngrade) {

  /* DTLS version number goes backwards (-1,-2,-3 so the check are reversed:
     version_a > version_b means that version_a is smaller than version_b.*/

  if (pv->major == DTLS_MAJOR && pv->minor > DTLSv1_2_MINOR) {
      *wantDowngrade = 1;
      ssl->version.minor = pv->minor;
  }

}

#define SN_LABEL_SZ 2
static const byte snLabel[SN_LABEL_SZ + 1] = "sn";

/**
 * Dtls13DeriveSnKeys() - derive the key used to encrypt the record number
 * @ssl: ssl object
 * @provision: which side (CLIENT or SERVER) to provision
 */
int Dtls13DeriveSnKeys(WOLFSSL *ssl, int provision)
{
    byte key_dig[MAX_PRF_DIG];
    int ret = 0;

    if (provision & PROVISION_CLIENT) {
        WOLFSSL_MSG("Derive SN Client key");
        ret = Tls13DeriveKey(ssl, key_dig, ssl->specs.key_size,
            ssl->clientSecret, snLabel, SN_LABEL_SZ, ssl->specs.mac_algorithm,
            0);
        if (ret != 0)
            goto end;

        XMEMCPY(ssl->keys.client_sn_key, key_dig, ssl->specs.key_size);
    }

    if (provision & PROVISION_SERVER) {
        WOLFSSL_MSG("Derive SN Server key");
        ret = Tls13DeriveKey(ssl, key_dig, ssl->specs.key_size,
            ssl->serverSecret, snLabel, SN_LABEL_SZ, ssl->specs.mac_algorithm,
            0);
        if (ret != 0)
            goto end;

        XMEMCPY(ssl->keys.server_sn_key, key_dig, ssl->specs.key_size);
    }

end:
    ForceZero(key_dig, MAX_PRF_DIG);
    return ret;
}

static int Dtls13InitAesCipher(WOLFSSL *ssl, Ciphers *cipher)
{
    if (cipher->aes == NULL) {
        cipher->aes =
            (Aes *)XMALLOC(sizeof(Aes), ssl->heap, DYNAMIC_TYPE_CIPHER);
        if (cipher->aes == NULL)
            return MEMORY_E;
    }
    else {
        wc_AesFree(cipher->aes);
    }

    XMEMSET(cipher->aes, 0, sizeof(*cipher->aes));

    return wc_AesInit(cipher->aes, ssl->heap, INVALID_DEVID);
}

int Dtls13SetRecordNumberKeys(WOLFSSL *ssl, enum encrypt_side side)
{
    Ciphers *enc = NULL;
    Ciphers *dec = NULL;
    byte *key;
    int ret = NOT_COMPILED_IN;

    switch(side) {
    case ENCRYPT_SIDE_ONLY:
        enc = &ssl->dtlsRecordNumberEncrypt;
        break;
    case DECRYPT_SIDE_ONLY:
        dec = &ssl->dtlsRecordNumberDecrypt;
        break;
    case ENCRYPT_AND_DECRYPT_SIDE:
        enc = &ssl->dtlsRecordNumberEncrypt;
        dec = &ssl->dtlsRecordNumberDecrypt;
        break;
    }

    /* DTLSv1.3 supposts only AEAD algorithm.  */
#if defined(BUILD_AESGCM) || defined(HAVE_AESCCM)
    if (ssl->specs.bulk_cipher_algorithm == wolfssl_aes_gcm ||
        ssl->specs.bulk_cipher_algorithm == wolfssl_aes_ccm) {

        if (enc) {
            ret = Dtls13InitAesCipher(ssl, enc);
            if (ret != 0)
                return ret;

            if (ssl->options.side == WOLFSSL_CLIENT_END)
                key = ssl->keys.client_sn_key;
            else
                key = ssl->keys.server_sn_key;

#ifdef WOLFSSL_DEBUG_TLS
            WOLFSSL_MSG("Provisioning Record Number enc key:");
            WOLFSSL_BUFFER(key, ssl->specs.key_size);
#endif /* WOLFSSL_DEBUG_TLS */

            ret = wc_AesSetKey(
                enc->aes, key, ssl->specs.key_size, NULL, AES_ENCRYPTION);
            if (ret != 0)
                return ret;
        }

        if (dec) {
            ret = Dtls13InitAesCipher(ssl, dec);
            if (ret != 0)
                return ret;

            if (ssl->options.side == WOLFSSL_CLIENT_END)
                key = ssl->keys.server_sn_key;
            else
                key = ssl->keys.client_sn_key;

#ifdef WOLFSSL_DEBUG_TLS
            WOLFSSL_MSG("Provisioning Record Number dec key:");
            WOLFSSL_BUFFER(key, ssl->specs.key_size);
#endif /* WOLFSSL_DEBUG_TLS */

            ret = wc_AesSetKey(
                dec->aes, key, ssl->specs.key_size, NULL, AES_ENCRYPTION);
            if (ret != 0)
                return ret;
        }
    }
#endif

    /* TODO: support chacha based ciphersuite */

    return ret;
}

#endif /* WOLFSSL_DTLS13 */
