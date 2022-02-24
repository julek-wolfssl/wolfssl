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

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>

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

#endif /* WOLFSSL_DTLS13 */
