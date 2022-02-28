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
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

enum rnDirection {
    PROTECT = 0,
    DEPROTECT,
};

typedef struct Dtls13HandshakeHeader {
    byte msg_type;
    byte length[3];
    byte messageSeq[2];
    byte fragmentOffset[3];
    byte fragmentLength[3];
} Dtls13HandshakeHeader;

typedef struct Dtls13RecordPlaintextHeader {
    byte contentType;
    ProtocolVersion legacyVersionRecord;
    byte epoch[2];
    byte sequenceNumber[6];
    byte length[2];
} Dtls13RecordPlaintextHeader;

/* No CID, 16bit Seq number, Length present */
typedef struct Dtls13RecordCiphertextHeader {
    /* 0 0 1 C S L E E */
    byte unifiedHdrFlags;
    byte sequenceNumber[2];
    byte length[2];
} Dtls13RecordCiphertextHeader;

#define DTLS13_LEN_SIZE 2
#define DTLS13_RN_MASK_SIZE 16
#define DTLS13_HDR_FLAGS_SIZE 1
#define DTLS13_SEQ_16_LEN 2
#define DTLS13_SEQ_8_LEN 1
#define DTLS13_SEQ_FULL_SIZE 4

#define DTLS13_FIXED_BITS_MASK (0x111 << 5)
#define DTLS13_FIXED_BITS (0x1 << 5)
#define DTLS13_C_BIT (0x1 << 4)
#define DTLS13_S_BIT (0x1 << 3)
#define DTLS13_L_BIT (0x1 << 2)


/* For now, the size of the outgoing DTLSv1.3 record header is fixed to 5 bytes
   (8 bit header flags + 16bit record number + 16 bit length). In the future, we
   can dinamically choose to remove the length from the header to save
   space. Also it has to account for client connection ID when supported. */
#define DTLS13_UNIFIED_HEADER_SIZE 5 /*  */
#define DTLS13_MIN_CIPHERTEXT 16

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
static int Dtls13RlAddPlaintextHeader(
    WOLFSSL *ssl, byte *out, enum ContentType content_type, size_t length)
{
    Dtls13RecordPlaintextHeader *hdr;

    hdr = (Dtls13RecordPlaintextHeader *)out;
    hdr->contentType = content_type;
    hdr->legacyVersionRecord.major = DTLS_MAJOR;
    hdr->legacyVersionRecord.minor = DTLSv1_2_MINOR;

    /* writeSeq updates both epoch and seq */
    WriteSEQ(ssl, CUR_ORDER, hdr->epoch);
    c16toa(length, hdr->length);

    return 0;
}

static int Dtls13HandshakeAddHeaderFrag(WOLFSSL *ssl, byte *output,
    enum HandShakeType msg_type, word32 frag_offset, word32 frag_length,
    word32 msg_length)
{
    Dtls13HandshakeHeader *hdr;

    hdr = (Dtls13HandshakeHeader *)output;

    hdr->msg_type = msg_type;
    c32to24((word32)msg_length, hdr->length);
    c16toa(ssl->keys.dtls_handshake_number, hdr->messageSeq);

    c32to24(frag_offset, hdr->fragmentOffset);
    c32to24(frag_length, hdr->fragmentLength);

    return 0;
}

static int Dtls13TypeIsEncrypted(enum HandShakeType hs_type)
{
    switch (hs_type) {
    case hello_request:
    case hello_verify_request:
    case client_hello:
    case server_hello:
        return 0;
    case encrypted_extensions:
    case session_ticket:
    case end_of_early_data   :
    case hello_retry_request :
    case certificate         :
    case server_key_exchange :
    case certificate_request :
    case server_hello_done   :
    case certificate_verify  :
    case client_key_exchange :
    case finished            :
    case certificate_status  :
    case key_update          :
    case change_cipher_hs    :
    case message_hash        :
    case no_shake            :
        return 1;
    }

    /* abide compilers */
    return 0;
}

static int Dtls13GetRnMask(
    WOLFSSL *ssl, const byte *ciphertext, byte *mask, enum rnDirection dir)
{
    Aes *aes;

    /* TODO: implements chacha based ciphers */

    if (ssl->specs.bulk_cipher_algorithm != wolfssl_aes_gcm)
        return WOLFSSL_NOT_IMPLEMENTED;

    if (dir == PROTECT)
        aes = ssl->dtlsRecordNumberEncrypt.aes;
    else
        aes = ssl->dtlsRecordNumberDecrypt.aes;

    if (aes == NULL)
        return BAD_STATE_E;

    return  wc_AesEncryptDirect(aes, mask, ciphertext);
}

static int Dtls13EncryptDecryptRecordNumber(WOLFSSL *ssl, byte *seq,
    int SeqLength, const byte *ciphertext, enum rnDirection dir)
{
    byte mask[DTLS13_RN_MASK_SIZE];
    int ret;

    ret = Dtls13GetRnMask(ssl, ciphertext, mask, dir);
    if (ret != 0)
        return ret;

    xorbuf(seq, mask, SeqLength);

    return 0;
}

static int Dtls13ProcessBufferedMessages(WOLFSSL *ssl)
{
    DtlsMsg *msg = ssl->dtls_rx_msg_list;
    word32 idx = 0;
    int ret = 0;

    WOLFSSL_ENTER("dtls13_process_buffered_messages()");

    while (msg != NULL) {
        idx = 0;

        /* message not in order */
        if (ssl->keys.dtls_expected_peer_handshake_number != msg->seq)
            break;

        /* message not complete */
        if (msg->fragSz != msg->sz)
            break;

        ret = DoTls13HandShakeMsgType(
            ssl, msg->msg, &idx, msg->type, msg->sz, msg->sz);
        if (ret != 0)
            break;

        ssl->keys.dtls_expected_peer_handshake_number++;

        ssl->dtls_rx_msg_list = msg->next;
        DtlsMsgDelete(msg, ssl->heap);
        msg = ssl->dtls_rx_msg_list;
        ssl->dtls_rx_msg_list_sz--;
    }

    WOLFSSL_LEAVE("dtls13_process_buffered_messages()", ret);

    return ret;
}

static int Dtls13NextMessageComplete(WOLFSSL *ssl) {
    return ssl->dtls_rx_msg_list != NULL &&
        ssl->dtls_rx_msg_list->fragSz == ssl->dtls_rx_msg_list->sz;
}

static inline int FragIsInOutputBuffer(WOLFSSL *ssl, const byte *frag)
{
    const byte *OutputBuffer = ssl->buffers.outputBuffer.buffer;
    word16 OutputBufferSize = ssl->buffers.outputBuffer.bufferSize;

    return frag >= OutputBuffer && frag < OutputBuffer + OutputBufferSize;
}

static int Dtls13SendFragFromBuffer(WOLFSSL *ssl, byte *output, word16 length)
{
    byte *buf;
    int ret;

    if (FragIsInOutputBuffer(ssl, output))
        return BAD_FUNC_ARG;

    ret = CheckAvailableSize(ssl, length);
    if (ret != 0)
        return ret;

    buf = ssl->buffers.outputBuffer.buffer + ssl->buffers.outputBuffer.length;

    XMEMCPY(buf, output, length);

    ssl->buffers.outputBuffer.length += length;

    return SendBuffered(ssl);
}

static int Dtls13SendFragment(WOLFSSL *ssl, byte *output, word16 output_size,
    word16 length, enum HandShakeType handshakeType, int hashOutput)
{
    word16 recordHeaderLength;
    word16 recordLength;
    byte isProtected;
    int sendLength;
    byte *msg;
    int ret;

    if (output_size < length)
        return BUFFER_ERROR;

    isProtected = Dtls13TypeIsEncrypted(handshakeType);
    recordHeaderLength = Dtls13GetRlHeaderLength(isProtected);

    if (length <= recordHeaderLength)
            return BUFFER_ERROR;

    recordLength = length - recordHeaderLength;

    if (!isProtected) {
        ret = Dtls13RlAddPlaintextHeader(ssl, output, handshake, recordLength);
        if (ret != 0)
            return ret;
    }
    else {
        msg = output + recordHeaderLength;

        if (length <= recordHeaderLength)
            return BUFFER_ERROR;

        sendLength = BuildTls13Message(ssl, output, output_size, msg,
            recordLength, handshake, hashOutput, 0, 0);
        if (sendLength < 0)
            return sendLength;

        length = sendLength;
    }

    if (!FragIsInOutputBuffer(ssl, output))
        return Dtls13SendFragFromBuffer(ssl, output, length);

    ssl->buffers.outputBuffer.length += length;
    return SendBuffered(ssl);
}

static void Dtls13FreeFragmentsBuffer(WOLFSSL *ssl)
{
    XFREE(ssl->dtls13FragmentsBuffer.buffer, ssl->heap,
        DYNAMIC_TYPE_TEMP_BUFFER);
    ssl->dtls13FragmentsBuffer.buffer = NULL;
    ssl->dtls13SendingFragments = 0;
    ssl->dtls13MessageLength = ssl->dtls13FragOffset = 0;
}

static int Dtls13SendFragmentedInternal(WOLFSSL *ssl)
{
    int fragLength, rlHeaderLength;
    int remainingSize, maxFragment;
    int recordLength;
    byte isEncrypted;
    byte *output;
    int ret;

    isEncrypted = Dtls13TypeIsEncrypted(ssl->dtls13FragHandshakeType);
    rlHeaderLength = Dtls13GetRlHeaderLength(isEncrypted);
    maxFragment = wolfSSL_GetMaxFragSize(ssl, MAX_RECORD_SIZE);

    remainingSize = ssl->dtls13MessageLength - ssl->dtls13FragOffset;

    while(remainingSize > 0) {

        fragLength = maxFragment - rlHeaderLength -
            DTLS_HANDSHAKE_HEADER_SZ;

        if (isEncrypted)
            fragLength -= cipherExtraData(ssl);

        if (fragLength > remainingSize)
            fragLength = remainingSize;

        ret = CheckAvailableSize(ssl, maxFragment);
        if (ret != 0)
            return ret;

        output = ssl->buffers.outputBuffer.buffer +
            ssl->buffers.outputBuffer.length;

        recordLength = fragLength +
                        DTLS_HANDSHAKE_HEADER_SZ + rlHeaderLength;

        ret = Dtls13HandshakeAddHeaderFrag(ssl, output + rlHeaderLength,
            ssl->dtls13FragHandshakeType, ssl->dtls13FragOffset,
            fragLength, ssl->dtls13MessageLength);
        if (ret != 0) {
            Dtls13FreeFragmentsBuffer(ssl);
            return ret;
        }

        XMEMCPY(output + rlHeaderLength + DTLS_HANDSHAKE_HEADER_SZ,
            ssl->dtls13FragmentsBuffer.buffer + ssl->dtls13FragOffset,
            fragLength);

        ret = Dtls13SendFragment(ssl, output, maxFragment, recordLength,
            ssl->dtls13FragHandshakeType, 0);
        if (ret == WANT_WRITE) {
            ssl->dtls13FragOffset += fragLength;
            return ret;
        }

        if (ret != 0) {
            Dtls13FreeFragmentsBuffer(ssl);
            return ret;
        }

        ssl->dtls13FragOffset += fragLength;
        remainingSize -= fragLength;
    }

    /* we sent all fragments */
    Dtls13FreeFragmentsBuffer(ssl);
    return 0;
}

static int Dtls13SendFragmented(WOLFSSL *ssl, byte *message, word16 length,
    enum HandShakeType handshake_type, int hash_output)
{
    int rlHeaderLength;
    byte isEncrypted;
    int messageSize;
    int ret;

    if (ssl->dtls13SendingFragments != 0)  {
        WOLFSSL_MSG(
            "dtls13_send_fragmented() invoked while already sending fragments");
        return BAD_STATE_E;
    }

    isEncrypted = Dtls13TypeIsEncrypted(handshake_type);
    rlHeaderLength = Dtls13GetRlHeaderLength(isEncrypted);

    if (length < rlHeaderLength)
        return INCOMPLETE_DATA;

    /* DTLSv1.3 do not consider fragmentation for hash transcript. Build the
       hash now pretending fragmentation will not happen */
    if (hash_output) {
        ret = HashRaw(ssl, message + rlHeaderLength, length - rlHeaderLength);
        if (ret != 0)
            return ret;
    }

    messageSize = length - rlHeaderLength - DTLS_HANDSHAKE_HEADER_SZ;

    ssl->dtls13FragmentsBuffer.buffer =
        (byte *)XMALLOC(messageSize, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);

    if (ssl->dtls13FragmentsBuffer.buffer == NULL)
        return MEMORY_E;

    XMEMCPY(ssl->dtls13FragmentsBuffer.buffer,
        message + rlHeaderLength + DTLS_HANDSHAKE_HEADER_SZ, messageSize);

    ssl->dtls13MessageLength = messageSize;
    ssl->dtls13FragHandshakeType = handshake_type;
    ssl->dtls13SendingFragments = 1;

    return Dtls13SendFragmentedInternal(ssl);
}

/**
 * dtls13RlAddCiphertextHeader() - add record layer header in the buffer
 * @ssl: ssl object
 * @out: output buffer where to put the ehader
 * @length: length of the record
 */
int Dtls13RlAddCiphertextHeader(WOLFSSL *ssl, byte *out, size_t length)
{
    Dtls13RecordCiphertextHeader *hdr;

    hdr = (Dtls13RecordCiphertextHeader *)out;

    hdr->unifiedHdrFlags = DTLS13_FIXED_BITS;
    hdr->unifiedHdrFlags |= (ssl->keys.dtls_epoch & EE_MASK);

    /* include 16-bit seq */
    hdr->unifiedHdrFlags |= DTLS13_S_BIT;
    /* include 16-bit length */
    hdr->unifiedHdrFlags |= DTLS13_L_BIT;

    hdr->sequenceNumber[0] = (ssl->keys.dtls_sequence_number_lo >> 16) & 0xff;
    hdr->sequenceNumber[1] = ssl->keys.dtls_sequence_number_lo & 0xff;

    c16toa(length, hdr->length);

    return 0;
}

/**
 * Dtls13HandshakeAddHeader() - add handshake layer header
 * @ssl: ssl object
 * @output: output buffer
 * @msg_type: handshake type
 * @length: length of the message
 */
int Dtls13HandshakeAddheader(
    WOLFSSL *ssl, byte *output, enum HandShakeType msg_type, size_t length)
{
    Dtls13HandshakeHeader *hdr;

    hdr = (Dtls13HandshakeHeader *)output;

    hdr->msg_type = msg_type;
    c32to24((word32)length, hdr->length);
    c16toa(ssl->keys.dtls_handshake_number, hdr->messageSeq);

    /* send unfragmented first */
    c32to24(0, hdr->fragmentOffset);
    c32to24((word32)length, hdr->fragmentLength);

    return 0;
}

/**
 * Dtls13EncryptRecordNumber() - encrypt record number in the header
 * @ssl: ssl object
 * @hdr: header
 *
 * Further info rfc draft 43 sec 4.2.3
 */
int Dtls13EncryptRecordNumber(WOLFSSL *ssl, byte *hdr, word16 recordLength)
{
    int seqLength;
    int hdrLength;

    if (ssl == NULL || hdr == NULL)
        return BAD_FUNC_ARG;

    /* we need at least a 16 bytes of ciphertext to encrypt record number see
       4.2.3*/
    if (recordLength < Dtls13GetRlHeaderLength(1) + DTLS13_MIN_CIPHERTEXT)
        return BUFFER_ERROR;

    seqLength = (*hdr & DTLS13_L_BIT) ? 2 : 1;

    /* header flags + seq number */
    hdrLength = 1 + seqLength;

    /* length present */
    if (*hdr & DTLS13_L_BIT)
        hdrLength += DTLS13_LEN_SIZE;

    return Dtls13EncryptDecryptRecordNumber(ssl,
        /* seq number offset */
        hdr + 1,
        /* seq size */
        seqLength,
        /* cipher thext */
        hdr + hdrLength, PROTECT);
}

/**
 * Dtls13GetRlHeaderLength() - get record layer header length
 * @ssl: ssl object
 * @isEncrypted: wheter the record will be protected or not
 *
 * returns the length of the record layer header in bytes.
 */
int Dtls13GetRlHeaderLength(int isEncrypted)
{
    /* the function looks useless but allow to support variable length unified
       header in the future */
    if (!isEncrypted)
      return DTLS_RECORD_HEADER_SZ;

    return DTLS13_UNIFIED_HEADER_SIZE;
}

/**
 * Dtls13GetHeadersLength() - return length of record + handshake header
 * @type: type of handshake in the message
 */
int Dtls13GetHeadersLength(enum HandShakeType type)
{
    int isEncrypted;

    isEncrypted = Dtls13TypeIsEncrypted(type);

    return Dtls13GetRlHeaderLength(isEncrypted) + DTLS_HANDSHAKE_HEADER_SZ;
}

/**
 * Dtls13IsUnifiedHeader() - check if header is a DTLS unified header
 * @header_flags: first byte of the header
 *
 * Further info: dtls v1.3 draft43 section 4
 */
int Dtls13IsUnifiedHeader(byte hdrFirstByte)
{
    if (hdrFirstByte == alert
        || hdrFirstByte == handshake
        || hdrFirstByte == ack)
        return 0;

    return ((hdrFirstByte & DTLS13_FIXED_BITS_MASK) == DTLS13_FIXED_BITS);
}
/**
 * Dtls13ParseUnifedRecordLayer() - parse DTLS unified header
 * @ssl: [in] ssl object
 * @input: [in] buffer where the header is
 * @inputSize: [in] size of the input buffer
 * @hdrInfo: [out] header info struct
 *
 * It parse the header and put the relevant information inside @hdrInfo. Further
 * info: draft43 section 4
 *
 * return 0 on success
 */
int Dtls13ParseUnifedRecordLayer(WOLFSSL *ssl, const byte *input,
    word16 inputSize, Dtls13UnifiedHdrInfo *hdrInfo)
{
    byte seqLen, hasLength;
    byte *seqNum;
    word16 idx;
    int ret;

    if (input == NULL || inputSize == 0)
        return BAD_FUNC_ARG;

    if (*input & DTLS13_C_BIT) {
        WOLFSSL_MSG("DTLS1.3 header with connection ID. Not supported");
        return WOLFSSL_NOT_IMPLEMENTED;
    }

    idx = DTLS13_HDR_FLAGS_SIZE;

    seqLen = (*input & DTLS13_S_BIT) != 0 ? DTLS13_SEQ_16_LEN
                                          : DTLS13_SEQ_8_LEN;
    hasLength = *input & DTLS13_L_BIT;
    hdrInfo->epochBits = *input & EE_MASK;

    idx += seqLen;

    if (inputSize < idx)
        return BUFFER_ERROR;

    if (hasLength) {
        if (inputSize < idx + DTLS13_LEN_SIZE)
            return BUFFER_ERROR;

        ato16(input + idx, &hdrInfo->recordLength);
        idx += DTLS13_LEN_SIZE;

        /* DTLS message must fit inside a datagram  */
        if (inputSize < idx + hdrInfo->recordLength)
            return LENGTH_ERROR;
    }
    else {
        /* length not present. The size of the record is the all the remaining
           data received with this datagram */
        hdrInfo->recordLength = inputSize - idx;
    }

    /* minimum size for a dtls1.3 packet is 16 bytes (to have enough ciphertext
       to create record number xor mask). (draft 43 - Sec 4.2.3) */
    if (hdrInfo->recordLength < DTLS13_RN_MASK_SIZE)
        return LENGTH_ERROR;

    seqNum = (byte*)(input + DTLS13_HDR_FLAGS_SIZE);

    ret = Dtls13EncryptDecryptRecordNumber(
        ssl, seqNum, seqLen, input + idx, DEPROTECT);
    if (ret != 0)
        return ret;

    hdrInfo->headerLength = idx;

    if (seqLen == DTLS13_SEQ_16_LEN) {
        hdrInfo->seqHiPresent = 1;
        hdrInfo->seqHi = seqNum[0];
        hdrInfo->seqLo = seqNum[1];
    }
    else {
        hdrInfo->seqHiPresent = 0;
        hdrInfo->seqLo = seqNum[0];
    }

    return 0;
}

/**
 * Dtls13HandshakeRecv() - process an handshake message. Deal with
 fragmentation if needed
 * @ssl: [in] ssl object
 * @input: [in] input buffer
 * @size: [in] input buffer size
 * @type: [out] content type
 * @processedSize: [out] amount of byte processed
 *
 * returns 0 on success
 */
int Dtls13HandshakeRecv(WOLFSSL *ssl, byte *input, word32 size,
                        word32 *processedSize)
{
    word32 frag_off, frag_length;
    word32 message_length;
    byte handshake_type;
    word32 idx;
    int ret;

    idx = 0;
    ret = GetDtlsHandShakeHeader(ssl, input, &idx, &handshake_type,
        &message_length, &frag_off, &frag_length, size);
    if (ret != 0)
        return PARSE_ERROR;

    if (idx + frag_length > size) {
        WOLFSSL_ERROR(INCOMPLETE_DATA);
        return INCOMPLETE_DATA;
    }

    if (frag_off + frag_length > message_length)
        return BUFFER_ERROR;

    if (frag_off != 0 || frag_length < message_length) {
        DtlsMsgStore(ssl, ssl->keys.curEpoch,
            ssl->keys.dtls_peer_handshake_number,
            input + DTLS_HANDSHAKE_HEADER_SZ, message_length, handshake_type,
            frag_off, frag_length, ssl->heap);

        *processedSize = idx + frag_length;

        *processedSize += ssl->keys.padSz;

        if (Dtls13NextMessageComplete(ssl))
            return Dtls13ProcessBufferedMessages(ssl);

        return 0;
    }

    if (ssl->keys.dtls_peer_handshake_number !=
        ssl->keys.dtls_expected_peer_handshake_number)
        return WOLFSSL_NOT_IMPLEMENTED;

    ssl->keys.dtls_expected_peer_handshake_number++;

    ret = DoTls13HandShakeMsgType(
        ssl, input, &idx, handshake_type, message_length, size);
    if (ret != 0)
        return ret;

    *processedSize = idx;

    return 0;
}

/**
 * Dtls13FragmentsContinue() - keep sending pending fragments
 * @ssl: ssl object
 */
int Dtls13FragmentsContinue(WOLFSSL *ssl)
{
    int ret;

    ret = Dtls13SendFragmentedInternal(ssl);
    if (ret != 0)
        return ret;

    if (ret == 0)
        ssl->keys.dtls_handshake_number++;

    return ret;
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

/**
 * Dtls13AddHeaders() - setup handhshake header
 * @output: output buffer at the start of the record
 * @length: length of the full message, included headers
 * @hsType: handshake type
 * @ssl: ssl object
 *
 * This function add the handshake headers and leaves space for the record
 * layer. The real record layer will be added in dtls_send() for unprotected
 * messages and in BuildTls13message() for protected messages.
 *
 * returns 0 on success, -1 otherwise
 */
int Dtls13AddHeaders(
    byte *output, word32 length, enum HandShakeType hsType, WOLFSSL *ssl)
{
    word16 handshakeOffset;
    int isEncrypted;

    isEncrypted = Dtls13TypeIsEncrypted(hsType);
    handshakeOffset = Dtls13GetRlHeaderLength(isEncrypted);

    /* The record header is placed by either Dtls13HandshakeSend() or
       BuildTls13Message() */

    return Dtls13HandshakeAddheader(
        ssl, output + handshakeOffset, hsType, length);
}

/**
 * Dtls13HandshakeSend() - send an handshake message. Fragment if necessary.
 *
 * @ssl: ssl object
 * @message: message where the buffer is in. Handshake header already in place.
 * @output_size: size of the @message buffer
 * @length: length of the message including headers
 * @handshakeType: handshake type of the message
 * @hashOutput: if true add the message to the transcript hash
 *
 */
int Dtls13HandshakeSend(WOLFSSL *ssl, byte *message, word16 outputSize,
    word16 length, enum HandShakeType handshakeType, int hashOutput)
{
    int maxFrag;
    int maxLen;
    int ret;

    maxFrag = wolfSSL_GetMaxFragSize(ssl, MAX_RECORD_SIZE);
    maxLen = length;

    if (maxLen < maxFrag) {
        ret = Dtls13SendFragment(
            ssl, message, outputSize, length, handshakeType, hashOutput);

        if (ret == 0 || ret == WANT_WRITE)
            ssl->keys.dtls_handshake_number++;
    }
    else {
        ret = Dtls13SendFragmented(
            ssl, message, length, handshakeType, hashOutput);
        if (ret == 0)
            ssl->keys.dtls_handshake_number++;
    }

    return ret;
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
