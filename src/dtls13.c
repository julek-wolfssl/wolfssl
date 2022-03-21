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
    Dtls13GetSeq(ssl, CUR_ORDER, (word32*)hdr->epoch, 1);
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

static int Dtls13RtxNeedsExplicitAck(WOLFSSL *ssl, enum HandShakeType hs)
{

    (void)hs;

#ifndef NO_WOLFSSL_SERVER
    if (ssl->options.side == WOLFSSL_SERVER_END && hs == finished)
        return 1;
#endif /* NO_WOLFSSL_SERVER */

    if (hs == session_ticket || hs == key_update)
        return 1;

    return 0;
}

static int Dtls13ProcessBufferedMessages(WOLFSSL *ssl)
{
    DtlsMsg *msg = ssl->dtls_rx_msg_list;
    Dtls13RtxFSM *fsm;
    word32 idx = 0;
    int ret = 0;

    /* TODO: handshake messages after initial handshake will have their
       duplicated fsm */
    fsm = &ssl->handshakeRtxFSM;

    WOLFSSL_ENTER("dtls13_process_buffered_messages()");

    while (msg != NULL) {
        idx = 0;

        /* message not in order */
        if (ssl->keys.dtls_expected_peer_handshake_number != msg->seq)
            break;

        /* message not complete */
        if (msg->fragSz != msg->sz)
            break;

        /* even if this record was acked, the lost one that stopped the
           processing of this message wasn't. */
        if (Dtls13RtxNeedsExplicitAck(ssl, msg->type))
            fsm->sendAcks = 1;

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

static WC_INLINE void Dtls13FreeRtxBufferRecord(
    WOLFSSL *ssl, Dtls13RtxRecord *r)
{
    (void)ssl;

    XFREE(r->data, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
    XFREE(r, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
}

/* rn is a size 2 array  */
static Dtls13RtxRecord *Dtls13RtxNewRecord(WOLFSSL *ssl, byte *data,
    word16 length, enum HandShakeType handshakeType, word32 *rn)
{
    Dtls13RtxRecord *r;
    int epochNumber;
    byte *buf;

    WOLFSSL_ENTER("Dtls13RtxNewRecord");

    if (ssl->dtls13EncryptEpoch == NULL)
        return NULL;

    epochNumber = ssl->dtls13EncryptEpoch->epochNumber;

    r = (Dtls13RtxRecord *)XMALLOC(
        sizeof(*r), ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
    if (r == NULL)
        return NULL;

    buf = (byte*)XMALLOC(length, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
    if (buf == NULL) {
        XFREE(r, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
        return NULL;
    }

    XMEMCPY(buf, data, length);

    r->epoch = epochNumber;
    r->data = buf;
    r->length = length;
    r->next = NULL;
    r->handshakeType = handshakeType;
    r->rn[0][0] = rn[0];
    r->rn[0][1] = rn[1];
    r->rnIdx = 1;

    return r;
}

static void Dtls13RtxAddRecord(Dtls13RtxFSM *fsm, Dtls13RtxRecord *r)
{
    Dtls13RtxRecord *list;

    WOLFSSL_ENTER("Dtls13RtxAddRecord");

    list = fsm->rtxRecords;

    /* list empty */
    if (list == NULL) {
        fsm->rtxRecords = r;
        return;
    }

    while (list->next != NULL)
        list = list->next;

    list->next = r;
}

static void Dtls13RtxFlushBuffered(
    WOLFSSL *ssl, Dtls13RtxFSM *fsm, byte keepNewSessionTicket)
{
    Dtls13RtxRecord *list, *r;

    WOLFSSL_ENTER("Dtls13RtxFlushBuffered");

    list = fsm->rtxRecords;

    if (list == NULL)
        return;

    /* we process the head at the end */
    while (list->next != NULL) {

        if (keepNewSessionTicket &&
            list->next->handshakeType == session_ticket) {
            list = list->next;
            continue;
        }

        /* else */
        r = list->next;
        list->next = r->next;
        Dtls13FreeRtxBufferRecord(ssl, r);
    }

    list = fsm->rtxRecords;

    if (keepNewSessionTicket && list->handshakeType == session_ticket)
        return;

    fsm->rtxRecords = list->next;
    Dtls13FreeRtxBufferRecord(ssl, list);
}

/* recordNumber is a size 2 array */
static Dtls13RecordNumber *Dtls13NewRecordNumber(
    WOLFSSL *ssl, word32 *recordNumber)
{
    Dtls13RecordNumber *rn;

    rn = (Dtls13RecordNumber *)XMALLOC(
        sizeof(*rn), ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
    if (rn == NULL)
        return NULL;

    XMEMCPY(rn->seq, recordNumber, sizeof(rn->seq));
    rn->next = NULL;

    return rn;
}

/* recordNumber is a size 2 array */
static int Dtls13RtxAddAck(
    WOLFSSL *ssl, Dtls13RtxFSM *fsm, word32 *recordNumber)
{
    Dtls13RecordNumber *rn, *list;

    WOLFSSL_ENTER("Dtls13RtxAddAck");

    rn = Dtls13NewRecordNumber(ssl, recordNumber);
    if (rn == NULL)
        return MEMORY_E;

    list = fsm->ackRecords;
    if (list == NULL) {
        fsm->ackRecords = rn;
        return 0;
    }

    while (list->next != NULL)
        list = list->next;

    list->next = rn;

    return 0;
}

static void Dtls13RtxFlushAcks(WOLFSSL *ssl, Dtls13RtxFSM *fsm)
{
    Dtls13RecordNumber *list, *rn;

    (void)ssl;

    WOLFSSL_ENTER("Dtls13RtxFlushAcks");

    list = fsm->ackRecords;

    while (list != NULL) {
        rn = list;
        list = rn->next;
        XFREE(rn, ssl->heap, DYNAMIC_TYEP_DTLS_MSG);
    }

    fsm->ackRecords = NULL;
}

static int Dtls13DetectDisruption(WOLFSSL *ssl, word32 fragOffset)
{
    /* retranmisssion. The other peer may have lost our flight or our ACKs. We
       not account this as a distruption */
    if (ssl->keys.dtls_peer_handshake_number <
        ssl->keys.dtls_expected_peer_handshake_number)
        return 0;

    /* out of order message */
    if (ssl->keys.dtls_peer_handshake_number >
        ssl->keys.dtls_expected_peer_handshake_number)
        return 1;

    /* first fragment of in-order message */
    if (fragOffset == 0)
        return 0;

    /* is not the next fragment in the message (the check is not 100% perfect,
       in the worst case, we don't detect the disruption and wait for the other
       peer retransmission) */
    if (ssl->dtls_rx_msg_list == NULL ||
        ssl->dtls_rx_msg_list->fragSz != fragOffset)
        return 1;

    return 0;
}

/* recordNumber is a size 2 array */
static int Dtls13RtxRecordRecvd(WOLFSSL *ssl, enum HandShakeType hs,
    Dtls13RtxFSM *fsm, word32 *recordNumber, word32 fragOffset)
{
    int ret;

    WOLFSSL_ENTER("Dtls13RtxRecordRecvd");

    if (!ssl->options.handShakeDone || hs != certificate_request) {
        /* After handshake we don't save certificate_req in the seen
           records. This is because we will ack that message with a
           certificate/cert_verifiy/finished flight and we have not a simple and
           nice way to remove this from seen records. */
        ret = Dtls13RtxAddAck(ssl, fsm, recordNumber);
        if (ret != 0) {
            WOLFSSL_MSG("can't save ack fragment");
            return ret;
        }
    }

    if (!ssl->options.handShakeDone
        && ssl->keys.dtls_peer_handshake_number >=
        ssl->keys.dtls_expected_peer_handshake_number) {

        /* In the handshake, receiving part of the next flight, acknowledge the
           sent flight. The only exception is, on the server side, receiving the
           last client flight does not ACK any sent new_session_ticket
           messages. */
        Dtls13RtxFlushBuffered(ssl, fsm, 1);
    }

    if (ssl->keys.dtls_peer_handshake_number <
        ssl->keys.dtls_expected_peer_handshake_number) {

        /* retransmission detected. */
        fsm->retransmit = 1;

        /* the other peer may have retransmitted because an ACK for a flight
           that needs explicit ACK was lost */
        if (fsm->ackRecords != NULL)
            fsm->sendAcks = 1;
    }

    if (Dtls13RtxNeedsExplicitAck(ssl, hs)
        || Dtls13DetectDisruption(ssl, fragOffset)) {
        fsm->sendAcks = 1;
    }

    return 0;
}

void Dtls13FreeFsmResources(WOLFSSL *ssl, Dtls13RtxFSM *fsm)
{
    Dtls13RtxFlushAcks(ssl, fsm);
    Dtls13RtxFlushBuffered(ssl, fsm, 0);
}

static int Dtls13SendOneFragmentRtx(WOLFSSL *ssl, Dtls13RtxFSM *fsm,
    enum HandShakeType handshakeType, word16 outputSize, byte *message,
    word32 length, int hashOutput)
{
    Dtls13RtxRecord *rtxRecord;
    word16 recordHeaderLength;
    byte isProtected;
    word32 rn[2];
    int ret;

    isProtected = Dtls13TypeIsEncrypted(handshakeType);
    recordHeaderLength = Dtls13GetRlHeaderLength(isProtected);

    Dtls13GetSeq(ssl, CUR_ORDER, rn, 0);
    rtxRecord = Dtls13RtxNewRecord(ssl, message + recordHeaderLength,
        length - recordHeaderLength, handshakeType, rn);

    if (rtxRecord == NULL)
        return MEMORY_E;

    ret = Dtls13SendFragment(
        ssl, message, outputSize, length, handshakeType, hashOutput);

    if (ret == 0 || ret == WANT_WRITE)
        Dtls13RtxAddRecord(fsm, rtxRecord);
    else
        Dtls13FreeRtxBufferRecord(ssl, rtxRecord);

    return ret;
}

static int Dtls13SendFragmentedInternal(WOLFSSL *ssl)
{
    int fragLength, rlHeaderLength;
    int remainingSize, maxFragment;
    Dtls13RtxFSM *fsm;
    int recordLength;
    byte isEncrypted;
    byte *output;
    int ret;

    isEncrypted = Dtls13TypeIsEncrypted(ssl->dtls13FragHandshakeType);
    rlHeaderLength = Dtls13GetRlHeaderLength(isEncrypted);
    maxFragment = wolfSSL_GetMaxFragSize(ssl, MAX_RECORD_SIZE);

    remainingSize = ssl->dtls13MessageLength - ssl->dtls13FragOffset;

    fsm = &ssl->handshakeRtxFSM;

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

        ret = Dtls13SendOneFragmentRtx(ssl, fsm, ssl->dtls13FragHandshakeType,
            maxFragment, output, recordLength, 0);
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
    word16 seqNumber;

    if (out == NULL)
        return BAD_FUNC_ARG;

    if (ssl->dtls13EncryptEpoch == NULL)
        return BAD_STATE_E;

    hdr = (Dtls13RecordCiphertextHeader *)out;

    hdr->unifiedHdrFlags = DTLS13_FIXED_BITS;
    hdr->unifiedHdrFlags |= (ssl->dtls13EncryptEpoch->epochNumber & EE_MASK);

    /* include 16-bit seq */
    hdr->unifiedHdrFlags |= DTLS13_S_BIT;
    /* include 16-bit length */
    hdr->unifiedHdrFlags |= DTLS13_L_BIT;

    seqNumber = (word16)(ssl->dtls13EncryptEpoch->nextSeqNumberLo);
    c16toa(seqNumber, hdr->sequenceNumber);

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

/* seq is a size 2 array */
static WC_INLINE void Dtls13MakeRN(
    word32 epoch, word16 seqHi, word32 seqLo, word32 *seq)
{
    seq[0] = (epoch << 16) | (seqHi & 0xFFFF);
    seq[1] = seqLo;
}

#define DTLS13_MIN_RTX_INTERVAL 1

static int Dtls13RtxSendBuffered(WOLFSSL *ssl, Dtls13RtxFSM *fsm)
{
    word16 headerLength;
    Dtls13RtxRecord *r;
    word32 newRn[2];
    byte *output;
    int sendSz;
    word32 now;
    int ret;

    WOLFSSL_ENTER("Dtls13RtxSendBuffered");

    now = LowResTimer();
    if (now - fsm->lastRtx < DTLS13_MIN_RTX_INTERVAL) {
#ifdef WOLFSSL_DEBUG_TLS
        WOLFSSL_MSG("Avoid to fast retransmission");
#endif /* WOLFSSL_DEBUG_TLS */
        return 0;
    }

    fsm->lastRtx = now;

    r = fsm->rtxRecords;
    while (r != NULL) {
        headerLength = Dtls13GetRlHeaderLength(r->epoch != 0);

        sendSz = r->length + headerLength;

        if (r->epoch != 0)
          sendSz += MAX_MSG_EXTRA;

        ret = CheckAvailableSize(ssl, sendSz);
        if (ret != 0)
            return ret;

        output = ssl->buffers.outputBuffer.buffer +
            ssl->buffers.outputBuffer.length;

        XMEMCPY(output + headerLength, r->data, r->length);

        if (ssl->dtls13EncryptEpoch->epochNumber != r->epoch) {
            ret = Dtls13SetEpochKeys(ssl, r->epoch, ENCRYPT_SIDE_ONLY);
            if (ret != 0)
                return ret;
        }

        ret = Dtls13GetSeq(ssl, CUR_ORDER, newRn, 0);
        if (ret != 0)
            return ret;

        ret = Dtls13SendFragment(
            ssl, output, sendSz, r->length + headerLength, r->handshakeType, 0);
        if (ret != 0)
            return ret;

        if (r->rnIdx >= DTLS13_RETRANS_RN_SIZE)
            r->rnIdx = 0;

        r->rn[r->rnIdx][0] = newRn[0];
        r->rn[r->rnIdx][1] = newRn[1];
        r->rnIdx++;

        r = r->next;
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
    Dtls13RtxFSM *fsm;
    word32 seq[2];
    word32 idx;
    int epoch;
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

    /* TODO: handshake messages after initial handhsake will have their
       duplicated fsm */
    fsm = &ssl->handshakeRtxFSM;

    epoch = ssl->keys.curEpoch;
    Dtls13MakeRN(epoch, ssl->keys.curSeq_hi, ssl->keys.curSeq_lo, seq);
    ret = Dtls13RtxRecordRecvd(ssl, handshake_type, fsm, seq, frag_off);
    if (ret != 0)
        return ret;

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
    Dtls13RtxFSM *fsm;
    int maxFrag;
    int maxLen;
    int ret;

    if (ssl->dtls13EncryptEpoch == NULL)
        return BAD_STATE_E;

    fsm = &ssl->handshakeRtxFSM;

    if (!ssl->options.handShakeDone) {

        /* during the handshake, if we are sending a new flight, we can flush
           our ACK list. When sending client
           [certificate/certificate_verify]/finished flight, we may flush an ACK
           for a newSessionticket message, sent by the server just after sending
           its finished message. This should not be a problem. That message
           arrived out-of-order (before the server finished) so likely an ACK
           was already sent. In the worst case we will ACK the server
           retranmission*/
        if (handshakeType == certificate || handshakeType == finished ||
            handshakeType == server_hello)
            Dtls13RtxFlushAcks(ssl, fsm);
    }

    /* we want to send always with the highest epoch  */
    if (ssl->dtls13EncryptEpoch->epochNumber != ssl->dtls13Epoch) {
        ret = Dtls13SetEpochKeys(ssl, ssl->dtls13Epoch, ENCRYPT_SIDE_ONLY);
        if (ret != 0)
            return ret;
    }

    maxFrag = wolfSSL_GetMaxFragSize(ssl, MAX_RECORD_SIZE);
    maxLen = length;

    if (maxLen < maxFrag) {
        ret = Dtls13SendOneFragmentRtx(
            ssl, fsm, handshakeType, outputSize, message, length, hashOutput);
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

struct Dtls13Epoch *Dtls13GetEpoch(WOLFSSL *ssl, word32 epochNumber)
{
    Dtls13Epoch *e;
    int i;

    for (i = 0; i < DTLS13_EPOCH_SIZE; ++i) {
        e = &ssl->dtls13Epochs[i];
        if (e->epochNumber == epochNumber && e->isValid)
            return e;
    }

    return NULL;
}

/* FIXME: copy only one side */
static void Dtls13EpochCopyKeys(WOLFSSL *ssl, Dtls13Epoch *e, Keys *k, int side)
{
    byte clientWrite, serverWrite;
    byte enc, dec;

    WOLFSSL_ENTER("Dtls13SetEpochKeys");

    clientWrite = serverWrite = 0;
    enc = dec = 0;
    switch (side) {

    case ENCRYPT_SIDE_ONLY:
        if (ssl->options.side == WOLFSSL_CLIENT_END)
            clientWrite = 1;
        if (ssl->options.side == WOLFSSL_SERVER_END)
            serverWrite = 1;
        enc = 1;
        break;

    case DECRYPT_SIDE_ONLY:
        if (ssl->options.side == WOLFSSL_CLIENT_END)
            serverWrite = 1;
        if (ssl->options.side == WOLFSSL_SERVER_END)
            clientWrite = 1;
        dec = 1;
        break;

    case ENCRYPT_AND_DECRYPT_SIDE:
        clientWrite = serverWrite = 1;
        enc = dec = 1;
        break;
    }

    if (clientWrite) {
        XMEMCPY(e->client_write_key, k->client_write_key,
            sizeof(e->client_write_key));

        XMEMCPY(
            e->client_write_IV, k->client_write_IV, sizeof(e->client_write_IV));

        XMEMCPY(e->client_sn_key, k->client_sn_key, sizeof(e->client_sn_key));
    }

    if (serverWrite) {
        XMEMCPY(e->server_write_key, k->server_write_key,
            sizeof(e->server_write_key));
        XMEMCPY(
            e->server_write_IV, k->server_write_IV, sizeof(e->server_write_IV));
        XMEMCPY(e->server_sn_key, k->server_sn_key, sizeof(e->server_sn_key));
    }

    /* FIXME:  */
    /* XMEMCPY(e->aead_exp_IV, k->aead_exp_IV, */
    /*         sizeof(e->aead_exp_IV)); */
    if (enc)
        XMEMCPY(
            e->aead_enc_imp_IV, k->aead_enc_imp_IV, sizeof(e->aead_enc_imp_IV));

    if (dec)
        XMEMCPY(
            e->aead_dec_imp_IV, k->aead_dec_imp_IV, sizeof(e->aead_dec_imp_IV));
}
static WC_INLINE void Dtls13SeqInc(word16 *seqHi, word32 *seqLo)
{
    *seqLo = *seqLo + 1;
    if (*seqLo == 0)
        *seqHi = *seqHi + 1;
}

/* seq is a size 2 array */
int Dtls13GetSeq(WOLFSSL *ssl, int order, word32 *seq, byte increment)
{
    word16 epoch;
    word16 *seqHi;
    word32 *seqLo;

    if (order == PEER_ORDER) {
        epoch = ssl->keys.curEpoch;
        seqHi = &ssl->keys.curSeq_hi;
        seqLo = &ssl->keys.curSeq_lo;
        /* never increment seq number for curent record. In DTLS seq number are
           explicit */
        increment = 0;
    }
    else if (order == CUR_ORDER) {

        if (ssl->dtls13EncryptEpoch == NULL) {
            return BAD_STATE_E;
        }

        epoch = ssl->dtls13EncryptEpoch->epochNumber;
        seqHi = &ssl->dtls13EncryptEpoch->nextSeqNumberHi;
        seqLo = &ssl->dtls13EncryptEpoch->nextSeqNumberLo;
    }
    else {
        return BAD_FUNC_ARG;
    }

    Dtls13MakeRN(epoch, *seqHi, *seqLo, seq);
    if (increment)
        Dtls13SeqInc(seqHi, seqLo);

    return 0;
}

static Dtls13Epoch *Dtls13NewEpochSlot(WOLFSSL *ssl)
{
    Dtls13Epoch *e, *oldest = NULL;
    word32 oldestNumber;
    byte found = 0;
    int i;

    /* if epochs[0] is not valid, it will be the chosen slot */
    oldestNumber = ssl->dtls13Epochs[0].epochNumber;
    oldest = &ssl->dtls13Epochs[0];

    for (i = 0; i < DTLS13_EPOCH_SIZE; ++i) {
        e = &ssl->dtls13Epochs[i];
        if (!e->isValid) {
            found = 1;
            break;
        }

        if (e->epochNumber != ssl->dtls13Epoch && e->epochNumber < oldestNumber)
            oldest = e;
    }

    if (!found) {
        e = oldest;
        XMEMSET(e, 0, sizeof(*e));
    }

    return e;
}

int Dtls13NewEpoch(WOLFSSL *ssl, word32 epochNumber, int side)
{
    Dtls13Epoch *e;

    WOLFSSL_ENTER("Dtls13NewEpoch");

    e = Dtls13GetEpoch(ssl, epochNumber);
    if (e == NULL) {
        e = Dtls13NewEpochSlot(ssl);
        if (e == NULL)
            return BAD_STATE_E;
    }

    Dtls13EpochCopyKeys(ssl, e, &ssl->keys, side);

    if (!e->isValid) {
        e->epochNumber = epochNumber;
        e->isValid = 1;
        e->side = side;
    }
    else if (e->side != side) {
        e->side = ENCRYPT_AND_DECRYPT_SIDE;
    }

    return 0;
}

int Dtls13SetEpochKeys(WOLFSSL *ssl, int epochNumber, enum encrypt_side side)
{
    byte clientWrite, serverWrite;
    Dtls13Epoch *e;
    byte enc, dec;

    WOLFSSL_ENTER("Dtls13SetEpochKeys");

    clientWrite = serverWrite = 0;
    enc = dec = 0;
    switch (side) {

    case ENCRYPT_SIDE_ONLY:
        if (ssl->options.side == WOLFSSL_CLIENT_END)
            clientWrite = 1;
        if (ssl->options.side == WOLFSSL_SERVER_END)
            serverWrite = 1;
        enc = 1;
        break;

    case DECRYPT_SIDE_ONLY:
        if (ssl->options.side == WOLFSSL_CLIENT_END)
            serverWrite = 1;
        if (ssl->options.side == WOLFSSL_SERVER_END)
            clientWrite = 1;
        dec = 1;
        break;

    case ENCRYPT_AND_DECRYPT_SIDE:
        clientWrite = serverWrite = 1;
        enc = dec = 1;
        break;
    }


    e = Dtls13GetEpoch(ssl, epochNumber);
    /* we don't have the requested key */
    if (e == NULL)
        return BAD_STATE_E;

    if (e->side != ENCRYPT_AND_DECRYPT_SIDE && e->side != side)
        return BAD_STATE_E;

    if (enc)
        ssl->dtls13EncryptEpoch = e;
    if (dec)
        ssl->dtls13DecryptEpoch = e;

    /* epoch 0 has no key to copy */
    if (epochNumber == 0)
        return 0;

    if (clientWrite) {
        XMEMCPY(ssl->keys.client_write_key, e->client_write_key,
            sizeof(ssl->keys.client_write_key));

        XMEMCPY(ssl->keys.client_write_IV, e->client_write_IV,
            sizeof(ssl->keys.client_write_IV));

        XMEMCPY(ssl->keys.client_sn_key, e->client_sn_key,
            sizeof(ssl->keys.client_sn_key));
    }

    if (serverWrite) {
        XMEMCPY(ssl->keys.server_write_key, e->server_write_key,
            sizeof(ssl->keys.server_write_key));

        XMEMCPY(ssl->keys.server_write_IV, e->server_write_IV,
            sizeof(ssl->keys.server_write_IV));

        XMEMCPY(ssl->keys.server_sn_key, e->server_sn_key,
            sizeof(ssl->keys.server_sn_key));
    }

    if (enc)
        XMEMCPY(ssl->keys.aead_enc_imp_IV, e->aead_enc_imp_IV,
            sizeof(ssl->keys.aead_enc_imp_IV));
    if (dec)
        XMEMCPY(ssl->keys.aead_dec_imp_IV, e->aead_dec_imp_IV,
            sizeof(ssl->keys.aead_dec_imp_IV));

    return SetKeysSide(ssl, side);
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

#define DTLS13_RN_EPOCH_SIZE (16 / 8)
#define DTLS13_RN_SEQ_SIZE (48 / 8)

static int Dtls13GetAckListLength(Dtls13RecordNumber *list, word16 *length)
{
    int numberElements;

    numberElements = 0;

    /* TODO: check that we don't exceed the maximum length */

    while(list != NULL) {
        list = list->next;
        numberElements++;
    }

    *length = (DTLS13_RN_EPOCH_SIZE + DTLS13_RN_SEQ_SIZE) * numberElements;
    return 0;
}

static int Dtls13WriteAckMessage(
    WOLFSSL *ssl, Dtls13RecordNumber *recordNumberList, word32 *length)
{
    word16 msgSz, headerLength;
    byte *output, *ackMessage;
    word32 sendSz;
    int ret;

    sendSz = 0;

    if (ssl->dtls13EncryptEpoch == NULL)
        return BAD_STATE_E;

    if (ssl->dtls13EncryptEpoch->epochNumber == 0) {
        /* unprotected ACK */
        headerLength = DTLS_RECORD_HEADER_SZ;;
    }
    else {
        headerLength = Dtls13GetRlHeaderLength(1);
        sendSz += MAX_MSG_EXTRA;
    }

    ret = Dtls13GetAckListLength(recordNumberList, &msgSz);
    if (ret != 0)
        return ret;

    sendSz += headerLength;

    /* ACK list size */
    sendSz += OPAQUE16_LEN;

    /* ACK list */
    sendSz += msgSz;

    ret = CheckAvailableSize(ssl, sendSz);
    if (ret != 0)
        return ret;

    output = ssl->buffers.outputBuffer.buffer +
        ssl->buffers.outputBuffer.length;

    ackMessage = output + headerLength;

    c16toa(msgSz, ackMessage);
    ackMessage += OPAQUE16_LEN;

    while (recordNumberList != NULL) {
        XMEMCPY(
            ackMessage, recordNumberList->seq, sizeof(recordNumberList->seq));
        ackMessage += sizeof(recordNumberList->seq);
        recordNumberList = recordNumberList->next;
    }

    *length = msgSz + OPAQUE16_LEN;

    return 0;
}

/* seq is a size 2 array */
static int Dtls13RtxIsTrackedByRn(const Dtls13RtxRecord *r, const word32 *seq)
{
    int i;

    for (i = 0; i < r->rnIdx; ++i) {
        if (r->rn[i][0] == seq[0] && r->rn[i][1] == seq[1]) {
            return 1;
        }
    }

    return 0;
}

/* seq is a size 2 array */
static int Dtls13RtxRemoveRecord(
    WOLFSSL *ssl, Dtls13RtxFSM *fsm, const word32 *seq)
{
    Dtls13RtxRecord *r, **prev_next;


    prev_next = &fsm->rtxRecords;
    r = fsm->rtxRecords;

    while (r != NULL) {
        if (Dtls13RtxIsTrackedByRn(r, seq)) {
            *prev_next = r->next;
            Dtls13FreeRtxBufferRecord(ssl, r);
            return 0;
        }
        prev_next = &r->next;
        r = r->next;
    }

    return 0;
}

int Dtls13DoScheduledWork(WOLFSSL *ssl)
{
    int ret;

    WOLFSSL_ENTER("Dtls13DoScheduledWork");

#ifdef WOLFSSL_DTLS13_DATAPENDING
    if(Dtls13DataPending(ssl, (WOLFSSL_DTLS_CTX *)ssl->IOCB_ReadCtx)) {
        WOLFSSL_MSG("deferring scheduled  work to process pending messages");
        return 0;
    }
#endif

    if (ssl->handshakeRtxFSM.sendAcks) {
        ssl->handshakeRtxFSM.sendAcks = 0;
        ret = SendDtls13Ack(ssl);
        if (ret != 0)
            return ret;
    }

    if (ssl->handshakeRtxFSM.retransmit) {

        ssl->handshakeRtxFSM.retransmit = 0;
        ret = Dtls13RtxSendBuffered(ssl, &ssl->handshakeRtxFSM);
        if (ret != 0)
            return ret;
    }

    return 0;
}

int Dtls13RtxTimeout(WOLFSSL *ssl)
{
    return Dtls13RtxSendBuffered(ssl, &ssl->handshakeRtxFSM);
}

int DoDtls13Ack(
    WOLFSSL *ssl, const byte *input, word32 inputSize, word32 *processedSize)
{
    Dtls13RtxFSM *fsm;
    const byte *ackMessage;
    word16 length;
    int i;

    if (inputSize < OPAQUE16_LEN)
      return BUFFER_ERROR;

    fsm = &ssl->handshakeRtxFSM;

    ato16(input, &length);

    if (inputSize < (word32)(OPAQUE16_LEN + length))
        return BUFFER_ERROR;

    if (length % (DTLS13_RN_EPOCH_SIZE + DTLS13_RN_SEQ_SIZE) != 0)
        return PARSE_ERROR;

    ackMessage = input + OPAQUE16_LEN;
    for (i = 0; i < length;
         i += DTLS13_RN_EPOCH_SIZE + DTLS13_RN_SEQ_SIZE) {

        Dtls13RtxRemoveRecord(ssl, fsm, (const word32*)(ackMessage + i));

    }

    /* last client flight was completely acknowledged by the server. Handshake
       is complete. */
    if (ssl->options.side == WOLFSSL_CLIENT_END &&
        ssl->options.connectState == WAIT_FINISHED_ACK &&
        fsm->rtxRecords == NULL) {
        ssl->options.serverState = SERVER_FINISHED_ACKED;
    }

    *processedSize = length + OPAQUE16_LEN;

    if (fsm->rtxRecords != NULL)
        fsm->retransmit = 1;

    return 0;
}

int SendDtls13Ack(WOLFSSL *ssl)
{
    Dtls13RtxFSM *fsm;
    word32 outputSize;
    int headerSize;
    word32 length;
    byte *output;
    int ret;

    if (ssl->dtls13EncryptEpoch == NULL)
        return BAD_STATE_E;

    WOLFSSL_ENTER("SendDtls13Ack");

    fsm = &ssl->handshakeRtxFSM;

    ret = 0;

    if (ssl->options.side == WOLFSSL_SERVER_END &&
        !ssl->options.handShakeDone &&
        ssl->dtls13Epoch >= DTLS13_EPOCH_TRAFFIC0) {
        ret =
            Dtls13SetEpochKeys(ssl, DTLS13_EPOCH_HANDSHAKE, ENCRYPT_SIDE_ONLY);
    }
    else if (ssl->dtls13Epoch != ssl->dtls13EncryptEpoch->epochNumber) {
        ret = Dtls13SetEpochKeys(ssl, ssl->dtls13Epoch, ENCRYPT_SIDE_ONLY);
    }

    if (ret != 0)
        return ret;

    if (ssl->dtls13EncryptEpoch->epochNumber == 0) {

        ret = Dtls13WriteAckMessage(ssl, fsm->ackRecords, &length);
        if (ret != 0)
            return ret;

        output = ssl->buffers.outputBuffer.buffer +
            ssl->buffers.outputBuffer.length;

        ret = Dtls13RlAddPlaintextHeader(ssl, output, ack, length);
        if (ret != 0)
            return ret;

        ssl->buffers.outputBuffer.length += length + DTLS_RECORD_HEADER_SZ;

        return SendBuffered(ssl);
    }


    ret = Dtls13WriteAckMessage(ssl, fsm->ackRecords, &length);
    if (ret != 0)
        return ret;

    output = ssl->buffers.outputBuffer.buffer +
        ssl->buffers.outputBuffer.length;

    outputSize = ssl->buffers.outputBuffer.bufferSize -
        ssl->buffers.outputBuffer.length;

    headerSize = Dtls13GetRlHeaderLength(1);

    ret = BuildTls13Message(
        ssl, output, outputSize, output + headerSize, length, ack, 0, 0, 0);
    if (ret < 0)
        return ret;

    Dtls13RtxFlushAcks(ssl, fsm);

    ssl->buffers.outputBuffer.length += ret;
    return SendBuffered(ssl);
}

static int Dtls13RtxRecordMatchesReqCtx(
    Dtls13RtxRecord *r, byte *ctx, byte ctxLen)
{
    if (r->handshakeType != certificate_request)
        return 0;
    if (r->length <= ctxLen + 1)
        return 0;
    return XMEMCMP(ctx, r->data + 1, ctxLen) == 0;
}

int Dtls13RtxProcessingCertificate(WOLFSSL *ssl, byte *input, word32 inputSize)
{
    Dtls13RtxRecord *rtxRecord, *r;
    byte ctxLength;

    WOLFSSL_ENTER("Dtls13RtxProcessingCertificate");

    if (inputSize <= 1) {
        WOLFSSL_MSG("Malformed Certificate");
        return BAD_FUNC_ARG;
    }

    ctxLength = *input;

    if (inputSize < ctxLength + OPAQUE8_LEN) {
        WOLFSSL_MSG("Malformed Certificate");
        return BAD_FUNC_ARG;
    }

    rtxRecord = ssl->handshakeRtxFSM.rtxRecords;

    if (Dtls13RtxRecordMatchesReqCtx(rtxRecord, input + 1, ctxLength)) {
        ssl->handshakeRtxFSM.rtxRecords = rtxRecord->next;
        Dtls13FreeRtxBufferRecord(ssl, rtxRecord);
        return 0;
    }

    while(rtxRecord->next != NULL) {
        if (Dtls13RtxRecordMatchesReqCtx(
                rtxRecord->next, input + 1, ctxLength)) {
            r = rtxRecord->next;
            rtxRecord->next = r->next;
            Dtls13FreeRtxBufferRecord(ssl, rtxRecord);
            return 0;
        }
    }

    WOLFSSL_MSG("Can't find any previous Certificate Request");
    return 0;
}

#endif /* WOLFSSL_DTLS13 */
