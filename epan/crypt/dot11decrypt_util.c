/* dot11decrypt_util.c
 *
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
 */

/****************************************************************************/
/* File includes                                                            */
#include "config.h"
#include "dot11decrypt_int.h"

#include "dot11decrypt_debug.h"
#include "dot11decrypt_util.h"
#include <glib.h>

/****************************************************************************/
/*    Internal definitions                                                  */

#define FC0_AAD_MASK 0x8f
#define FC1_AAD_MASK 0xc7

/****************************************************************************/
/* Internal macros                                                          */

/****************************************************************************/
/* Internal function prototypes declarations                                */

/****************************************************************************/
/* Function definitions                                                     */

/* From IEEE 802.11 2016 Chapter 12.5.3.3.3 and 12.5.5.3.3 Construct AAD */
void dot11decrypt_construct_aad(
    PDOT11DECRYPT_MAC_FRAME wh,
    guint8 *aad,
    size_t *aad_len)
{
    guint8 mgmt = (DOT11DECRYPT_TYPE(wh->fc[0]) == DOT11DECRYPT_TYPE_MANAGEMENT);
    int alen = 22;

    /* AAD:
    * FC with bits 4..6 and 11..13 masked to zero; 14 is always one
    * A1 | A2 | A3
    * SC with bits 4..15 (seq#) masked to zero
    * A4 (if present)
    * QC (if present)
    */

    /* NB: aad[1] set below */
    if (!mgmt) {
        aad[0] = (UINT8)(wh->fc[0] & FC0_AAD_MASK);
    } else {
        aad[0] = wh->fc[0];
    }
    aad[1] = (UINT8)(wh->fc[1] & FC1_AAD_MASK);
    memcpy(aad + 2, (guint8 *)wh->addr1, DOT11DECRYPT_MAC_LEN);
    memcpy(aad + 8, (guint8 *)wh->addr2, DOT11DECRYPT_MAC_LEN);
    memcpy(aad + 14, (guint8 *)wh->addr3, DOT11DECRYPT_MAC_LEN);
    aad[20] = (UINT8)(wh->seq[0] & DOT11DECRYPT_SEQ_FRAG_MASK);
    aad[21] = 0; /* all bits masked */

    /*
    * Construct variable-length portion of AAD based
    * on whether this is a 4-address frame/QOS frame.
    */
    if (DOT11DECRYPT_IS_4ADDRESS(wh)) {
        alen += 6;
        DOT11DECRYPT_ADDR_COPY(aad + 22,
            ((PDOT11DECRYPT_MAC_FRAME_ADDR4)wh)->addr4);
        if (DOT11DECRYPT_IS_QOS_DATA(wh)) {
            PDOT11DECRYPT_MAC_FRAME_ADDR4_QOS qwh4 =
                (PDOT11DECRYPT_MAC_FRAME_ADDR4_QOS) wh;
            aad[28] = (UINT8)(qwh4->qos[0] & 0x0f);/* just priority bits */
            aad[29] = 0;
            alen += 2;
        }
    } else {
        if (DOT11DECRYPT_IS_QOS_DATA(wh)) {
            PDOT11DECRYPT_MAC_FRAME_QOS qwh =
                (PDOT11DECRYPT_MAC_FRAME_QOS) wh;
            aad[22] = (UINT8)(qwh->qos[0] & 0x0f); /* just priority bits */
            aad[23] = 0;
            alen += 2;
        }
    }
    *aad_len = alen;
}

/**
 * IEEE 802.11-2016 12.7.1.2 PRF (Pseudo Random Function)
 *
 * @param key Derivation input key.
 * @param key_len Length of the key in bytes.
 * @param label Unique label for each different purpose of the PRF (named 'A' in the standard).
 * @param context Provides context to identify the derived key (named 'B' in the standard).
 * @param context_len Length of context in bytes.
 * @param hash_algo Hash algorithm to use for the PRF.
 *        See gcrypt available hash algorithms:
 *        https://gnupg.org/documentation/manuals/gcrypt/Available-hash-algorithms.html
 * @param[out] output Derived key.
 * @param output_len Length of derived key in bytes.
 * @return FALSE on error
 */
#define MAX_R_LEN 256
#define MAX_TMP_LEN 1024
#define MAX_CONTEXT_LEN 256

gboolean
dot11decrypt_prf(const guint8 *key, size_t key_len,
                 const char *label,
                 const guint8 *context, size_t context_len,
                 int hash_algo,
                 guint8 *output, size_t output_len)
{
    guint8 R[MAX_R_LEN]; /* Will hold "label || 0 || context || i" */
    size_t label_len = strlen(label);
    guint8 tmp[MAX_TMP_LEN];
    guint16 hash_len = gcry_md_get_algo_dlen(hash_algo);
    size_t offset = 0;
    guint8 i;

    if (!key || !label || !context || !output) {
        return FALSE;
    }
    if (label_len + 1 + context_len + 1 > MAX_R_LEN ||
        output_len > 64) {
        DEBUG_PRINT_LINE("Invalid input or output sizes", DEBUG_LEVEL_3);
        return FALSE;
    }

    /* Fill R with "label || 0 || context || i" */
    memcpy(R + offset, label, label_len);
    offset += label_len;
    R[offset++] = 0;
    memcpy(R + offset, context, context_len);
    offset += context_len;

    for (i = 0; i <= output_len * 8 / 160; i++)
    {
        R[offset] = i;
        if (ws_hmac_buffer(hash_algo, tmp + hash_len * i, R, offset + 1, key, key_len)) {
            return FALSE;
        }
    }
    memcpy(output, tmp, output_len);
    return TRUE;
}

/**
 * 12.7.1.7.2 Key derivation function (KDF)
 *
 * @param key Derivation input key.
 * @param key_len Length of the key in bytes.
 * @param label A string identifying the purpose of the keys derived using this KDF.
 * @param context Provides context to identify the derived key.
 * @param context_len Length of context in bytes.
 * @param hash_algo Hash algorithm to use for the KDF.
 *        See gcrypt available hash algorithms:
 *        https://gnupg.org/documentation/manuals/gcrypt/Available-hash-algorithms.html
 * @param[out] output Derived key.
 * @param output_len Length of derived key in bytes.
 * @return FALSE on error
 */
gboolean
dot11decrypt_kdf(const guint8 *key, size_t key_len,
                 const char *label,
                 const guint8 *context, size_t context_len,
                 int hash_algo,
                 guint8 *output, size_t output_len)
{
    guint8 R[MAX_R_LEN]; /* Will hold "i || Label || Context || Length" */
    guint8 tmp[MAX_TMP_LEN];
    size_t label_len = strlen(label);
    guint16 hash_len = gcry_md_get_algo_dlen(hash_algo);
    guint iterations = (guint)output_len * 8 / hash_len;
    guint16 len_le = GUINT16_TO_LE(output_len * 8);
    size_t offset = 0;
    guint16 i;

    if (!key || !label || !context || !output) {
        return FALSE;
    }
    if (2 + label_len + context_len + 2 > MAX_R_LEN ||
        iterations * hash_len > MAX_TMP_LEN) {
        DEBUG_PRINT_LINE("Invalid input sizes", DEBUG_LEVEL_3);
        return FALSE;
    }

    /* Fill tmp with "i || Label || Context || Length" */
    offset += 2; /* Skip "i" (will be copied in for loop below) */
    memcpy(R + offset, label, label_len);
    offset += label_len;
    memcpy(R + offset, context, context_len);
    offset += context_len;
    memcpy(R + offset, &len_le, 2);
    offset += 2;

    for (i = 0; i < iterations; i++)
    {
        guint16 count_le = GUINT16_TO_LE(i + 1);
        memcpy(R, &count_le, 2);

        if (ws_hmac_buffer(hash_algo, tmp + hash_len * i, R, offset, key, key_len)) {
            return FALSE;
        }
    }
    memcpy(output, tmp, output_len);
    return TRUE;
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
