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

static gboolean sha256(const guint8 *data, size_t len, guint8 output[32])
{
    gcry_md_hd_t ctx;
    gcry_error_t result = gcry_md_open(&ctx, GCRY_MD_SHA256, 0);
    guint8 *digest;

    if (result) {
        return FALSE;
    }
    gcry_md_write(ctx, data, len);
    digest = gcry_md_read(ctx, GCRY_MD_SHA256);
    if (!digest) {
        return FALSE;
    }
    memcpy(output, digest, 32);
    gcry_md_close(ctx);
    return TRUE;
}

/**
 * Derive PMK-R0 and PMKR0Name. See IEEE 802.11-2016 12.7.1.7.3 PMK-R0
 *
 * @param xxkey PSK / MPMK or certain part of MSK.
 * @param xxkey_len Length of xxkey in bytes.
 * @param ssid SSID
 * @param ssid_len Length of SSID in bytes.
 * @param mdid MDID (Mobility Domain Identifier).
 * @param r0kh_id PMK-R0 key holder identifier in the Authenticator.
 * @param r0kh_id_len Lenth of r0kh_id in bytes.
 * @param s0kh_id PMK-R0 key holder in the Supplicant (STA mac address)
 * @param s0kd_id_len Length of s0kh_id in bytes.
 * @param hash_algo Hash algorithm to use for the KDF.
 *        See gcrypt available hash algorithms:
 *        https://gnupg.org/documentation/manuals/gcrypt/Available-hash-algorithms.html
 * @param[out] pmk_r0 Pairwise master key, first level
 * @param[out] pmk_r0_name Pairwise master key (PMK) R0 name.
 */
gboolean
dot11decrypt_derive_pmk_r0(const guint8 *xxkey, size_t xxkey_len,
                           const guint8 *ssid, size_t ssid_len,
                           const guint8 mdid[2],
                           const guint8 *r0kh_id, size_t r0kh_id_len,
                           const guint8 s0kh_id[DOT11DECRYPT_MAC_LEN],
                           int hash_algo,
                           guint8 *pmk_r0,
                           size_t *pmk_r0_len,
                           guint8 pmk_r0_name[16])
{
    const char *ft_r0n = "FT-R0N";
    const size_t ft_r0n_len = strlen(ft_r0n);
    guint8 context[MAX_CONTEXT_LEN];
    guint8 r0_key_data[DOT11DECRYPT_WPA_PMK_MAX_LEN + 16];
    guint8 sha256_res[32];
    size_t offset = 0;
    guint q = gcry_md_get_algo_dlen(hash_algo);
    guint16 mdid_le = GUINT16_TO_LE(*(guint16*)mdid);

    if (!xxkey || !ssid || !mdid || !r0kh_id || !s0kh_id ||
        !pmk_r0 || !pmk_r0_len || !pmk_r0_name)
    {
        return FALSE;
    }
    if (1 + ssid_len + 2 + 1 + r0kh_id_len + DOT11DECRYPT_MAC_LEN > MAX_CONTEXT_LEN)
    {
        DEBUG_PRINT_LINE("Invalid input sizes", DEBUG_LEVEL_3);
        return FALSE;
    }

    // R0-Key-Data =
    //   KDF-Hash-Length(XXKey, "FT-R0",
    //           SSIDlength || SSID || MDID || R0KHlength || R0KH-ID || S0KH-ID)
    // PMK-R0 = L(R0-Key-Data, 0, Q) * PMK-R0Name-Salt = L(R0-Key-Data, Q, 128)
    context[offset++] = (guint8)ssid_len;
    memcpy(context + offset, ssid, ssid_len);
    offset += ssid_len;
    memcpy(context + offset, &mdid_le, 2);
    offset += 2;
    context[offset++] = (guint8)r0kh_id_len;
    memcpy(context + offset, r0kh_id, r0kh_id_len);
    offset += r0kh_id_len;
    memcpy(context + offset, s0kh_id, DOT11DECRYPT_MAC_LEN);
    offset += DOT11DECRYPT_MAC_LEN;
    dot11decrypt_kdf(xxkey, xxkey_len, "FT-R0", context, offset, hash_algo,
                     r0_key_data, q + 16);
    memcpy(pmk_r0, r0_key_data, q);
    *pmk_r0_len = q;

    // PMK-R0Name-Salt = L(R0-Key-Data, Q, 128)
    // PMKR0Name = Truncate-128(SHA-256("FT-R0N" || PMK-R0Name-Salt))
    offset = 0;
    memcpy(context + offset, ft_r0n, ft_r0n_len);
    offset += ft_r0n_len;
    memcpy(context + offset, r0_key_data + q, 16);
    offset += 16;
    if(!sha256(context, offset, sha256_res))
        return FALSE;
    memcpy(pmk_r0_name, sha256_res, 16);
    return TRUE;
}

/**
 * Derive PMK-R1 and PMKR1Name. See IEEE 802.11-2016 12.7.1.7.4 PMK-R1
 *
 */
gboolean
dot11decrypt_derive_pmk_r1(const guint8 *pmk_r0, size_t pmk_r0_len,
                           const guint8 *pmk_r0_name,
                           const guint8 *r1kh_id, const guint8 *s1kh_id,
                           int hash_algo,
                           guint8 *pmk_r1, size_t *pmk_r1_len,
                           guint8 *pmk_r1_name)
{
    const char *ft_r1n = "FT-R1N";
    const size_t ft_r1n_len = strlen(ft_r1n);
    // context len = MAX(R1KH-ID || S1KH-ID, “FT-R1N” || PMKR0Name || R1KH-ID || S1KH-ID)
    guint8 context[6 + 16 + 6 + 6];
    guint8 sha256_res[32];
    size_t offset = 0;

    if (!pmk_r0 || !pmk_r0_name || !r1kh_id || !s1kh_id ||
        !pmk_r1 || !pmk_r1_len || !pmk_r1_name)
    {
        return FALSE;
    }
    *pmk_r1_len = gcry_md_get_algo_dlen(hash_algo);

    // PMK-R1 = KDF-Hash-Length(PMK-R0, "FT-R1", R1KH-ID || S1KH-ID)
    memcpy(context + offset, r1kh_id, DOT11DECRYPT_MAC_LEN);
    offset += DOT11DECRYPT_MAC_LEN;
    memcpy(context + offset, s1kh_id, DOT11DECRYPT_MAC_LEN);
    offset += DOT11DECRYPT_MAC_LEN;
    dot11decrypt_kdf(pmk_r0, pmk_r0_len, "FT-R1", context, offset, hash_algo,
                     pmk_r1, *pmk_r1_len);

    // PMKR1Name = Truncate-128(SHA-256(“FT-R1N” || PMKR0Name || R1KH-ID || S1KH-ID))
    offset = 0;
    memcpy(context + offset, ft_r1n, ft_r1n_len);
    offset += ft_r1n_len;
    memcpy(context + offset, pmk_r0_name, 16);
    offset += 16;
    memcpy(context + offset, r1kh_id, DOT11DECRYPT_MAC_LEN);
    offset += DOT11DECRYPT_MAC_LEN;
    memcpy(context + offset, s1kh_id, DOT11DECRYPT_MAC_LEN);
    offset += DOT11DECRYPT_MAC_LEN;
    if(!sha256(context, offset, sha256_res))
        return FALSE;
    memcpy(pmk_r1_name, sha256_res, 16);
    return TRUE;
}

/**
 * Derive PTK for FT AKMS. See IEE 802.11-2016 12.7.1.7.5 PTK
 *
 * PTK = KDF-Hash-Length(PMK-R1, "FT-PTK", SNonce || ANonce || BSSID || STA-ADDR)
 * PTKName = Truncate-128(
 *         SHA-256(PMKR1Name || “FT-PTKN” || SNonce || ANonce || BSSID || STA-ADDR))
 */
gboolean
dot11decrypt_derive_ft_ptk(const guint8 *pmk_r1, size_t pmk_r1_len,
                           const guint8 *pmk_r1_name _U_,
                           const guint8 *snonce, const guint8 *anonce,
                           const guint8 *bssid, const guint8 *sta_addr,
                           int hash_algo,
                           guint8 *ptk, const size_t ptk_len, guint8 *ptk_name _U_)
{
    guint8 context[32 + 32 + 6 + 6];
    guint offset = 0;

    // PTK = KDF-Hash-Length(PMK-R1, "FT-PTK", SNonce || ANonce || BSSID || STA-ADDR)
    memcpy(context + offset, snonce, 32);
    offset += 32;
    memcpy(context + offset, anonce, 32);
    offset += 32;
    memcpy(context + offset, bssid, DOT11DECRYPT_MAC_LEN);
    offset += DOT11DECRYPT_MAC_LEN;
    memcpy(context + offset, sta_addr, DOT11DECRYPT_MAC_LEN);
    offset += DOT11DECRYPT_MAC_LEN;
    dot11decrypt_kdf(pmk_r1, pmk_r1_len, "FT-PTK", context, offset, hash_algo,
                     ptk, ptk_len);

    // TODO derive PTKName
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
