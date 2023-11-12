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

#include "dot11decrypt_debug.h"
#include "dot11decrypt_int.h"
#include "dot11decrypt_util.h"

/****************************************************************************/
/*    Internal definitions                                                  */

#define FC0_AAD_MASK 0x8f
#define FC1_AAD_MASK 0xc7
#define FC1_AAD_QOS_MASK 0x47

/****************************************************************************/
/* Internal macros                                                          */

/****************************************************************************/
/* Internal function prototypes declarations                                */

/****************************************************************************/
/* Function definitions                                                     */

/* From IEEE 802.11 2016 Chapter 12.5.3.3.3 and 12.5.5.3.3 Construct AAD */
void dot11decrypt_construct_aad(
    PDOT11DECRYPT_MAC_FRAME wh,
    uint8_t *aad,
    size_t *aad_len)
{
    uint8_t mgmt = (DOT11DECRYPT_TYPE(wh->fc[0]) == DOT11DECRYPT_TYPE_MANAGEMENT);
    int alen = 22;

    /* AAD:
    * FC with bits 4..6 and 11..13 masked to zero; 14 is always one; 15 zero when QoS Control field present
    * A1 | A2 | A3
    * SC with bits 4..15 (seq#) masked to zero
    * A4 (if present)
    * QC (if present)
    */

    /* NB: aad[1] set below */
    if (!mgmt) {
        aad[0] = (uint8_t)(wh->fc[0] & FC0_AAD_MASK);
    } else {
        aad[0] = wh->fc[0];
    }
    if (DOT11DECRYPT_IS_QOS_DATA(wh)) {
        aad[1] = (uint8_t)((wh->fc[1] & FC1_AAD_QOS_MASK) | 0x40);
    } else {
        aad[1] = (uint8_t)((wh->fc[1] & FC1_AAD_MASK) | 0x40);
    }
    memcpy(aad + 2, (uint8_t *)wh->addr1, DOT11DECRYPT_MAC_LEN);
    memcpy(aad + 8, (uint8_t *)wh->addr2, DOT11DECRYPT_MAC_LEN);
    memcpy(aad + 14, (uint8_t *)wh->addr3, DOT11DECRYPT_MAC_LEN);
    aad[20] = (uint8_t)(wh->seq[0] & DOT11DECRYPT_SEQ_FRAG_MASK);
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
            aad[28] = (uint8_t)(qwh4->qos[0] & 0x0f);/* just priority bits */
            aad[29] = 0;
            alen += 2;
        }
    } else {
        if (DOT11DECRYPT_IS_QOS_DATA(wh)) {
            PDOT11DECRYPT_MAC_FRAME_QOS qwh =
                (PDOT11DECRYPT_MAC_FRAME_QOS) wh;
            aad[22] = (uint8_t)(qwh->qos[0] & 0x0f); /* just priority bits */
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
 * @return false on error
 */
#define MAX_R_LEN 256
#define MAX_TMP_LEN 1024
#define MAX_CONTEXT_LEN 256

bool
dot11decrypt_prf(const uint8_t *key, size_t key_len,
                 const char *label,
                 const uint8_t *context, size_t context_len,
                 int hash_algo,
                 uint8_t *output, size_t output_len)
{
    uint8_t R[MAX_R_LEN]; /* Will hold "label || 0 || context || i" */
    size_t label_len = strlen(label);
    uint8_t tmp[MAX_TMP_LEN];
    uint16_t hash_len = gcry_md_get_algo_dlen(hash_algo);
    size_t offset = 0;
    uint8_t i;

    if (!key || !label || !context || !output) {
        return false;
    }
    if (label_len + 1 + context_len + 1 > MAX_R_LEN ||
        output_len > 64) {
        ws_warning("Invalid input or output sizes");
        return false;
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
            return false;
        }
    }
    memcpy(output, tmp, output_len);
    return true;
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
 * @return false on error
 */
bool
dot11decrypt_kdf(const uint8_t *key, size_t key_len,
                 const char *label,
                 const uint8_t *context, size_t context_len,
                 int hash_algo,
                 uint8_t *output, size_t output_len)
{
    uint8_t R[MAX_R_LEN]; /* Will hold "i || Label || Context || Length" */
    uint8_t tmp[MAX_TMP_LEN];
    size_t label_len = strlen(label);
    uint16_t hash_len = gcry_md_get_algo_dlen(hash_algo);
    unsigned iterations = (unsigned)output_len * 8 / hash_len;
    uint16_t len_le = GUINT16_TO_LE(output_len * 8);
    size_t offset = 0;
    uint16_t i;

    if (!key || !label || !context || !output) {
        return false;
    }
    if (2 + label_len + context_len + 2 > MAX_R_LEN ||
        iterations * hash_len > MAX_TMP_LEN) {
        ws_warning("Invalid input sizes");
        return false;
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
        uint16_t count_le = GUINT16_TO_LE(i + 1);
        memcpy(R, &count_le, 2);

        if (ws_hmac_buffer(hash_algo, tmp + hash_len * i, R, offset, key, key_len)) {
            return false;
        }
    }
    memcpy(output, tmp, output_len);
    return true;
}

static bool sha256(const uint8_t *data, size_t len, uint8_t output[32])
{
    gcry_md_hd_t ctx;
    gcry_error_t result = gcry_md_open(&ctx, GCRY_MD_SHA256, 0);
    uint8_t *digest;

    if (result) {
        return false;
    }
    gcry_md_write(ctx, data, len);
    digest = gcry_md_read(ctx, GCRY_MD_SHA256);
    if (!digest) {
        return false;
    }
    memcpy(output, digest, 32);
    gcry_md_close(ctx);
    return true;
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
 * @param r0kh_id_len Length of r0kh_id in bytes.
 * @param s0kh_id PMK-R0 key holder in the Supplicant (STA mac address)
 * @param hash_algo Hash algorithm to use for the KDF.
 *        See gcrypt available hash algorithms:
 *        https://gnupg.org/documentation/manuals/gcrypt/Available-hash-algorithms.html
 * @param[out] pmk_r0 Pairwise master key, first level
 * @param pmk_r0_len Length of pmk_r0 in bytes.
 * @param[out] pmk_r0_name Pairwise master key (PMK) R0 name.
 */
bool
dot11decrypt_derive_pmk_r0(const uint8_t *xxkey, size_t xxkey_len,
                           const uint8_t *ssid, size_t ssid_len,
                           const uint8_t mdid[2],
                           const uint8_t *r0kh_id, size_t r0kh_id_len,
                           const uint8_t s0kh_id[DOT11DECRYPT_MAC_LEN],
                           int hash_algo,
                           uint8_t *pmk_r0,
                           size_t *pmk_r0_len,
                           uint8_t pmk_r0_name[16])
{
    const char *ft_r0n = "FT-R0N";
    const size_t ft_r0n_len = strlen(ft_r0n);
    uint8_t context[MAX_CONTEXT_LEN];
    uint8_t r0_key_data[DOT11DECRYPT_WPA_PMK_MAX_LEN + 16];
    uint8_t sha256_res[32];
    size_t offset = 0;
    unsigned q = gcry_md_get_algo_dlen(hash_algo);
    uint16_t mdid_le = GUINT16_TO_LE(*(uint16_t*)mdid);

    if (!xxkey || !ssid || !mdid || !r0kh_id || !s0kh_id ||
        !pmk_r0 || !pmk_r0_len || !pmk_r0_name)
    {
        return false;
    }
    if (1 + ssid_len + 2 + 1 + r0kh_id_len + DOT11DECRYPT_MAC_LEN > MAX_CONTEXT_LEN)
    {
        ws_warning("Invalid input sizes");
        return false;
    }

    // R0-Key-Data =
    //   KDF-Hash-Length(XXKey, "FT-R0",
    //           SSIDlength || SSID || MDID || R0KHlength || R0KH-ID || S0KH-ID)
    // PMK-R0 = L(R0-Key-Data, 0, Q) * PMK-R0Name-Salt = L(R0-Key-Data, Q, 128)
    context[offset++] = (uint8_t)ssid_len;
    memcpy(context + offset, ssid, ssid_len);
    offset += ssid_len;
    memcpy(context + offset, &mdid_le, 2);
    offset += 2;
    context[offset++] = (uint8_t)r0kh_id_len;
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
        return false;
    memcpy(pmk_r0_name, sha256_res, 16);
    return true;
}

/**
 * Derive PMK-R1 and PMKR1Name. See IEEE 802.11-2016 12.7.1.7.4 PMK-R1
 *
 */
bool
dot11decrypt_derive_pmk_r1(const uint8_t *pmk_r0, size_t pmk_r0_len,
                           const uint8_t *pmk_r0_name,
                           const uint8_t *r1kh_id, const uint8_t *s1kh_id,
                           int hash_algo,
                           uint8_t *pmk_r1, size_t *pmk_r1_len,
                           uint8_t *pmk_r1_name)
{
    const char *ft_r1n = "FT-R1N";
    const size_t ft_r1n_len = strlen(ft_r1n);
    // context len = MAX(R1KH-ID || S1KH-ID, "FT-R1N" || PMKR0Name || R1KH-ID || S1KH-ID)
    uint8_t context[6 + 16 + 6 + 6];
    uint8_t sha256_res[32];
    size_t offset = 0;

    if (!pmk_r0 || !pmk_r0_name || !r1kh_id || !s1kh_id ||
        !pmk_r1 || !pmk_r1_len || !pmk_r1_name)
    {
        return false;
    }
    *pmk_r1_len = gcry_md_get_algo_dlen(hash_algo);

    // PMK-R1 = KDF-Hash-Length(PMK-R0, "FT-R1", R1KH-ID || S1KH-ID)
    memcpy(context + offset, r1kh_id, DOT11DECRYPT_MAC_LEN);
    offset += DOT11DECRYPT_MAC_LEN;
    memcpy(context + offset, s1kh_id, DOT11DECRYPT_MAC_LEN);
    offset += DOT11DECRYPT_MAC_LEN;
    dot11decrypt_kdf(pmk_r0, pmk_r0_len, "FT-R1", context, offset, hash_algo,
                     pmk_r1, *pmk_r1_len);

    // PMKR1Name = Truncate-128(SHA-256("FT-R1N" || PMKR0Name || R1KH-ID || S1KH-ID))
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
        return false;
    memcpy(pmk_r1_name, sha256_res, 16);
    return true;
}

/**
 * Derive PTK for FT AKMS. See IEE 802.11-2016 12.7.1.7.5 PTK
 *
 * PTK = KDF-Hash-Length(PMK-R1, "FT-PTK", SNonce || ANonce || BSSID || STA-ADDR)
 * PTKName = Truncate-128(
 *         SHA-256(PMKR1Name || "FT-PTKN" || SNonce || ANonce || BSSID || STA-ADDR))
 */
bool
dot11decrypt_derive_ft_ptk(const uint8_t *pmk_r1, size_t pmk_r1_len,
                           const uint8_t *pmk_r1_name _U_,
                           const uint8_t *snonce, const uint8_t *anonce,
                           const uint8_t *bssid, const uint8_t *sta_addr,
                           int hash_algo,
                           uint8_t *ptk, const size_t ptk_len, uint8_t *ptk_name _U_)
{
    uint8_t context[32 + 32 + 6 + 6];
    unsigned offset = 0;

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
    return true;
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
