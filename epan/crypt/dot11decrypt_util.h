/** @file
 *
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
 */

#ifndef _DOT11DECRYPT_UTIL_H
#define _DOT11DECRYPT_UTIL_H

#include "dot11decrypt_int.h"

/**
 * @brief Constructs the AAD (Additional Authentication Data) for a 802.11 MAC frame.
 *
 * @param wh Pointer to the DOT11DECRYPT_MAC_FRAME structure containing the MAC header.
 * @param A1 Pointer to the first address field of the MAC frame.
 * @param A2 Pointer to the second address field of the MAC frame.
 * @param A3 Pointer to the third address field of the MAC frame.
 * @param aad Buffer to store the constructed AAD.
 * @param aad_len Pointer to store the length of the constructed AAD.
 */
void dot11decrypt_construct_aad(
    PDOT11DECRYPT_MAC_FRAME wh,
    const uint8_t *A1,
    const uint8_t *A2,
    const uint8_t *A3,
    uint8_t *aad,
    size_t *aad_len);

/**
 * @brief Extracts the AAD addresses for nonce calculation.
 *
 * Reference: IEEE 802.11-2024 12.5.4.3.3 Construct AAD,
 * IEEE 802.11be-2024 12.5.2.3.3 Construct AAD, 12.5.2.3.4 Construct CCM nonce,
 * 12.5.4.3.4 Construct GCM nonce.
 *
 * @param wh Pointer to the MAC frame structure.
 * @param ap_mld_mac Pointer to the Access Point's Multi-Link MAC address.
 * @param sta_mld_mac Pointer to the Station's Multi-Link MAC address.
 * @param A1 Pointer to store the first address component.
 * @param A2 Pointer to store the second address component.
 * @param A3 Pointer to store the third address component.
 */
static inline void dot11decrypt_get_nonce_aad_addrs(
    PDOT11DECRYPT_MAC_FRAME wh,
    const uint8_t *ap_mld_mac,
    const uint8_t *sta_mld_mac,
    const uint8_t **A1,
    const uint8_t **A2,
    const uint8_t **A3
)
{
    *A1 = wh->addr1;
    *A2 = wh->addr2;
    *A3 = wh->addr3;

    if (ap_mld_mac && !(wh->addr1[0] & 1) &&
        DOT11DECRYPT_TYPE(wh->fc[0]) == DOT11DECRYPT_TYPE_DATA) {
        uint8_t ds = wh->fc[1] & DOT11DECRYPT_FC1_DIR_MASK;
        if (ds == IEEE80211_FC1_DIR_TODS) {
            *A1 = ap_mld_mac;
            *A2 = sta_mld_mac;
        } else if (ds == IEEE80211_FC1_DIR_FROMDS) {
            *A1 = sta_mld_mac;
            *A2 = ap_mld_mac;
        }
        // TODO 4 addr support

        if (DOT11DECRYPT_IS_QOS_DATA(wh)) {
            PDOT11DECRYPT_MAC_FRAME_QOS qwh = (PDOT11DECRYPT_MAC_FRAME_QOS)wh;
            // The MPDU is an A-MSDU.
            // A3 is BSSID and shall be set to MLD MAC of the AP MLD when building AAD.
            if (qwh->qos[0] & 0x80)
                *A3 = ap_mld_mac;
        }
    }
}

bool
dot11decrypt_prf(const uint8_t *key, size_t key_len,
                 const char *label,
                 const uint8_t *context, size_t context_len,
                 int hash_algo,
                 uint8_t *output, size_t output_len);

/**
 * @brief Perform a KDF (Key Derivation Function) using the specified parameters.
 *
 * Reference: IEEE 802.11-2016
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
                 uint8_t *output, size_t output_len);

/**
 * @brief Derive PMK-R0 using the provided parameters
 *
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
                           uint8_t pmk_r0_name[16]);

/**
 * @brief Derive PMK-R1 from PMK-R0 using a key derivation function.
 *
 * Derive PMK-R1 and PMKR1Name. See IEEE 802.11-2016 12.7.1.7.4 PMK-R1
 *
 * @param pmk_r0 Pointer to the PMK-R0 buffer.
 * @param pmk_r0_len Length of the PMK-R0 buffer.
 * @param pmk_r0_name Name associated with PMK-R0.
 * @param r1kh_id R1KH ID for the key derivation.
 * @param s1kh_id S1KH ID for the key derivation.
 * @param hash_algo Hash algorithm to use for the key derivation.
 * @param pmk_r1 Pointer to the buffer where the derived PMK-R1 will be stored.
 * @param pmk_r1_len Pointer to the length of the PMK-R1 buffer, which will be updated with the actual length of the derived PMK-R1.
 * @param pmk_r1_name Pointer to the buffer where the name for the derived PMK-R1 will be stored.
 * @return true if the derivation was successful, false otherwise.
 */
bool
dot11decrypt_derive_pmk_r1(const uint8_t *pmk_r0, size_t pmk_r0_len,
                           const uint8_t *pmk_r0_name,
                           const uint8_t *r1kh_id, const uint8_t *s1kh_id,
                           int hash_algo,
                           uint8_t *pmk_r1, size_t *pmk_r1_len,
                           uint8_t *pmk_r1_name);

/**
 * @brief Derive the FT PTK using the provided parameters.
 *
 * Derive PTK for FT AKMS. See IEE 802.11-2016 12.7.1.7.5 PTK
 *
 * PTK = KDF-Hash-Length(PMK-R1, "FT-PTK", SNonce || ANonce || BSSID || STA-ADDR)
 * PTKName = Truncate-128(
 *         SHA-256(PMKR1Name || "FT-PTKN" || SNonce || ANonce || BSSID || STA-ADDR))
 *
 * @param pmk_r1 Pointer to the PMK_R1 value.
 * @param pmk_r1_len Length of the PMK_R1 value.
 * @param pmk_r1_name Name associated with the PMK_R1.
 * @param snonce Session nonce.
 * @param anonce Authenticator nonce.
 * @param bssid Base station address.
 * @param sta_addr Station address.
 * @param hash_algo Hash algorithm to use.
 * @param ptk Pointer to store the derived PTK.
 * @param ptk_len Length of the PTK buffer.
 * @param ptk_name Name associated with the PTK.
 * @return void
 */
bool
dot11decrypt_derive_ft_ptk(const uint8_t *pmk_r1, size_t pmk_r1_len,
                           const uint8_t *pmk_r1_name,
                           const uint8_t *snonce, const uint8_t *anonce,
                           const uint8_t *bssid, const uint8_t *sta_addr,
                           int hash_algo,
                           uint8_t *ptk, const size_t ptk_len, uint8_t *ptk_name);
#endif /* _DOT11DECRYPT_UTIL_H */

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
