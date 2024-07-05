/* dot11decrypt.c
 *
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
 */

/****************************************************************************/
/*      File includes                                                       */

#include "config.h"
/* Keep this first after config.h so that WS_LOG_DOMAIN is set correctly. */
#include "dot11decrypt_debug.h"

#include <stdint.h>
#include <glib.h>

#include <wsutil/wsgcrypt.h>
#include <wsutil/crc32.h>
#include <wsutil/pint.h>

#include <epan/proto.h> /* for DISSECTOR_ASSERT. */
#include <epan/tvbuff.h>
#include <epan/to_str.h>
#include <epan/strutil.h>

#include "dot11decrypt_util.h"
#include "dot11decrypt_system.h"
#include "dot11decrypt_int.h"

#include "wep-wpadefs.h"


/****************************************************************************/
static int Dot11DecryptGetKckLen(int akm);
static int Dot11DecryptGetTkLen(int cipher);
static int Dot11DecryptGetKekLen(int akm);
static int Dot11DecryptGetPtkLen(int akm, int cipher);
static int Dot11DecryptGetHashAlgoFromAkm(int akm);

/****************************************************************************/
/*      Constant definitions                                                    */

/*      EAPOL definitions                                                       */
/**
 * Length of the EAPOL-Key key confirmation key (KCK) used to calculate
 * MIC over EAPOL frame and validate an EAPOL packet (128 bits)
 */
#define DOT11DECRYPT_WPA_KCK_LEN    16
/**
 *Offset of the Key MIC in the EAPOL packet body
 */
#define DOT11DECRYPT_WPA_MICKEY_OFFSET      77
/**
 * Maximum length of the EAPOL packet (it depends on the maximum MAC
 * frame size)
 */
#define DOT11DECRYPT_WPA_MAX_EAPOL_LEN      4095
/**
 * EAPOL Key Descriptor Version 1, used for all EAPOL-Key frames to and
 * from a STA when neither the group nor pairwise ciphers are CCMP for
 * Key Descriptor 1.
 * @note
 * Defined in 802.11i-2004, page 78
 */
#define DOT11DECRYPT_WPA_KEY_VER_NOT_CCMP   1
/**
 * EAPOL Key Descriptor Version 2, used for all EAPOL-Key frames to and
 * from a STA when either the pairwise or the group cipher is AES-CCMP
 * for Key Descriptor 2.
 * /note
 * Defined in 802.11i-2004, page 78
 */
#define DOT11DECRYPT_WPA_KEY_VER_AES_CCMP   2

/** Define EAPOL Key Descriptor type values:  use 254 for WPA and 2 for WPA2 **/
#define DOT11DECRYPT_RSN_WPA_KEY_DESCRIPTOR 254
#define DOT11DECRYPT_RSN_WPA2_KEY_DESCRIPTOR 2

/* PMK to PTK derive functions */
#define DOT11DECRYPT_DERIVE_USING_PRF 0
#define DOT11DECRYPT_DERIVE_USING_KDF 1
/****************************************************************************/


/****************************************************************************/
/*      Macro definitions                                                       */

extern const uint32_t crc32_table[256];
#define CRC(crc, ch)     (crc = (crc >> 8) ^ crc32_table[(crc ^ (ch)) & 0xff])

#define KCK_OFFSET(akm) (0)
#define KEK_OFFSET(akm) ((KCK_OFFSET(akm) + Dot11DecryptGetKckLen(akm) / 8))
#define TK_OFFSET(akm)  ((KEK_OFFSET(akm) + Dot11DecryptGetKekLen(akm) / 8))

#define DOT11DECRYPT_GET_KCK(ptk, akm)   (ptk + KCK_OFFSET(akm))
#define DOT11DECRYPT_GET_KEK(ptk, akm)   (ptk + KEK_OFFSET(akm))
#define DOT11DECRYPT_GET_TK_TKIP(ptk)    (ptk + 32)
#define DOT11DECRYPT_GET_TK(ptk, akm)    (ptk + TK_OFFSET(akm))

#define DOT11DECRYPT_IEEE80211_OUI(oui) (pntoh24(oui) == 0x000fac)

/****************************************************************************/

/****************************************************************************/
/*      Type definitions                                                        */

/*      Internal function prototype declarations                                */

#ifdef  __cplusplus
extern "C" {
#endif

/**
 * It is a step of the PBKDF2 (specifically the PKCS #5 v2.0) defined in
 * the RFC 2898 to derive a key (used as PMK in WPA)
 * @param ppbytes [IN] pointer to a password (sequence of between 8 and
 * 63 ASCII encoded characters)
 * @param ssid [IN] pointer to the SSID string encoded in max 32 ASCII
 * encoded characters
 * @param iterations [IN] times to hash the password (4096 for WPA)
 * @param count [IN] ???
 * @param output [OUT] pointer to a preallocated buffer of
 * SHA1_DIGEST_LEN characters that will contain a part of the key
 */
static int Dot11DecryptRsnaPwd2PskStep(
    const uint8_t *ppbytes,
    const unsigned passLength,
    const char *ssid,
    const size_t ssidLength,
    const int iterations,
    const int count,
    unsigned char *output)
    ;

/**
 * It calculates the passphrase-to-PSK mapping reccomanded for use with
 * RSNAs. This implementation uses the PBKDF2 method defined in the RFC
 * 2898.
 * @param userPwd [IN] pointer to the struct containing a password
 * (octet string between 8 and 63 octets) and optional SSID octet
 * string of up to 32 octets (both are usually ASCII but in fact
 * opaque and can be any encoding.)
 * @param output [OUT] calculated PSK (to use as PMK in WPA)
 * @note
 * Described in 802.11i-2004, page 165
 */
static int Dot11DecryptRsnaPwd2Psk(
    const struct DOT11DECRYPT_KEY_ITEMDATA_PWD *userPwd,
    unsigned char *output)
    ;

static int Dot11DecryptRsnaMng(
    unsigned char *decrypt_data,
    unsigned mac_header_len,
    unsigned *decrypt_len,
    PDOT11DECRYPT_KEY_ITEM key,
    DOT11DECRYPT_SEC_ASSOCIATION *sa)
    ;

static int Dot11DecryptWepMng(
    PDOT11DECRYPT_CONTEXT ctx,
    unsigned char *decrypt_data,
    unsigned mac_header_len,
    unsigned *decrypt_len,
    PDOT11DECRYPT_KEY_ITEM key,
    DOT11DECRYPT_SEC_ASSOCIATION_ID *id)
    ;

static int Dot11DecryptRsna4WHandshake(
    PDOT11DECRYPT_CONTEXT ctx,
    PDOT11DECRYPT_EAPOL_PARSED eapol_parsed,
    const uint8_t *eapol_raw,
    DOT11DECRYPT_SEC_ASSOCIATION_ID *id,
    const unsigned tot_len);

/**
 * It checks whether the specified key is corrected or not.
 * @note
 * For a standard WEP key the length will be changed to the standard
 * length, and the type changed in a generic WEP key.
 * @param key [IN] pointer to the key to validate
 * @return
 * - true: the key contains valid fields and values
 * - false: the key has some invalid field or value
 */
static int Dot11DecryptValidateKey(
    PDOT11DECRYPT_KEY_ITEM key)
    ;

static int Dot11DecryptRsnaMicCheck(
    PDOT11DECRYPT_EAPOL_PARSED eapol_parsed,
    unsigned char *eapol,
    unsigned short eapol_len,
    unsigned char *KCK,
    unsigned short key_ver,
    int akm)
    ;

static int
Dot11DecryptFtMicCheck(
    const PDOT11DECRYPT_ASSOC_PARSED assoc_parsed,
    const uint8_t *kck,
    size_t kck_len);

static PDOT11DECRYPT_SEC_ASSOCIATION
Dot11DecryptGetSa(
    PDOT11DECRYPT_CONTEXT ctx,
    const DOT11DECRYPT_SEC_ASSOCIATION_ID *id)
    ;

static int Dot11DecryptGetSaAddress(
    const DOT11DECRYPT_MAC_FRAME_ADDR4 *frame,
    DOT11DECRYPT_SEC_ASSOCIATION_ID *id)
    ;

static const unsigned char * Dot11DecryptGetStaAddress(
    const DOT11DECRYPT_MAC_FRAME_ADDR4 *frame)
    ;

static const unsigned char * Dot11DecryptGetBssidAddress(
    const DOT11DECRYPT_MAC_FRAME_ADDR4 *frame)
    ;

static uint8_t
Dot11DecryptDerivePtk(
    const DOT11DECRYPT_SEC_ASSOCIATION *sa,
    const unsigned char *pmk,
    size_t pmk_len,
    const unsigned char snonce[32],
    int key_version,
    int akm,
    int cipher,
    uint8_t *ptk, size_t *ptk_len);

static uint8_t
Dot11DecryptFtDerivePtk(
    const PDOT11DECRYPT_CONTEXT ctx,
    const DOT11DECRYPT_SEC_ASSOCIATION *sa,
    const PDOT11DECRYPT_KEY_ITEM key,
    const uint8_t mdid[2],
    const uint8_t *snonce,
    const uint8_t *r0kh_id, size_t r0kh_id_len,
    const uint8_t *r1kh_id, size_t r1kh_id_len _U_,
    int akm, int cipher,
    uint8_t *ptk, size_t *ptk_len);

/**
 * @param sa  [IN/OUT] pointer to SA that will hold the key
 * @param data [IN] Frame
 * @param offset_rsne [IN] RSNE IE offset in the frame
 * @param offset_fte [IN] Fast BSS Transition IE offset in the frame
 * @param offset_timeout [IN] Timeout Interval IE offset in the frame
 * @param offset_link [IN] Link Identifier IE offset in the frame
 * @param action [IN] Tdls Action code (response or confirm)
 *
 * @return
 *  DOT11DECRYPT_RET_SUCCESS if Key has been successfully derived (and MIC verified)
 *  DOT11DECRYPT_RET_UNSUCCESS otherwise
 */
static int
Dot11DecryptTDLSDeriveKey(
    PDOT11DECRYPT_SEC_ASSOCIATION sa,
    const uint8_t *data,
    unsigned offset_rsne,
    unsigned offset_fte,
    unsigned offset_timeout,
    unsigned offset_link,
    uint8_t action)
    ;
#ifdef  __cplusplus
}
#endif

/****************************************************************************/

/****************************************************************************/
/* Exported function definitions                                                */

#ifdef  __cplusplus
extern "C" {
#endif

const uint8_t broadcast_mac[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

#define TKIP_GROUP_KEY_LEN 32
#define CCMP_GROUP_KEY_LEN 16

#define EAPOL_RSN_KEY_LEN 95

/* Minimum possible key data size (at least one GTK KDE with CCMP key) */
#define GROUP_KEY_MIN_LEN 8 + CCMP_GROUP_KEY_LEN
/* Minimum possible group key msg size (group key msg using CCMP as cipher)*/
#define GROUP_KEY_PAYLOAD_LEN_MIN \
    (EAPOL_RSN_KEY_LEN + GROUP_KEY_MIN_LEN)

static void
Dot11DecryptCopyKey(PDOT11DECRYPT_SEC_ASSOCIATION sa, PDOT11DECRYPT_KEY_ITEM key)
{
    if (key!=NULL) {
        if (sa->key!=NULL)
            memcpy(key, sa->key, sizeof(DOT11DECRYPT_KEY_ITEM));
        else
            memset(key, 0, sizeof(DOT11DECRYPT_KEY_ITEM));
        key->KeyData.Wpa.PtkLen = sa->wpa.ptk_len;
        memcpy(key->KeyData.Wpa.Ptk, sa->wpa.ptk, sa->wpa.ptk_len);
        key->KeyData.Wpa.Akm = sa->wpa.akm;
        key->KeyData.Wpa.Cipher = sa->wpa.cipher;
        if (sa->wpa.key_ver==DOT11DECRYPT_WPA_KEY_VER_NOT_CCMP)
            key->KeyType=DOT11DECRYPT_KEY_TYPE_TKIP;
        else if (sa->wpa.key_ver == 0 || sa->wpa.key_ver == 3 ||
                 sa->wpa.key_ver == DOT11DECRYPT_WPA_KEY_VER_AES_CCMP)
        {
            switch (sa->wpa.cipher) {
                case 1:
                    key->KeyType = DOT11DECRYPT_KEY_TYPE_WEP_40;
                    break;
                case 2:
                    key->KeyType = DOT11DECRYPT_KEY_TYPE_TKIP;
                    break;
                case 4:
                    key->KeyType = DOT11DECRYPT_KEY_TYPE_CCMP;
                    break;
                case 5:
                    key->KeyType = DOT11DECRYPT_KEY_TYPE_WEP_104;
                    break;
                case 8:
                    key->KeyType = DOT11DECRYPT_KEY_TYPE_GCMP;
                    break;
                case 9:
                    key->KeyType = DOT11DECRYPT_KEY_TYPE_GCMP_256;
                    break;
                case 10:
                    key->KeyType = DOT11DECRYPT_KEY_TYPE_CCMP_256;
                    break;
                default:
                    key->KeyType = DOT11DECRYPT_KEY_TYPE_UNKNOWN;
                    break;
                /* NOT SUPPORTED YET
                case 3:  Reserved
                case 6:  BIP-CMAC-128
                case 7:  Group addressed traffic not allowed
                case 11: BIP-GMAC-128
                case 12: BIP-GMAC-256
                case 13: BIP-CMAC-256 */
            }
        }
    }
}

static uint8_t*
Dot11DecryptRc4KeyData(const uint8_t *decryption_key, unsigned decryption_key_len,
                       const uint8_t *encrypted_keydata, unsigned encrypted_keydata_len)
{
    gcry_cipher_hd_t  rc4_handle;
    uint8_t dummy[256] = { 0 };
    uint8_t *decrypted_key = NULL;

    if (gcry_cipher_open (&rc4_handle, GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, 0)) {
        return NULL;
    }
    if (gcry_cipher_setkey(rc4_handle, decryption_key, decryption_key_len)) {
        gcry_cipher_close(rc4_handle);
        return NULL;
    }
    decrypted_key = (uint8_t *)g_memdup2(encrypted_keydata, encrypted_keydata_len);
    if (!decrypted_key) {
        gcry_cipher_close(rc4_handle);
        return NULL;
    }

    /* Do dummy 256 iterations of the RC4 algorithm (per 802.11i, Draft 3.0, p. 97 line 6) */
    gcry_cipher_decrypt(rc4_handle, dummy, 256, NULL, 0);
    gcry_cipher_decrypt(rc4_handle, decrypted_key, encrypted_keydata_len, NULL, 0);
    gcry_cipher_close(rc4_handle);
    return decrypted_key;
}

static int
AES_unwrap(
    const uint8_t *kek,
    uint16_t kek_len,
    const uint8_t *cipher_text,
    uint16_t cipher_len,
    uint8_t *output,
    uint16_t *output_len)
{
    gcry_cipher_hd_t handle;

    if (kek == NULL || cipher_len < 16 || cipher_text == NULL) {
        return 1; /* "should not happen" */
    }
    if (gcry_cipher_open(&handle, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_AESWRAP, 0)) {
        return 1;
    }
    if (gcry_cipher_setkey(handle, kek, kek_len)) {
        gcry_cipher_close(handle);
        return 1;
    }
    if (gcry_cipher_decrypt(handle, output, cipher_len - 8, cipher_text, cipher_len)) {
        gcry_cipher_close(handle);
        return 1;
    }
    *output_len = cipher_len - 8;
    gcry_cipher_close(handle);
    return 0;
}

int
Dot11DecryptDecryptKeyData(PDOT11DECRYPT_CONTEXT ctx,
                           PDOT11DECRYPT_EAPOL_PARSED eapol_parsed,
                           const unsigned char bssid[DOT11DECRYPT_MAC_LEN],
                           const unsigned char sta[DOT11DECRYPT_MAC_LEN],
                           unsigned char *decrypted_data, unsigned *decrypted_len,
                           PDOT11DECRYPT_KEY_ITEM key)
{
    uint8_t key_version;
    const uint8_t *key_data;
    uint16_t key_bytes_len = 0; /* Length of the total key data field */
    DOT11DECRYPT_SEC_ASSOCIATION_ID id;
    PDOT11DECRYPT_SEC_ASSOCIATION sa;

    /* search for a cached Security Association for current BSSID and AP */
    memcpy(id.bssid, bssid, DOT11DECRYPT_MAC_LEN);
    memcpy(id.sta, sta, DOT11DECRYPT_MAC_LEN);
    sa = Dot11DecryptGetSa(ctx, &id);
    if (sa == NULL || !sa->validKey) {
        ws_debug("No valid SA for BSSID found");
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    /* Decrypt GTK using KEK portion of PTK */
    uint8_t *decryption_key = DOT11DECRYPT_GET_KEK(sa->wpa.ptk, sa->wpa.akm);
    unsigned decryption_key_len = Dot11DecryptGetKekLen(sa->wpa.akm) / 8;

    /* We skip verifying the MIC of the key. If we were implementing a WPA supplicant we'd want to verify, but for a sniffer it's not needed. */

    /* Preparation for decrypting the group key -  determine group key data length */
    /* depending on whether the pairwise key is TKIP or AES encryption key */
    key_version = eapol_parsed->key_version;
    if (key_version == DOT11DECRYPT_WPA_KEY_VER_NOT_CCMP){
        /* TKIP */
        key_bytes_len = eapol_parsed->key_len;
    }else if (key_version == DOT11DECRYPT_WPA_KEY_VER_AES_CCMP){
        /* AES */
        key_bytes_len = eapol_parsed->key_data_len;

        /* AES keys must be at least 128 bits = 16 bytes. */
        if (key_bytes_len < 16) {
            return DOT11DECRYPT_RET_UNSUCCESS;
        }
    } else {
        /* XXX Ideally group cipher suite type from EAPOL message 2 of 4 should be used to  */
        /* determine key size. As we currently have no way to do this lookup check that key */
        /* is at least 16 bytes (IEEE802.11-2016 Table 12-4 Cipher suite key lengths)       */
        key_bytes_len = eapol_parsed->key_data_len;

        if (key_bytes_len < 16) {
            return DOT11DECRYPT_RET_UNSUCCESS;
        }
    }

    if ((key_bytes_len < GROUP_KEY_MIN_LEN) ||
        (eapol_parsed->len < EAPOL_RSN_KEY_LEN) ||
        (key_bytes_len > eapol_parsed->len - EAPOL_RSN_KEY_LEN)) {
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    /* Encrypted key is in the information element field of the EAPOL key packet */
    key_data = eapol_parsed->key_data;

    DEBUG_DUMP("Encrypted Broadcast key", key_data, key_bytes_len, LOG_LEVEL_DEBUG);
    DEBUG_DUMP("KeyIV", eapol_parsed->key_iv, 16, LOG_LEVEL_DEBUG);
    DEBUG_DUMP("decryption_key", decryption_key, decryption_key_len, LOG_LEVEL_DEBUG);

    /* As we have no concept of the prior association request at this point, we need to deduce the     */
    /* group key cipher from the length of the key bytes. In WPA this is straightforward as the        */
    /* keybytes just contain the GTK, and the GTK is only in the group handshake, NOT the M3.          */
    /* In WPA2 its a little more tricky as the M3 keybytes contain an RSN_IE, but the group handshake  */
    /* does not. Also there are other (variable length) items in the keybytes which we need to account */
    /* for to determine the true key length, and thus the group cipher.                                */

    if (key_version == DOT11DECRYPT_WPA_KEY_VER_NOT_CCMP){
        /* TKIP key */
        /* Per 802.11i, Draft 3.0 spec, section 8.5.2, p. 97, line 4-8, */
        /* group key is decrypted using RC4.  Concatenate the IV with the 16 byte EK (PTK+16) to get the decryption key */
        uint8_t new_key[32];
        uint8_t *data;

        /* The WPA group key just contains the GTK bytes so deducing the type is straightforward   */
        /* Note - WPA M3 doesn't contain a group key so we'll only be here for the group handshake */
        sa->wpa.key_ver = (key_bytes_len >=TKIP_GROUP_KEY_LEN)?DOT11DECRYPT_WPA_KEY_VER_NOT_CCMP:DOT11DECRYPT_WPA_KEY_VER_AES_CCMP;

        /* Build the full decryption key based on the IV and part of the pairwise key */
        memcpy(new_key, eapol_parsed->key_iv, 16);
        memcpy(new_key+16, decryption_key, 16);
        DEBUG_DUMP("FullDecrKey", new_key, 32, LOG_LEVEL_DEBUG);
        data = Dot11DecryptRc4KeyData(new_key, 32, key_data, key_bytes_len);
        if (!data) {
            return DOT11DECRYPT_RET_UNSUCCESS;
        }
        memcpy(decrypted_data, data, key_bytes_len);
        g_free(data);
    } else {
        /* Ideally AKM from EAPOL message 2 of 4 should be used to determine Key-wrap algorithm to use */
        /* Though fortunately IEEE802.11-2016 Table 12-8 state that all AKMs use "NIST AES Key Wrap"  */
        /* algorithm so no AKM lookup is needed. */

        /* Unwrap the key; the result is key_bytes_len in length */
        if (AES_unwrap(decryption_key, decryption_key_len, key_data, key_bytes_len,
                       decrypted_data, &key_bytes_len)) {
            return DOT11DECRYPT_RET_UNSUCCESS;
        }
    }

    Dot11DecryptCopyKey(sa, key);
    *decrypted_len = key_bytes_len;
    return DOT11DECRYPT_RET_SUCCESS;
}

/**
 * @param ctx [IN] pointer to the current context
 * @param id [IN] id of the association (composed by BSSID and MAC of
 * the station)
 * @return a pointer of the requested SA. NULL if it doesn't exist.
 */
static PDOT11DECRYPT_SEC_ASSOCIATION
Dot11DecryptGetSa(
    PDOT11DECRYPT_CONTEXT ctx,
    const DOT11DECRYPT_SEC_ASSOCIATION_ID *id)
{
    return (DOT11DECRYPT_SEC_ASSOCIATION *)g_hash_table_lookup(ctx->sa_hash, id);
}

static PDOT11DECRYPT_SEC_ASSOCIATION
Dot11DecryptNewSa(const DOT11DECRYPT_SEC_ASSOCIATION_ID *id)
{
    PDOT11DECRYPT_SEC_ASSOCIATION sa = g_new0(DOT11DECRYPT_SEC_ASSOCIATION, 1);
    if (sa != NULL) {
        sa->saId = *id;
    }
    return sa;
}

static DOT11DECRYPT_SEC_ASSOCIATION *
Dot11DecryptPrependSa(
    DOT11DECRYPT_SEC_ASSOCIATION *existing_sa,
    DOT11DECRYPT_SEC_ASSOCIATION *new_sa)
{
    DOT11DECRYPT_SEC_ASSOCIATION tmp_sa;

    /* Add new SA first in list, but copy by value into existing record
     * so that sa_hash need not be updated with new value */
    tmp_sa = *existing_sa;
    *existing_sa = *new_sa;
    *new_sa = tmp_sa;
    existing_sa->next = new_sa;
    return existing_sa;
}

/* Add SA, keep existing (if any). Return pointer to newly inserted (first) SA */
static PDOT11DECRYPT_SEC_ASSOCIATION
Dot11DecryptAddSa(
    PDOT11DECRYPT_CONTEXT ctx,
    const DOT11DECRYPT_SEC_ASSOCIATION_ID *id,
    DOT11DECRYPT_SEC_ASSOCIATION *sa)
{
    DOT11DECRYPT_SEC_ASSOCIATION *existing_sa = Dot11DecryptGetSa(ctx, id);
    if (existing_sa != NULL) {
        sa = Dot11DecryptPrependSa(existing_sa, sa);
    } else {
        void *key = g_memdup2(id, sizeof(DOT11DECRYPT_SEC_ASSOCIATION_ID));
        g_hash_table_insert(ctx->sa_hash, key, sa);
    }
    return sa;
}

int
Dot11DecryptGetKCK(const PDOT11DECRYPT_KEY_ITEM key, const uint8_t **kck)
{
    if (!key || !kck) {
        return 0;
    }
    *kck = DOT11DECRYPT_GET_KCK(key->KeyData.Wpa.Ptk, key->KeyData.Wpa.Akm);
    return Dot11DecryptGetKckLen(key->KeyData.Wpa.Akm) / 8;
}

int
Dot11DecryptGetKEK(const PDOT11DECRYPT_KEY_ITEM key, const uint8_t **kek)
{
    if (!key || !kek) {
        return 0;
    }
    *kek = DOT11DECRYPT_GET_KEK(key->KeyData.Wpa.Ptk, key->KeyData.Wpa.Akm);
    return Dot11DecryptGetKekLen(key->KeyData.Wpa.Akm) / 8;
}

int
Dot11DecryptGetTK(const PDOT11DECRYPT_KEY_ITEM key, const uint8_t **tk)
{
    int len;
    if (!key || !tk) {
        return 0;
    }
    if (key->KeyType == DOT11DECRYPT_KEY_TYPE_TKIP) {
        *tk = DOT11DECRYPT_GET_TK_TKIP(key->KeyData.Wpa.Ptk);
        len = 16;
    } else {
        *tk = DOT11DECRYPT_GET_TK(key->KeyData.Wpa.Ptk, key->KeyData.Wpa.Akm);
        len = Dot11DecryptGetTkLen(key->KeyData.Wpa.Cipher) / 8;
    }
    return len;
}

int
Dot11DecryptGetGTK(const PDOT11DECRYPT_KEY_ITEM key, const uint8_t **gtk)
{
    int len;
    if (!key || !gtk) {
        return 0;
    }

    /* GTK is stored in PTK at offset 32. See comment in Dot11DecryptCopyBroadcastKey */
    *gtk = key->KeyData.Wpa.Ptk + 32;
    if (key->KeyType == DOT11DECRYPT_KEY_TYPE_TKIP) {
        len = 16;
    } else {
        len = Dot11DecryptGetTkLen(key->KeyData.Wpa.Cipher) / 8;
    }
    return len;
}

int Dot11DecryptScanTdlsForKeys(
    PDOT11DECRYPT_CONTEXT ctx,
    const uint8_t *data,
    const unsigned tot_len)
{
    unsigned offset = 0;
    unsigned tot_len_left = tot_len;
    DOT11DECRYPT_SEC_ASSOCIATION_ID id;
    PDOT11DECRYPT_SEC_ASSOCIATION sa;
    const uint8_t *initiator, *responder;
    uint8_t action;
    unsigned status, offset_rsne = 0, offset_fte = 0, offset_link = 0, offset_timeout = 0;
    ws_debug("Authentication: TDLS Action Frame");

    /* TDLS payload contains a TDLS Action field (802.11-2016 9.6.13) */

    /* check if the packet is a TDLS response or confirm */
    if (tot_len_left < 1) {
        ws_debug("Not EAPOL-Key");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }
    action = data[offset];
    if (action != 1 && action != 2) {
        ws_debug("Not Response nor confirm");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }
    offset++;
    tot_len_left--;

    /* Check for SUCCESS (0) or SUCCESS_POWER_SAVE_MODE (85) Status Code */
    if (tot_len_left < 5) {
        ws_debug("Not EAPOL-Key");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }
    status=pntoh16(data + offset);
    if (status != 0 && status != 85) {
        ws_debug("TDLS setup not successful");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }

    /* skip Token + capabilities */
    offset += 5;

    /* search for RSN, Fast BSS Transition, Link Identifier and Timeout Interval IEs */

    while(offset < (tot_len - 2)) {
        uint8_t element_id = data[offset];
        uint8_t length = data[offset + 1];
        unsigned min_length = length;
        switch (element_id) {
        case 48:    /* RSN (802.11-2016 9.4.2.35) */
            offset_rsne = offset;
            min_length = 1;
            break;
        case 55:    /* FTE (802.11-2016 9.4.2.48) */
            offset_fte = offset;
            /* Plus variable length optional parameter(s) */
            min_length = 2 + 16 + 32 + 32;
            break;
        case 56:    /* Timeout Interval (802.11-2016 9.4.2.49) */
            offset_timeout = offset;
            min_length = 1 + 4;
            break;
        case 101:   /* Link Identifier (802.11-2016 9.4.2.62) */
            offset_link = offset;
            min_length = 6 + 6 + 6;
            break;
        }

        if (length < min_length || tot_len < offset + 2 + length) {
            ws_debug("Invalid length records in IEs");
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }
        offset += 2 + length;
    }

    if (offset_rsne == 0 || offset_fte == 0 ||
        offset_timeout == 0 || offset_link == 0)
    {
        ws_debug("Cannot Find all necessary IEs");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }

    ws_debug("Found RSNE/Fast BSS/Timeout Interval/Link IEs");

    /* Will create a Security Association between 2 STA. Need to get both MAC address */
    initiator = &data[offset_link + 8];
    responder = &data[offset_link + 14];

    if (memcmp(initiator, responder, DOT11DECRYPT_MAC_LEN) < 0) {
        memcpy(id.sta, initiator, DOT11DECRYPT_MAC_LEN);
        memcpy(id.bssid, responder, DOT11DECRYPT_MAC_LEN);
    } else {
        memcpy(id.sta, responder, DOT11DECRYPT_MAC_LEN);
        memcpy(id.bssid, initiator, DOT11DECRYPT_MAC_LEN);
    }

    /* Check if already derived this key */
    sa = Dot11DecryptGetSa(ctx, &id);
    PDOT11DECRYPT_SEC_ASSOCIATION iter_sa;
    for (iter_sa = sa; iter_sa != NULL; iter_sa = iter_sa->next) {
        if (iter_sa->validKey &&
            memcmp(iter_sa->wpa.nonce, data + offset_fte + 52,
                   DOT11DECRYPT_WPA_NONCE_LEN) == 0)
        {
            /* Already have valid key for this SA, no need to redo key derivation */
            return DOT11DECRYPT_RET_SUCCESS_HANDSHAKE;
        }
    }
    /* We are opening a new session with the same two STA (previous sa will be kept if any) */
    sa = Dot11DecryptNewSa(&id);
    if (sa == NULL) {
        ws_warning("Failed to alloc new SA entry");
        return DOT11DECRYPT_RET_REQ_DATA;
    }
    if (Dot11DecryptTDLSDeriveKey(sa, data, offset_rsne, offset_fte,
            offset_timeout, offset_link, action) == DOT11DECRYPT_RET_SUCCESS) {
        Dot11DecryptAddSa(ctx, &id, sa);
        return DOT11DECRYPT_RET_SUCCESS_HANDSHAKE;
    }
    g_free(sa);
    return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
}

static int
Dot11DecryptCopyBroadcastKey(
    PDOT11DECRYPT_CONTEXT ctx,
    const uint8_t *gtk, size_t gtk_len,
    const DOT11DECRYPT_SEC_ASSOCIATION_ID *id)
{
    DOT11DECRYPT_SEC_ASSOCIATION_ID broadcast_id;
    DOT11DECRYPT_SEC_ASSOCIATION *sa;
    DOT11DECRYPT_SEC_ASSOCIATION *broadcast_sa;

    if (!gtk || gtk_len == 0) {
        ws_debug("No broadcast key found");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }
    if (gtk_len > DOT11DECRYPT_WPA_PTK_MAX_LEN - 32) {
        ws_debug("Broadcast key too large");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }

    sa = Dot11DecryptGetSa(ctx, id);
    if (sa == NULL) {
        ws_debug("No SA for BSSID found");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }

    /* Broadcast SA for the current BSSID */
    memcpy(broadcast_id.bssid, id->bssid, DOT11DECRYPT_MAC_LEN);
    memcpy(broadcast_id.sta, broadcast_mac, DOT11DECRYPT_MAC_LEN);

    broadcast_sa = Dot11DecryptNewSa(&broadcast_id);
    if (broadcast_sa == NULL) {
        ws_warning("Failed to alloc broadcast sa");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }

    /* Retrieve AKMS / cipher etc from handshake message 2 */

    broadcast_sa->wpa.key_ver = sa->wpa.key_ver;
    broadcast_sa->wpa.akm = sa->wpa.akm;
    broadcast_sa->wpa.cipher = sa->wpa.tmp_group_cipher;
    broadcast_sa->wpa.ptk_len = sa->wpa.ptk_len;
    broadcast_sa->validKey = true;
    DEBUG_DUMP("Broadcast key", gtk, gtk_len, LOG_LEVEL_DEBUG);

    /* Since this is a GTK and its size is only 32 bytes (vs. the 64 byte size of a PTK),
     * we fake it and put it in at a 32-byte offset so the Dot11DecryptRsnaMng() function
     * will extract the right piece of the GTK for decryption. (The first 16 bytes of the
     * GTK are used for decryption.) */
    memset(broadcast_sa->wpa.ptk, 0, sizeof(broadcast_sa->wpa.ptk));
    memcpy(broadcast_sa->wpa.ptk + 32, gtk, gtk_len);
    Dot11DecryptAddSa(ctx, &broadcast_id, broadcast_sa);
    return DOT11DECRYPT_RET_SUCCESS_HANDSHAKE;
}

static int
Dot11DecryptGroupHandshake(
    PDOT11DECRYPT_CONTEXT ctx,
    PDOT11DECRYPT_EAPOL_PARSED eapol_parsed,
    const DOT11DECRYPT_SEC_ASSOCIATION_ID *id,
    const unsigned tot_len)
{

    if (GROUP_KEY_PAYLOAD_LEN_MIN > tot_len) {
        ws_debug("Message too short for Group Key");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }
    if (eapol_parsed->msg_type != DOT11DECRYPT_HS_MSG_TYPE_GHS_1){
        ws_warning("Not Group handshake message 1");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }
    return Dot11DecryptCopyBroadcastKey(ctx, eapol_parsed->gtk, eapol_parsed->gtk_len, id);
}

int Dot11DecryptScanEapolForKeys(
    PDOT11DECRYPT_CONTEXT ctx,
    PDOT11DECRYPT_EAPOL_PARSED eapol_parsed,
    const uint8_t *eapol_raw,
    const unsigned tot_len,
    const unsigned char bssid[DOT11DECRYPT_MAC_LEN],
    const unsigned char sta[DOT11DECRYPT_MAC_LEN])
{
    DOT11DECRYPT_SEC_ASSOCIATION_ID id;

    /* Callers provide these guarantees, so let's make them explicit. */
    DISSECTOR_ASSERT(tot_len <= DOT11DECRYPT_EAPOL_MAX_LEN);

    ws_debug("Authentication: EAPOL packet");

    /* check if the key descriptor type is valid (IEEE 802.1X-2004, pg. 27) */
    if (/*eapol_parsed->key_type != 0x1 &&*/ /* RC4 Key Descriptor Type (deprecated) */
        eapol_parsed->key_type != DOT11DECRYPT_RSN_WPA2_KEY_DESCRIPTOR &&  /* IEEE 802.11 Key Descriptor Type  (WPA2) */
        eapol_parsed->key_type != DOT11DECRYPT_RSN_WPA_KEY_DESCRIPTOR)     /* 254 = RSN_KEY_DESCRIPTOR - WPA,         */
    {
        ws_debug("Not valid key descriptor type");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }

    /* search for a cached Security Association for current BSSID and AP */
    memcpy(id.bssid, bssid, DOT11DECRYPT_MAC_LEN);
    memcpy(id.sta, sta, DOT11DECRYPT_MAC_LEN);

    switch (eapol_parsed->msg_type) {
        case DOT11DECRYPT_HS_MSG_TYPE_4WHS_1:
        case DOT11DECRYPT_HS_MSG_TYPE_4WHS_2:
        case DOT11DECRYPT_HS_MSG_TYPE_4WHS_3:
        case DOT11DECRYPT_HS_MSG_TYPE_4WHS_4:
            return Dot11DecryptRsna4WHandshake(ctx, eapol_parsed, eapol_raw,
                                               &id, tot_len);
        case DOT11DECRYPT_HS_MSG_TYPE_GHS_1:
            return Dot11DecryptGroupHandshake(ctx, eapol_parsed, &id, tot_len);
        case DOT11DECRYPT_HS_MSG_TYPE_GHS_2:
            break;
        case DOT11DECRYPT_HS_MSG_TYPE_INVALID:
        default:
            ws_warning("Invalid message type");
            break;
    }
    return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
}

static int
Dot11DecryptGetNbrOfTkKeys(PDOT11DECRYPT_CONTEXT ctx)
{
    int nbr = 0;
    for (size_t i = 0; i < ctx->keys_nr; i++) {
        if (ctx->keys[i].KeyType == DOT11DECRYPT_KEY_TYPE_TK) {
            nbr++;
        }
    }
    return nbr;
}

static int
Dot11DecryptUsingUserTk(
    PDOT11DECRYPT_CONTEXT ctx,
    unsigned char *decrypt_data,
    unsigned mac_header_len,
    unsigned *decrypt_len,
    DOT11DECRYPT_SEC_ASSOCIATION_ID *id,
    DOT11DECRYPT_KEY_ITEM *used_key)
{
    int ret = DOT11DECRYPT_RET_REQ_DATA;
    DOT11DECRYPT_SEC_ASSOCIATION *sa = Dot11DecryptNewSa(id);
    DOT11DECRYPT_KEY_ITEM *key;
    if (sa == NULL) {
        return ret;
    }

    sa->wpa.akm = 2;
    sa->validKey = true;

    /* Try decrypt packet with all user TKs applicable ciphers */
    for (size_t key_index = 0; key_index < ctx->keys_nr; key_index++) {
        key = &ctx->keys[key_index];
        if (key->KeyType != DOT11DECRYPT_KEY_TYPE_TK) {
            continue;
        }
        int ciphers_to_try[4] = { 0 };
        switch (key->Tk.Len) {
            case DOT11DECRYPT_WEP_40_KEY_LEN:
            case DOT11DECRYPT_WEP_104_KEY_LEN:
                /* TBD implement */
                continue;
            case 256 / 8:
                ciphers_to_try[0] = 9; /* GCMP-256 */
                ciphers_to_try[1] = 10; /* CCMP-256 */
                break;
            case 128 / 8:
                ciphers_to_try[0] = 4; /* CCMP-128 */
                ciphers_to_try[1] = 8; /* GCMP-128 */
                ciphers_to_try[2] = 2; /* TKIP */
                break;
            default:
                continue;
        }

        sa->key = key;

        for (int i = 0; ciphers_to_try[i] != 0; i++) {
            sa->wpa.cipher = ciphers_to_try[i];
            if (sa->wpa.cipher == 2 /* TKIP */) {
                sa->wpa.key_ver = 1;
                memcpy(DOT11DECRYPT_GET_TK_TKIP(sa->wpa.ptk),
                       key->Tk.Tk, key->Tk.Len);
            } else {
                sa->wpa.key_ver = 2;
                sa->wpa.akm = 2;
                memcpy(DOT11DECRYPT_GET_TK(sa->wpa.ptk, sa->wpa.akm),
                       key->Tk.Tk, key->Tk.Len);
            }
            sa->wpa.ptk_len = Dot11DecryptGetPtkLen(sa->wpa.akm, sa->wpa.cipher) / 8;
            ret = Dot11DecryptRsnaMng(decrypt_data, mac_header_len, decrypt_len, used_key, sa);
            if (ret == DOT11DECRYPT_RET_SUCCESS) {
                /* Successfully decrypted using user TK. Add SA formed from user TK so that
                 * subsequent frames can be decrypted much faster using normal code path
                 * without trying each and every user TK entered.
                 */
                Dot11DecryptAddSa(ctx, id, sa);
                return ret;
            }
        }
    }
    g_free(sa);
    return ret;
}

int Dot11DecryptDecryptPacket(
    PDOT11DECRYPT_CONTEXT ctx,
    const uint8_t *data,
    const unsigned mac_header_len,
    const unsigned tot_len,
    unsigned char *decrypt_data,
    unsigned *decrypt_len,
    PDOT11DECRYPT_KEY_ITEM key)
{
    DOT11DECRYPT_SEC_ASSOCIATION_ID id;
    DISSECTOR_ASSERT(decrypt_data);
    DISSECTOR_ASSERT(decrypt_len);

    if (decrypt_len) {
        *decrypt_len = 0;
    }
    if (ctx==NULL) {
        ws_warning("NULL context");
        return DOT11DECRYPT_RET_REQ_DATA;
    }
    if (data==NULL || tot_len==0) {
        ws_debug("NULL data or length=0");
        return DOT11DECRYPT_RET_REQ_DATA;
    }

    /* check correct packet size, to avoid wrong elaboration of encryption algorithms */
    if (tot_len < (unsigned)(mac_header_len+DOT11DECRYPT_CRYPTED_DATA_MINLEN)) {
        ws_debug("minimum length violated");
        return DOT11DECRYPT_RET_WRONG_DATA_SIZE;
    }

    /* Assume that the decrypt_data field is no more than this size. */
    if (tot_len > DOT11DECRYPT_MAX_CAPLEN) {
        ws_debug("length too large");
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    /* get STA/BSSID address */
    if (Dot11DecryptGetSaAddress((const DOT11DECRYPT_MAC_FRAME_ADDR4 *)(data), &id) != DOT11DECRYPT_RET_SUCCESS) {
        ws_noisy("STA/BSSID not found");
        return DOT11DECRYPT_RET_REQ_DATA;
    }

    /* check if data is encrypted (use the WEP bit in the Frame Control field) */
    if (DOT11DECRYPT_WEP(data[1])==0) {
        return DOT11DECRYPT_RET_NO_DATA_ENCRYPTED;
    }
    PDOT11DECRYPT_SEC_ASSOCIATION sa;

    /* create new header and data to modify */
    *decrypt_len = tot_len;
    memcpy(decrypt_data, data, *decrypt_len);

    /* encrypted data */
    ws_noisy("Encrypted data");

    /* check the Extension IV to distinguish between WEP encryption and WPA encryption */
    /* refer to IEEE 802.11i-2004, 8.2.1.2, pag.35 for WEP,    */
    /*          IEEE 802.11i-2004, 8.3.2.2, pag. 45 for TKIP,  */
    /*          IEEE 802.11i-2004, 8.3.3.2, pag. 57 for CCMP   */
    if (DOT11DECRYPT_EXTIV(data[mac_header_len + 3]) == 0) {
        ws_noisy("WEP encryption");
        return Dot11DecryptWepMng(ctx, decrypt_data, mac_header_len, decrypt_len, key, &id);
    } else {
        ws_noisy("TKIP or CCMP encryption");

        /* If the destination is a multicast address use the group key. This will not work if the AP is using
            more than one group key simultaneously.  I've not seen this in practice, however.
            Usually an AP will rotate between the two key index values of 1 and 2 whenever
            it needs to change the group key to be used. */
        if (((const DOT11DECRYPT_MAC_FRAME_ADDR4 *)(data))->addr1[0] & 0x01) {
            ws_noisy("Broadcast/Multicast address. This is encrypted with a group key.");

            /* force STA address to broadcast MAC so we load the SA for the groupkey */
            memcpy(id.sta, broadcast_mac, DOT11DECRYPT_MAC_LEN);
        }
        /* search for a cached Security Association for current BSSID and STA/broadcast MAC */
        int ret = DOT11DECRYPT_RET_REQ_DATA;
        sa = Dot11DecryptGetSa(ctx, &id);
        if (sa != NULL) {
            /* Decrypt the packet using the appropriate SA */
            ret = Dot11DecryptRsnaMng(decrypt_data, mac_header_len, decrypt_len, key, sa);
        }
        if (ret != DOT11DECRYPT_RET_SUCCESS && Dot11DecryptGetNbrOfTkKeys(ctx) > 0) {
            /* Decryption with known SAs failed. Try decrypt with TK user entries */
            ret = Dot11DecryptUsingUserTk(ctx, decrypt_data, mac_header_len, decrypt_len, &id, key);
        }
        return ret;
     }
    return DOT11DECRYPT_RET_UNSUCCESS;
}

int Dot11DecryptSetKeys(
    PDOT11DECRYPT_CONTEXT ctx,
    DOT11DECRYPT_KEY_ITEM keys[],
    const size_t keys_nr)
{
    int i;
    int success;

    if (ctx==NULL || keys==NULL) {
        ws_warning("NULL context or NULL keys array");
        return 0;
    }

    if (keys_nr>DOT11DECRYPT_MAX_KEYS_NR) {
        ws_warning("Keys number greater than maximum");
        return 0;
    }

    /* clean key and SA collections before setting new ones */
    Dot11DecryptInitContext(ctx);

    /* check and insert keys */
    for (i=0, success=0; i<(int)keys_nr; i++) {
        if (Dot11DecryptValidateKey(keys+i)==true) {
            if (keys[i].KeyType==DOT11DECRYPT_KEY_TYPE_WPA_PWD) {
                Dot11DecryptRsnaPwd2Psk(&keys[i].UserPwd, keys[i].KeyData.Wpa.Psk);
                keys[i].KeyData.Wpa.PskLen = DOT11DECRYPT_WPA_PWD_PSK_LEN;
            }
            memcpy(&ctx->keys[success], &keys[i], sizeof(keys[i]));
            success++;
        }
    }

    ctx->keys_nr=success;
    return success;
}

static void
Dot11DecryptCleanKeys(
    PDOT11DECRYPT_CONTEXT ctx)
{
    if (ctx==NULL) {
        ws_warning("NULL context");
        return;
    }

    memset(ctx->keys, 0, sizeof(DOT11DECRYPT_KEY_ITEM) * DOT11DECRYPT_MAX_KEYS_NR);

    ctx->keys_nr=0;
    ws_debug("Keys collection cleaned!");
}

static void
Dot11DecryptCleanSA(
    void * first_sa)
{
    DOT11DECRYPT_SEC_ASSOCIATION *cur_sa = (DOT11DECRYPT_SEC_ASSOCIATION *)first_sa;
    while (cur_sa) {
        DOT11DECRYPT_SEC_ASSOCIATION *next_sa = cur_sa->next;
        g_free(cur_sa);
        cur_sa = next_sa;
    }
}

static void
Dot11DecryptCleanSecAssoc(
    PDOT11DECRYPT_CONTEXT ctx)
{
    if (ctx->sa_hash != NULL) {
        g_hash_table_destroy(ctx->sa_hash);
        ctx->sa_hash = NULL;
    }
}

/*
 * XXX - This won't be reliable if a packet containing SSID "B" shows
 * up in the middle of a 4-way handshake for SSID "A".
 * We should probably use a small array or hash table to keep multiple
 * SSIDs.
 */
int Dot11DecryptSetLastSSID(
    PDOT11DECRYPT_CONTEXT ctx,
    char *pkt_ssid,
    size_t pkt_ssid_len)
{
    if (!ctx || !pkt_ssid || pkt_ssid_len < 1 || pkt_ssid_len > WPA_SSID_MAX_SIZE)
        return DOT11DECRYPT_RET_UNSUCCESS;

    memcpy(ctx->pkt_ssid, pkt_ssid, pkt_ssid_len);
    ctx->pkt_ssid_len = pkt_ssid_len;

    return DOT11DECRYPT_RET_SUCCESS;
}

static unsigned
Dot11DecryptSaHash(const void *key)
{
    GBytes *bytes = g_bytes_new_static(key, sizeof(DOT11DECRYPT_SEC_ASSOCIATION_ID));
    unsigned hash = g_bytes_hash(bytes);
    g_bytes_unref(bytes);
    return hash;
}

static gboolean
Dot11DecryptIsSaIdEqual(const void *key1, const void *key2)
{
    return memcmp(key1, key2, sizeof(DOT11DECRYPT_SEC_ASSOCIATION_ID)) == 0;
}

int Dot11DecryptInitContext(
    PDOT11DECRYPT_CONTEXT ctx)
{
    if (ctx==NULL) {
        ws_warning("NULL context");
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    Dot11DecryptCleanKeys(ctx);
    Dot11DecryptCleanSecAssoc(ctx);

    ctx->pkt_ssid_len = 0;
    ctx->sa_hash = g_hash_table_new_full(Dot11DecryptSaHash, Dot11DecryptIsSaIdEqual,
                                         g_free, Dot11DecryptCleanSA);
    if (ctx->sa_hash == NULL) {
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    ws_debug("Context initialized!");
    return DOT11DECRYPT_RET_SUCCESS;
}

int Dot11DecryptDestroyContext(
    PDOT11DECRYPT_CONTEXT ctx)
{
    if (ctx==NULL) {
        ws_warning("NULL context");
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    Dot11DecryptCleanKeys(ctx);
    Dot11DecryptCleanSecAssoc(ctx);

    ws_debug("Context destroyed!");
    return DOT11DECRYPT_RET_SUCCESS;
}

#ifdef __cplusplus
}
#endif

/****************************************************************************/

/****************************************************************************/
/* Internal function definitions                                         */

#ifdef __cplusplus
extern "C" {
#endif

static int
Dot11DecryptRsnaMng(
    unsigned char *decrypt_data,
    unsigned mac_header_len,
    unsigned *decrypt_len,
    PDOT11DECRYPT_KEY_ITEM key,
    DOT11DECRYPT_SEC_ASSOCIATION *sa)
{
    int ret = 1;
    unsigned char *try_data;
    unsigned try_data_len = *decrypt_len;

    if (*decrypt_len == 0) {
        ws_debug("Invalid decryption length");
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    /* allocate a temp buffer for the decryption loop */
    try_data=(unsigned char *)g_malloc(try_data_len);

    /* start of loop added by GCS */
    for(/* sa */; sa != NULL ;sa=sa->next) {

       if (sa->validKey==false) {
           ws_noisy("Key not yet valid");
           continue;
       }

       /* copy the encrypted data into a temp buffer */
       memcpy(try_data, decrypt_data, *decrypt_len);

       if (sa->wpa.key_ver==1) {
           /* CCMP -> HMAC-MD5 is the EAPOL-Key MIC, RC4 is the EAPOL-Key encryption algorithm */
           ws_noisy("TKIP");
           DEBUG_DUMP("ptk", sa->wpa.ptk, 64, LOG_LEVEL_NOISY);
           DEBUG_DUMP("ptk portion used", DOT11DECRYPT_GET_TK_TKIP(sa->wpa.ptk),
                      16, LOG_LEVEL_NOISY);

           if (*decrypt_len < (unsigned)mac_header_len) {
               ws_debug("Invalid decryption length");
               g_free(try_data);
               return DOT11DECRYPT_RET_UNSUCCESS;
           }
           if (*decrypt_len < DOT11DECRYPT_TKIP_MICLEN + DOT11DECRYPT_WEP_ICV) {
               ws_debug("Invalid decryption length");
               g_free(try_data);
               return DOT11DECRYPT_RET_UNSUCCESS;
           }

           ret = Dot11DecryptTkipDecrypt(try_data + mac_header_len, *decrypt_len - mac_header_len,
                                         try_data + DOT11DECRYPT_TA_OFFSET,
                                         DOT11DECRYPT_GET_TK_TKIP(sa->wpa.ptk));
           if (ret) {
               ws_noisy("TKIP failed!");
               continue;
           }

           ws_noisy("TKIP DECRYPTED!!!");
           /* remove MIC and ICV from the end of packet */
           *decrypt_len -= DOT11DECRYPT_TKIP_MICLEN + DOT11DECRYPT_WEP_ICV;
           break;
       } else if (sa->wpa.cipher == 8 || sa->wpa.cipher == 9) {
           ws_noisy("GCMP");

           if (*decrypt_len < DOT11DECRYPT_GCMP_TRAILER) {
               ws_debug("Invalid decryption length");
               g_free(try_data);
               return DOT11DECRYPT_RET_UNSUCCESS;
           }
           ret = Dot11DecryptGcmpDecrypt(try_data, mac_header_len, (int)*decrypt_len,
                                         DOT11DECRYPT_GET_TK(sa->wpa.ptk, sa->wpa.akm),
                                         Dot11DecryptGetTkLen(sa->wpa.cipher) / 8);
           if (ret) {
              continue;
           }
           ws_noisy("GCMP DECRYPTED!!!");
           /* remove MIC from the end of packet */
           *decrypt_len -= DOT11DECRYPT_GCMP_TRAILER;
           break;
       } else {
           /* AES-CCMP -> HMAC-SHA1-128 is the EAPOL-Key MIC, AES wep_key wrap is the EAPOL-Key encryption algorithm */
           ws_noisy("CCMP");

           unsigned trailer = sa->wpa.cipher != 10 ? DOT11DECRYPT_CCMP_TRAILER : DOT11DECRYPT_CCMP_256_TRAILER;
           if (*decrypt_len < trailer) {
               ws_debug("Invalid decryption length");
               g_free(try_data);
               return DOT11DECRYPT_RET_UNSUCCESS;
           }

           ret = Dot11DecryptCcmpDecrypt(try_data, mac_header_len, (int)*decrypt_len,
                                         DOT11DECRYPT_GET_TK(sa->wpa.ptk, sa->wpa.akm),
                                         Dot11DecryptGetTkLen(sa->wpa.cipher) / 8,
                                         trailer);
           if (ret) {
              continue;
           }
           ws_noisy("CCMP DECRYPTED!!!");
           /* remove MIC from the end of packet */
           *decrypt_len -= trailer;
           break;
       }
    }
    /* end of loop */

    /* none of the keys worked */
    if(sa == NULL) {
        g_free(try_data);
        return ret;
    }

    if (*decrypt_len > try_data_len || *decrypt_len < 8) {
        ws_debug("Invalid decryption length");
        g_free(try_data);
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    /* remove protection bit */
    decrypt_data[1]&=0xBF;

    /* remove TKIP/CCMP header */
    *decrypt_len-=8;

    if (*decrypt_len < mac_header_len) {
        ws_debug("Invalid decryption length < mac_header_len");
        g_free(try_data);
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    /* copy the decrypted data into the decrypt buffer GCS*/
    memcpy(decrypt_data + mac_header_len, try_data + mac_header_len + 8,
           *decrypt_len - mac_header_len);
    g_free(try_data);

    Dot11DecryptCopyKey(sa, key);
    return DOT11DECRYPT_RET_SUCCESS;
}

static int
Dot11DecryptWepMng(
    PDOT11DECRYPT_CONTEXT ctx,
    unsigned char *decrypt_data,
    unsigned mac_header_len,
    unsigned *decrypt_len,
    PDOT11DECRYPT_KEY_ITEM key,
    DOT11DECRYPT_SEC_ASSOCIATION_ID *id)
{
    unsigned char wep_key[DOT11DECRYPT_WEP_KEY_MAXLEN+DOT11DECRYPT_WEP_IVLEN];
    size_t keylen;
    int ret_value=1;
    int key_index;
    DOT11DECRYPT_KEY_ITEM *tmp_key;
    uint8_t useCache=false;
    unsigned char *try_data;
    DOT11DECRYPT_SEC_ASSOCIATION *sa;
    unsigned try_data_len = *decrypt_len;

    try_data = (unsigned char *)g_malloc(try_data_len);

    /* get the Security Association structure for the STA and AP */

    /* For WEP the sa is used only for caching. When no sa exists all user
     * entered WEP keys are checked and on successful packet decryption an
     * sa is formed caching the key used for decryption.
     */
    sa = Dot11DecryptGetSa(ctx, id);
    if (sa != NULL && sa->key != NULL) {
        useCache = true;
    }

    for (key_index=0; key_index<(int)ctx->keys_nr; key_index++) {
        /* use the cached one, or try all keys */
        if (!useCache) {
            tmp_key=&ctx->keys[key_index];
        } else {
            if (sa->key!=NULL && sa->key->KeyType==DOT11DECRYPT_KEY_TYPE_WEP) {
                ws_noisy("Try cached WEP key...");
                tmp_key=sa->key;
            } else {
                ws_noisy("Cached key is not valid, try another WEP key...");
                tmp_key=&ctx->keys[key_index];
            }
        }

        /* obviously, try only WEP keys... */
        if (tmp_key->KeyType==DOT11DECRYPT_KEY_TYPE_WEP) {
            ws_noisy("Try WEP key...");

            memset(wep_key, 0, sizeof(wep_key));
            memcpy(try_data, decrypt_data, *decrypt_len);

            /* Construct the WEP seed: copy the IV in first 3 bytes and then the WEP key (refer to 802-11i-2004, 8.2.1.4.3, pag. 36) */
            memcpy(wep_key, try_data+mac_header_len, DOT11DECRYPT_WEP_IVLEN);
            keylen=tmp_key->KeyData.Wep.WepKeyLen;
            memcpy(wep_key+DOT11DECRYPT_WEP_IVLEN, tmp_key->KeyData.Wep.WepKey, keylen);

            ret_value=Dot11DecryptWepDecrypt(wep_key,
                keylen+DOT11DECRYPT_WEP_IVLEN,
                try_data + (mac_header_len+DOT11DECRYPT_WEP_IVLEN+DOT11DECRYPT_WEP_KIDLEN),
                *decrypt_len-(mac_header_len+DOT11DECRYPT_WEP_IVLEN+DOT11DECRYPT_WEP_KIDLEN+DOT11DECRYPT_CRC_LEN));

            if (ret_value == DOT11DECRYPT_RET_SUCCESS)
                memcpy(decrypt_data, try_data, *decrypt_len);
        }

        if (!ret_value && tmp_key->KeyType==DOT11DECRYPT_KEY_TYPE_WEP) {
            /* the tried key is the correct one, cache it in the Security Association */

            /* Form an SA if one does not exist already */
            if (sa == NULL) {
                sa = Dot11DecryptNewSa(id);
                if (sa == NULL) {
                    ws_warning("Failed to alloc sa for WEP");
                    ret_value = DOT11DECRYPT_RET_UNSUCCESS;
                    break;
                }
                sa = Dot11DecryptAddSa(ctx, id, sa);
            }
            sa->key=tmp_key;

            if (key!=NULL) {
                memcpy(key, sa->key, sizeof(DOT11DECRYPT_KEY_ITEM));
                key->KeyType=DOT11DECRYPT_KEY_TYPE_WEP;
            }

            break;
        } else {
            /* the cached key was not valid, try other keys */

            if (useCache==true) {
                useCache=false;
                key_index--;
            }
        }
    }

    g_free(try_data);
    if (ret_value)
        return DOT11DECRYPT_RET_UNSUCCESS;

    ws_noisy("WEP DECRYPTED!!!");

    /* remove ICV (4bytes) from the end of packet */
    *decrypt_len-=4;

    if (*decrypt_len < 4) {
        ws_debug("Decryption length too short");
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    /* remove protection bit */
    decrypt_data[1]&=0xBF;

    /* remove IC header */
    *decrypt_len-=4;
    memmove(decrypt_data + mac_header_len,
            decrypt_data + mac_header_len + DOT11DECRYPT_WEP_IVLEN + DOT11DECRYPT_WEP_KIDLEN,
            *decrypt_len - mac_header_len);

    return DOT11DECRYPT_RET_SUCCESS;
}

/* From IEEE 802.11-2016 Table 9-133—AKM suite selectors */
static bool Dot11DecryptIsFtAkm(int akm)
{
    switch (akm) {
        case 3:
        case 4:
        case 9:
        case 13:
            return true;
    }
    return false;
}

/* Get xxkey portion of MSK */
/* From IEEE 802.11-2016 12.7.1.7.3 PMK-R0 */
static const uint8_t *
Dot11DecryptGetXXKeyFromMSK(const uint8_t *msk, size_t msk_len,
                            int akm, size_t *xxkey_len)
{
    if (!xxkey_len) {
        return NULL;
    }
    switch (akm) {
    case 3:
        if (msk_len < 64) {
            return NULL;
        }
        *xxkey_len = 32;
        return msk + 32;
    case 13:
        if (msk_len < 48) {
            return NULL;
        }
        *xxkey_len = 48;
        return msk;
    default:
        return NULL;
    }
}

/* From IEEE 802.11-2016 12.7.1.3 Pairwise key hierarchy */
static void
Dot11DecryptDerivePmkFromMsk(const uint8_t *msk, uint8_t msk_len, int akm,
                             uint8_t *pmk, uint8_t *pmk_len)
{
    if (!msk || !pmk || !pmk_len) {
        return;
    }
    // When using AKM suite selector 00-0F-AC:12, the length of the PMK, PMK_bits,
    // shall be 384 bits. With all other AKM suite selectors, the length of the PMK,
    // PMK_bits, shall be 256 bits.
    if (akm == 12) {
        *pmk_len = 384 / 8;
    } else {
        *pmk_len = 256 / 8;
    }
    if ((uint8_t)(msk_len + *pmk_len) < msk_len) {
        *pmk_len = 0;
        return;
    }
    // PMK = L(MSK, 0, PMK_bits).
    memcpy(pmk, msk, *pmk_len);
}

static bool
Dot11DecryptIsWpaKeyType(uint8_t key_type)
{
    switch (key_type) {
        case DOT11DECRYPT_KEY_TYPE_WPA_PWD:
        case DOT11DECRYPT_KEY_TYPE_WPA_PSK:
        case DOT11DECRYPT_KEY_TYPE_WPA_PMK:
        case DOT11DECRYPT_KEY_TYPE_MSK:
            return true;
    }
    return false;
}

static bool
Dot11DecryptIsPwdWildcardSsid(const PDOT11DECRYPT_CONTEXT ctx,
                              const DOT11DECRYPT_KEY_ITEM *key_item)
{
    if (!ctx || !key_item || key_item->KeyType != DOT11DECRYPT_KEY_TYPE_WPA_PWD) {
        return false;
    }
    if (key_item->UserPwd.SsidLen == 0 && ctx->pkt_ssid_len > 0 &&
        ctx->pkt_ssid_len <= DOT11DECRYPT_WPA_SSID_MAX_LEN) {
        return true;
    }
    return false;
}

/* Refer to IEEE 802.11i-2004, 8.5.3, pag. 85 */
static int
Dot11DecryptRsna4WHandshake(
    PDOT11DECRYPT_CONTEXT ctx,
    PDOT11DECRYPT_EAPOL_PARSED eapol_parsed,
    const uint8_t *eapol_raw,
    DOT11DECRYPT_SEC_ASSOCIATION_ID *id,
    const unsigned tot_len)
{
    DOT11DECRYPT_KEY_ITEM *tmp_key, *tmp_pkt_key, pkt_key;
    DOT11DECRYPT_SEC_ASSOCIATION *sa;
    int key_index;
    int ret = 1;
    unsigned char useCache=false;
    unsigned char eapol[DOT11DECRYPT_EAPOL_MAX_LEN];

    if (eapol_parsed->len > DOT11DECRYPT_EAPOL_MAX_LEN ||
        eapol_parsed->key_len > DOT11DECRYPT_EAPOL_MAX_LEN ||
        eapol_parsed->key_data_len > DOT11DECRYPT_EAPOL_MAX_LEN) {
        ws_debug("Too large EAPOL frame and/or key data");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }

    /* TODO timeouts? */

    /* TODO consider key-index */

    /* TODO consider Deauthentications */

    ws_debug("4-way handshake...");

    /* manage 4-way handshake packets; this step completes the 802.1X authentication process (IEEE 802.11i-2004, pag. 85) */

    /* message 1: Authenticator->Supplicant (Sec=0, Mic=0, Ack=1, Inst=0, Key=1(pairwise), KeyRSC=0, Nonce=ANonce, MIC=0) */
    if (eapol_parsed->msg_type == DOT11DECRYPT_HS_MSG_TYPE_4WHS_1) {
        ws_debug("4-way handshake message 1");

        /* On reception of Message 1, the Supplicant determines whether the Key Replay Counter field value has been        */
        /* used before with the current PMKSA. If the Key Replay Counter field value is less than or equal to the current  */
        /* local value, the Supplicant discards the message.                                                               */
        /* -> not checked, the Authenticator will be send another Message 1 (hopefully!)                                   */

        /* save ANonce (from authenticator) to derive the PTK with the SNonce (from the 2 message) */
        if (!eapol_parsed->nonce) {
            ws_debug("ANonce missing");
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }

        sa = Dot11DecryptGetSa(ctx, id);
        if (sa == NULL || sa->handshake >= 2) {
            /* Either no SA exists or one exists but we're reauthenticating */
            sa = Dot11DecryptNewSa(id);
            if (sa == NULL) {
                ws_warning("Failed to alloc broadcast sa");
                return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
            }
            sa = Dot11DecryptAddSa(ctx, id, sa);
        }
        memcpy(sa->wpa.nonce, eapol_parsed->nonce, 32);

        /* get the Key Descriptor Version (to select algorithm used in decryption -CCMP or TKIP-) */
        sa->wpa.key_ver = eapol_parsed->key_version;
        sa->handshake=1;
        return DOT11DECRYPT_RET_SUCCESS_HANDSHAKE;
    }

    /* message 2|4: Supplicant->Authenticator (Sec=0|1, Mic=1, Ack=0, Inst=0, Key=1(pairwise), KeyRSC=0, Nonce=SNonce|0, MIC=MIC(KCK,EAPOL)) */
    if (eapol_parsed->msg_type == DOT11DECRYPT_HS_MSG_TYPE_4WHS_2) {
        ws_debug("4-way handshake message 2");

        /* On reception of Message 2, the Authenticator checks that the key replay counter corresponds to the */
        /* outstanding Message 1. If not, it silently discards the message.                                   */
        /* If the calculated MIC does not match the MIC that the Supplicant included in the EAPOL-Key frame,  */
        /* the Authenticator silently discards Message 2.                                                     */
        /* -> not checked; the Supplicant will send another message 2 (hopefully!)                            */

        sa = Dot11DecryptGetSa(ctx, id);
        if (sa == NULL) {
            ws_debug("No SA for BSSID found");
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }
        if (!eapol_parsed->nonce) {
            ws_debug("SNonce missing");
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }
        if (sa->key != NULL) {
            useCache = true;
        }

        int akm = -1;
        int cipher = -1;
        int group_cipher = -1;
        uint8_t ptk[DOT11DECRYPT_WPA_PTK_MAX_LEN];
        size_t ptk_len = 0;

        /* now you can derive the PTK */
        for (key_index=0; key_index<(int)ctx->keys_nr || useCache; key_index++) {
            /* use the cached one, or try all keys */
            if (useCache && Dot11DecryptIsWpaKeyType(sa->key->KeyType)) {
                ws_debug("Try cached WPA key...");
                tmp_key = sa->key;
                /* Step back loop counter as cached key is used instead */
                key_index--;
            } else {
                ws_debug("Try WPA key...");
                tmp_key = &ctx->keys[key_index];
            }
            useCache = false;

            /* obviously, try only WPA keys... */
            if (!Dot11DecryptIsWpaKeyType(tmp_key->KeyType)) {
                continue;
            }
            if (tmp_key->KeyType == DOT11DECRYPT_KEY_TYPE_WPA_PWD &&
                Dot11DecryptIsPwdWildcardSsid(ctx, tmp_key))
            {
                /* We have a "wildcard" SSID.  Use the one from the packet. */
                memcpy(&pkt_key, tmp_key, sizeof(pkt_key));
                memcpy(&pkt_key.UserPwd.Ssid, ctx->pkt_ssid, ctx->pkt_ssid_len);
                pkt_key.UserPwd.SsidLen = ctx->pkt_ssid_len;
                Dot11DecryptRsnaPwd2Psk(&pkt_key.UserPwd, pkt_key.KeyData.Wpa.Psk);
                tmp_pkt_key = &pkt_key;
            } else {
                tmp_pkt_key = tmp_key;
            }
            memcpy(eapol, eapol_raw, tot_len);

            /* From IEEE 802.11-2016 12.7.2 EAPOL-Key frames */
            if (eapol_parsed->key_version == 0 || eapol_parsed->key_version == 3 ||
                eapol_parsed->key_version == DOT11DECRYPT_WPA_KEY_VER_AES_CCMP)
            {
                /* PTK derivation is based on Authentication Key Management Type */
                akm = eapol_parsed->akm;
                cipher = eapol_parsed->cipher;
                group_cipher = eapol_parsed->group_cipher;
            } else if (eapol_parsed->key_version == DOT11DECRYPT_WPA_KEY_VER_NOT_CCMP) {
                /* TKIP */
                akm = 2;
                cipher = 2;
                group_cipher = 2;
            } else {
                ws_info("EAPOL key_version not supported");
                return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
            }

            if (tmp_pkt_key->KeyType == DOT11DECRYPT_KEY_TYPE_MSK) {
                Dot11DecryptDerivePmkFromMsk(tmp_pkt_key->Msk.Msk, tmp_pkt_key->Msk.Len, akm,
                                             tmp_pkt_key->KeyData.Wpa.Psk,
                                             &tmp_pkt_key->KeyData.Wpa.PskLen);
            }

            if (Dot11DecryptIsFtAkm(akm)) {
                ret = Dot11DecryptFtDerivePtk(ctx, sa, tmp_pkt_key,
                                              eapol_parsed->mdid,
                                              eapol_parsed->nonce,
                                              eapol_parsed->fte.r0kh_id,
                                              eapol_parsed->fte.r0kh_id_len,
                                              eapol_parsed->fte.r1kh_id,
                                              eapol_parsed->fte.r1kh_id_len,
                                              akm, cipher, ptk, &ptk_len);
            } else {
                /* derive the PTK from the BSSID, STA MAC, PMK, SNonce, ANonce */
                ret = Dot11DecryptDerivePtk(sa, /* authenticator nonce, bssid, station mac */
                                            tmp_pkt_key->KeyData.Wpa.Psk, /* PSK == PMK */
                                            tmp_pkt_key->KeyData.Wpa.PskLen,
                                            eapol_parsed->nonce, /* supplicant nonce */
                                            eapol_parsed->key_version,
                                            akm, cipher, ptk, &ptk_len);
            }
            if (ret) {
                /* Unsuccessful PTK derivation */
                continue;
            }
            DEBUG_DUMP("TK", DOT11DECRYPT_GET_TK(ptk, akm), Dot11DecryptGetTkLen(cipher) / 8,
                       LOG_LEVEL_DEBUG);

            ret = Dot11DecryptRsnaMicCheck(eapol_parsed,
                                           eapol, /* eapol frame (header also) */
                                           tot_len, /* eapol frame length */
                                           DOT11DECRYPT_GET_KCK(ptk, akm),
                                           eapol_parsed->key_version,
                                           akm);
            /* If the MIC is valid, the Authenticator checks that the RSN information element bit-wise matches   */
            /* that from the (Re)Association Request message.                                                    */
            /*     i) TODO If these are not exactly the same, the Authenticator uses MLME-DEAUTHENTICATE.request */
            /* primitive to terminate the association.                                                           */
            /*     ii) If they do match bit-wise, the Authenticator constructs Message 3.                        */

            if (ret == DOT11DECRYPT_RET_SUCCESS) {
                /* the key is the correct one, cache it in the Security Association */
                sa->key = tmp_key;
                break;
            }
        }

        if (ret) {
            ws_debug("handshake step failed");
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }
        sa->wpa.key_ver = eapol_parsed->key_version;
        sa->wpa.akm = akm;
        sa->wpa.cipher = cipher;
        sa->wpa.tmp_group_cipher = group_cipher;
        memcpy(sa->wpa.ptk, ptk, ptk_len);
        sa->wpa.ptk_len = (int)ptk_len;
        sa->handshake = 2;
        sa->validKey = true; /* we can use the key to decode, even if we have not captured the other eapol packets */

        return DOT11DECRYPT_RET_SUCCESS_HANDSHAKE;
    }

    /* message 3: Authenticator->Supplicant (Sec=1, Mic=1, Ack=1, Inst=0/1, Key=1(pairwise), KeyRSC=???, Nonce=ANonce, MIC=1) */
    if (eapol_parsed->msg_type == DOT11DECRYPT_HS_MSG_TYPE_4WHS_3) {
        ws_debug("4-way handshake message 3");

        /* On reception of Message 3, the Supplicant silently discards the message if the Key Replay Counter field     */
        /* value has already been used or if the ANonce value in Message 3 differs from the ANonce value in Message 1. */
        /* -> not checked, the Authenticator will send another message 3 (hopefully!)                                  */

        /* TODO check page 88 (RNS) */

        /* If using WPA2 PSK, message 3 will contain an RSN for the group key (GTK KDE).
           In order to properly support decrypting WPA2-PSK packets, we need to parse this to get the group key. */
        if (eapol_parsed->key_type == DOT11DECRYPT_RSN_WPA2_KEY_DESCRIPTOR) {
            return Dot11DecryptCopyBroadcastKey(ctx, eapol_parsed->gtk, eapol_parsed->gtk_len, id);
       }
    }

    /* message 4 */
    if (eapol_parsed->msg_type == DOT11DECRYPT_HS_MSG_TYPE_4WHS_4) {
        /* TODO "Note that when the 4-Way Handshake is first used Message 4 is sent in the clear." */

        /* TODO check MIC and Replay Counter                                                                     */
        /* On reception of Message 4, the Authenticator verifies that the Key Replay Counter field value is one  */
        /* that it used on this 4-Way Handshake; if it is not, it silently discards the message.                 */
        /* If the calculated MIC does not match the MIC that the Supplicant included in the EAPOL-Key frame, the */
        /* Authenticator silently discards Message 4.                                                            */

        ws_debug("4-way handshake message 4");
        return DOT11DECRYPT_RET_SUCCESS_HANDSHAKE;
    }
    return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
}

/* Refer to IEEE 802.11-2016 Chapeter 13.8 FT authentication sequence */
int
Dot11DecryptScanFtAssocForKeys(
    const PDOT11DECRYPT_CONTEXT ctx,
    const PDOT11DECRYPT_ASSOC_PARSED assoc_parsed,
    uint8_t *decrypted_gtk, size_t *decrypted_len,
    DOT11DECRYPT_KEY_ITEM* used_key)
{
    DOT11DECRYPT_SEC_ASSOCIATION_ID id;

    ws_debug("(Re)Association packet");

    if (!ctx || !assoc_parsed) {
        ws_warning("Invalid input parameters");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }
    if (!Dot11DecryptIsFtAkm(assoc_parsed->akm)) {
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }
    if (!assoc_parsed->fte.anonce || !assoc_parsed->fte.snonce) {
        ws_debug("ANonce or SNonce missing");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }

    switch (assoc_parsed->frame_subtype) {
        case DOT11DECRYPT_SUBTYPE_ASSOC_REQ:
        case DOT11DECRYPT_SUBTYPE_REASSOC_REQ:
            memcpy(id.sta, assoc_parsed->sa, DOT11DECRYPT_MAC_LEN);
            break;
        case DOT11DECRYPT_SUBTYPE_ASSOC_RESP:
        case DOT11DECRYPT_SUBTYPE_REASSOC_RESP:
            memcpy(id.sta, assoc_parsed->da, DOT11DECRYPT_MAC_LEN);
            break;
        default:
            ws_warning("Invalid frame subtype");
            return DOT11DECRYPT_RET_UNSUCCESS;
    }
    memcpy(id.bssid, assoc_parsed->bssid, DOT11DECRYPT_MAC_LEN);

    DOT11DECRYPT_KEY_ITEM *tmp_key, *tmp_pkt_key, pkt_key;
    DOT11DECRYPT_SEC_ASSOCIATION *sa;
    size_t key_index;
    unsigned ret = 1;
    bool useCache = false;

    sa = Dot11DecryptNewSa(&id);
    if (sa == NULL) {
        ws_warning("Failed to alloc sa");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }

    memcpy(sa->wpa.nonce, assoc_parsed->fte.anonce, 32);

    if (sa->key != NULL) {
        useCache = true;
    }

    uint8_t ptk[DOT11DECRYPT_WPA_PTK_MAX_LEN];
    size_t ptk_len;

    /* now you can derive the PTK */
    for (key_index = 0; key_index < ctx->keys_nr || useCache; key_index++) {
        /* use the cached one, or try all keys */
        if (useCache && Dot11DecryptIsWpaKeyType(sa->key->KeyType)) {
            ws_debug("Try cached WPA key...");
            tmp_key = sa->key;
            /* Step back loop counter as cached key is used instead */
            key_index--;
        } else {
            ws_debug("Try WPA key...");
            tmp_key = &ctx->keys[key_index];
        }
        useCache = false;

        /* Try only WPA keys... */
        if (!Dot11DecryptIsWpaKeyType(tmp_key->KeyType)) {
            continue;
        }
        if (tmp_key->KeyType == DOT11DECRYPT_KEY_TYPE_WPA_PWD &&
            Dot11DecryptIsPwdWildcardSsid(ctx, tmp_key))
        {
            /* We have a "wildcard" SSID.  Use the one from the packet. */
            memcpy(&pkt_key, tmp_key, sizeof(pkt_key));
            memcpy(&pkt_key.UserPwd.Ssid, ctx->pkt_ssid, ctx->pkt_ssid_len);
            pkt_key.UserPwd.SsidLen = ctx->pkt_ssid_len;
            Dot11DecryptRsnaPwd2Psk(&pkt_key.UserPwd, pkt_key.KeyData.Wpa.Psk);
            tmp_pkt_key = &pkt_key;
        } else {
            tmp_pkt_key = tmp_key;
        }

        if (tmp_pkt_key->KeyType == DOT11DECRYPT_KEY_TYPE_MSK) {
            Dot11DecryptDerivePmkFromMsk(tmp_pkt_key->Msk.Msk, tmp_pkt_key->Msk.Len,
                                         assoc_parsed->akm,
                                         tmp_pkt_key->KeyData.Wpa.Psk,
                                         &tmp_pkt_key->KeyData.Wpa.PskLen);
        }

        ret = Dot11DecryptFtDerivePtk(ctx, sa, tmp_pkt_key,
                                      assoc_parsed->mdid,
                                      assoc_parsed->fte.snonce,
                                      assoc_parsed->fte.r0kh_id,
                                      assoc_parsed->fte.r0kh_id_len,
                                      assoc_parsed->fte.r1kh_id,
                                      assoc_parsed->fte.r1kh_id_len,
                                      assoc_parsed->akm, assoc_parsed->cipher,
                                      ptk, &ptk_len);
        if (ret != DOT11DECRYPT_RET_SUCCESS) {
            continue;
        }
        DEBUG_DUMP("TK", DOT11DECRYPT_GET_TK(ptk, assoc_parsed->akm),
                   Dot11DecryptGetTkLen(assoc_parsed->cipher) / 8,
                   LOG_LEVEL_DEBUG);

        ret = Dot11DecryptFtMicCheck(assoc_parsed,
                                     DOT11DECRYPT_GET_KCK(ptk, assoc_parsed->akm),
                                     Dot11DecryptGetKckLen(assoc_parsed->akm) / 8);
        if (ret == DOT11DECRYPT_RET_SUCCESS) {
            /* the key is the correct one, cache it in the Security Association */
            sa->key = tmp_key;
            break;
        }
    }

    if (ret) {
        ws_debug("handshake step failed");
        g_free(sa);
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }
    sa = Dot11DecryptAddSa(ctx, &id, sa);

    sa->wpa.key_ver = 0; /* Determine key type from akms and cipher*/
    sa->wpa.akm = assoc_parsed->akm;
    sa->wpa.cipher = assoc_parsed->cipher;
    sa->wpa.tmp_group_cipher = assoc_parsed->group_cipher;
    memcpy(sa->wpa.ptk, ptk, ptk_len);
    sa->wpa.ptk_len = (int)ptk_len;
    sa->validKey = true;

    if (assoc_parsed->gtk && assoc_parsed->gtk_len - 8 <= DOT11DECRYPT_WPA_PTK_MAX_LEN - 32) {
        uint8_t decrypted_key[DOT11DECRYPT_WPA_PTK_MAX_LEN - 32];
        uint16_t decrypted_key_len;
        if (AES_unwrap(DOT11DECRYPT_GET_KEK(sa->wpa.ptk, sa->wpa.akm),
                       Dot11DecryptGetKekLen(sa->wpa.akm) / 8,
                       assoc_parsed->gtk, assoc_parsed->gtk_len,
                       decrypted_key, &decrypted_key_len)) {
            return DOT11DECRYPT_RET_UNSUCCESS;
        }
        if (decrypted_key_len != assoc_parsed->gtk_subelem_key_len) {
            ws_debug("Unexpected GTK length");
            return DOT11DECRYPT_RET_UNSUCCESS;
        }
        Dot11DecryptCopyBroadcastKey(ctx, decrypted_key, decrypted_key_len, &id);
        *decrypted_len = decrypted_key_len;
        memcpy(decrypted_gtk, decrypted_key, decrypted_key_len);
    }
    Dot11DecryptCopyKey(sa, used_key);
    return DOT11DECRYPT_RET_SUCCESS_HANDSHAKE;
}

/* From IEEE 802.11-2016 Table 12-8 Integrity and key-wrap algorithms */
static int
Dot11DecryptGetIntegrityAlgoFromAkm(int akm, int *algo, bool *hmac)
{
    int res = 0;
    switch (akm) {
        case 1:
        case 2:
            *algo = GCRY_MD_SHA1;
            *hmac = true;
            break;
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
            *algo = GCRY_MAC_CMAC_AES;
            *hmac = false;
            break;
        case 11:
        case 18:
            *algo = GCRY_MD_SHA256;
            *hmac = true;
            break;
        case 12:
        case 13:
            *algo = GCRY_MD_SHA384;
            *hmac = true;
            break;
        default:
            /* Unknown / Not supported yet */
            res = -1;
            break;
    }
    return res;
}

static int
Dot11DecryptRsnaMicCheck(
    PDOT11DECRYPT_EAPOL_PARSED eapol_parsed,
    unsigned char *eapol,
    unsigned short eapol_len,
    unsigned char *KCK,
    unsigned short key_ver,
    int akm)
{
    uint8_t *mic = eapol_parsed->mic;
    uint16_t mic_len = eapol_parsed->mic_len;
    uint16_t kck_len = Dot11DecryptGetKckLen(akm) / 8;
    /* MIC 16 or 24 bytes, though HMAC-SHA256 / SHA384 algos need 32 / 48 bytes buffer */
    unsigned char c_mic[48] = { 0 };
    int algo = -1;
    bool hmac = true;

    if (!mic || mic_len > DOT11DECRYPT_WPA_MICKEY_MAX_LEN) {
        ws_debug("Not a valid mic");
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    /* set to 0 the MIC in the EAPOL packet (to calculate the MIC) */
    memset(eapol + DOT11DECRYPT_WPA_MICKEY_OFFSET + 4, 0, mic_len);

    if (key_ver==DOT11DECRYPT_WPA_KEY_VER_NOT_CCMP) {
        /* use HMAC-MD5 for the EAPOL-Key MIC */
        algo = GCRY_MD_MD5;
        hmac = true;
    } else if (key_ver==DOT11DECRYPT_WPA_KEY_VER_AES_CCMP) {
        /* use HMAC-SHA1-128 for the EAPOL-Key MIC */
        algo = GCRY_MD_SHA1;
        hmac = true;
    } else {
        /* Mic check algorithm determined by AKM type */
        if (Dot11DecryptGetIntegrityAlgoFromAkm(akm, &algo, &hmac)) {
            ws_warning("Unknown Mic check algo");
            return DOT11DECRYPT_RET_UNSUCCESS;
        };
    }
    if (hmac) {
        if (ws_hmac_buffer(algo, c_mic, eapol, eapol_len, KCK, kck_len)) {
            ws_debug("HMAC_BUFFER");
            return DOT11DECRYPT_RET_UNSUCCESS;
        }
    } else {
        if (ws_cmac_buffer(algo, c_mic, eapol, eapol_len, KCK, kck_len)) {
            ws_debug("HMAC_BUFFER");
            return DOT11DECRYPT_RET_UNSUCCESS;
        }
    }

    /* compare calculated MIC with the Key MIC and return result (0 means success) */
    DEBUG_DUMP("mic",  mic, mic_len, LOG_LEVEL_DEBUG);
    DEBUG_DUMP("c_mic", c_mic, mic_len, LOG_LEVEL_DEBUG);
    return memcmp(mic, c_mic, mic_len);
}

/* IEEE 802.11-2016 Chapter 13.8.4 FT authentication sequence: contents of third message
 * IEEE 802.11-2016 Chapter 13.8.5 FT authentication sequence: contents of fourth message
 * The MIC shall be calculated on the concatenation of the following data, in the order given here:
 * —
 * — FTO’s MAC address (6 octets)
 * — Target AP’s MAC address (6 octets)
 * If third message:
 * — Transaction sequence number (1 octet), which shall be set to the value 5 if this is a
 *   Reassociation Request frame and, otherwise, set to the value 3
 * If fourth message:
 * — Transaction sequence number (1 octet), which shall be set to the value 6 if this is a
 *   Reassociation Response frame or, otherwise, set to the value 4
 *
 * — RSNE
 * — MDE
 * — FTE, with the MIC field of the FTE set to 0
 * — Contents of the RIC-Response (if present)
 */
static int
Dot11DecryptFtMicCheck(
    const PDOT11DECRYPT_ASSOC_PARSED assoc_parsed,
    const uint8_t *kck,
    size_t kck_len)
{
    uint8_t *sta;
    uint8_t seq_num;
    uint8_t fte_len;
    uint16_t mic_len;
    uint8_t zeros[16] = { 0 };
    gcry_mac_hd_t handle;

    fte_len = assoc_parsed->fte_tag[1] + 2;
    if (fte_len < 20) {
        ws_debug("FTE too short");
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    switch (assoc_parsed->frame_subtype) {
        case DOT11DECRYPT_SUBTYPE_ASSOC_REQ:
            sta = assoc_parsed->sa;
            seq_num = 3;
            break;
        case DOT11DECRYPT_SUBTYPE_ASSOC_RESP:
            sta = assoc_parsed->da;
            seq_num = 4;
            break;
        case DOT11DECRYPT_SUBTYPE_REASSOC_REQ:
            sta = assoc_parsed->sa;
            seq_num = 5;
            break;
        case DOT11DECRYPT_SUBTYPE_REASSOC_RESP:
            sta = assoc_parsed->da;
            seq_num = 6;
            break;
        default:
            return DOT11DECRYPT_RET_UNSUCCESS;
    }

    if (gcry_mac_open(&handle, GCRY_MAC_CMAC_AES, 0, NULL)) {
        ws_warning("gcry_mac_open failed");
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    if (gcry_mac_setkey(handle, kck, kck_len)) {
        ws_warning("gcry_mac_setkey failed");
        gcry_mac_close(handle);
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    gcry_mac_write(handle, sta, DOT11DECRYPT_MAC_LEN);
    gcry_mac_write(handle, assoc_parsed->bssid, DOT11DECRYPT_MAC_LEN);

    gcry_mac_write(handle, &seq_num, 1);

    gcry_mac_write(handle, assoc_parsed->rsne_tag, assoc_parsed->rsne_tag[1] + 2);
    gcry_mac_write(handle, assoc_parsed->mde_tag, assoc_parsed->mde_tag[1] + 2);

    mic_len = assoc_parsed->fte.mic_len;
    gcry_mac_write(handle, assoc_parsed->fte_tag, 4);
    gcry_mac_write(handle, zeros, mic_len); /* MIC zeroed */
    gcry_mac_write(handle, assoc_parsed->fte_tag + 4 + mic_len, fte_len - 4 - mic_len);

    if (assoc_parsed->rde_tag) {
        gcry_mac_write(handle, assoc_parsed->rde_tag, assoc_parsed->rde_tag[1] + 2);
    }

    if (gcry_mac_verify(handle, assoc_parsed->fte.mic, mic_len) != 0) {
        DEBUG_DUMP("MIC", assoc_parsed->fte.mic, mic_len, LOG_LEVEL_DEBUG);
        ws_debug("MIC verification failed");
        gcry_mac_close(handle);
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    DEBUG_DUMP("MIC", assoc_parsed->fte.mic, mic_len, LOG_LEVEL_DEBUG);
    gcry_mac_close(handle);
    return DOT11DECRYPT_RET_SUCCESS;
}

static int
Dot11DecryptValidateKey(
    PDOT11DECRYPT_KEY_ITEM key)
{
    size_t len;
    unsigned char ret=true;

    if (key==NULL) {
        ws_warning("NULL key");
        return false;
    }

    switch (key->KeyType) {
        case DOT11DECRYPT_KEY_TYPE_WEP:
            /* check key size limits */
            len=key->KeyData.Wep.WepKeyLen;
            if (len<DOT11DECRYPT_WEP_KEY_MINLEN || len>DOT11DECRYPT_WEP_KEY_MAXLEN) {
                ws_info("WEP key: key length not accepted");
                ret=false;
            }
            break;

        case DOT11DECRYPT_KEY_TYPE_WEP_40:
            /* set the standard length and use a generic WEP key type */
            key->KeyData.Wep.WepKeyLen=DOT11DECRYPT_WEP_40_KEY_LEN;
            key->KeyType=DOT11DECRYPT_KEY_TYPE_WEP;
            break;

        case DOT11DECRYPT_KEY_TYPE_WEP_104:
            /* set the standard length and use a generic WEP key type */
            key->KeyData.Wep.WepKeyLen=DOT11DECRYPT_WEP_104_KEY_LEN;
            key->KeyType=DOT11DECRYPT_KEY_TYPE_WEP;
            break;

        case DOT11DECRYPT_KEY_TYPE_WPA_PWD:
            /* check passphrase and SSID size limits */
            len=strlen(key->UserPwd.Passphrase);
            if (len<DOT11DECRYPT_WPA_PASSPHRASE_MIN_LEN || len>DOT11DECRYPT_WPA_PASSPHRASE_MAX_LEN) {
                ws_info("WPA-PWD key: passphrase length not accepted");
                ret=false;
            }

            len=key->UserPwd.SsidLen;
            if (len>DOT11DECRYPT_WPA_SSID_MAX_LEN) {
                ws_info("WPA-PWD key: ssid length not accepted");
                ret=false;
            }

            break;

        case DOT11DECRYPT_KEY_TYPE_WPA_PSK:
            break;

        case DOT11DECRYPT_KEY_TYPE_TK:
            break;

        case DOT11DECRYPT_KEY_TYPE_MSK:
            break;

        default:
            ret=false;
    }
    return ret;
}

static int
Dot11DecryptGetSaAddress(
    const DOT11DECRYPT_MAC_FRAME_ADDR4 *frame,
    DOT11DECRYPT_SEC_ASSOCIATION_ID *id)
{
    if ((DOT11DECRYPT_TYPE(frame->fc[0])==DOT11DECRYPT_TYPE_DATA) &&
        (DOT11DECRYPT_DS_BITS(frame->fc[1]) == 0) &&
        (memcmp(frame->addr2, frame->addr3, DOT11DECRYPT_MAC_LEN) != 0) &&
        (memcmp(frame->addr1, frame->addr3, DOT11DECRYPT_MAC_LEN) != 0)) {
        /* DATA frame with fromDS=0 ToDS=0 and neither RA or SA is BSSID
           => TDLS traffic. Use highest MAC address for bssid */
        if (memcmp(frame->addr1, frame->addr2, DOT11DECRYPT_MAC_LEN) < 0) {
            memcpy(id->sta, frame->addr1, DOT11DECRYPT_MAC_LEN);
            memcpy(id->bssid, frame->addr2, DOT11DECRYPT_MAC_LEN);
        } else {
            memcpy(id->sta, frame->addr2, DOT11DECRYPT_MAC_LEN);
            memcpy(id->bssid, frame->addr1, DOT11DECRYPT_MAC_LEN);
        }
    } else {
        const unsigned char *addr;

        /* Normal Case: SA between STA and AP */
        if ((addr = Dot11DecryptGetBssidAddress(frame)) != NULL) {
            memcpy(id->bssid, addr, DOT11DECRYPT_MAC_LEN);
        } else {
            return DOT11DECRYPT_RET_UNSUCCESS;
        }

        if ((addr = Dot11DecryptGetStaAddress(frame)) != NULL) {
            memcpy(id->sta, addr, DOT11DECRYPT_MAC_LEN);
        } else {
            return DOT11DECRYPT_RET_UNSUCCESS;
        }
    }
    ws_noisy("BSSID_MAC: %02X.%02X.%02X.%02X.%02X.%02X\t",
             id->bssid[0],id->bssid[1],id->bssid[2],id->bssid[3],id->bssid[4],id->bssid[5]);
    ws_noisy("STA_MAC: %02X.%02X.%02X.%02X.%02X.%02X\t",
             id->sta[0],id->sta[1],id->sta[2],id->sta[3],id->sta[4],id->sta[5]);

    return DOT11DECRYPT_RET_SUCCESS;
}

/*
 * Dot11DecryptGetBssidAddress() and Dot11DecryptGetBssidAddress() are used for
 * key caching.  In each case, it's more important to return a value than
 * to return a _correct_ value, so we fudge addresses in some cases, e.g.
 * the BSSID in bridged connections.
 * FromDS    ToDS   Sta      BSSID
 * 0         0      addr1/2  addr3
 * 0         1      addr2    addr1
 * 1         0      addr1    addr2
 * 1         1      addr2    addr1
 */

static const unsigned char *
Dot11DecryptGetStaAddress(
    const DOT11DECRYPT_MAC_FRAME_ADDR4 *frame)
{
    switch(DOT11DECRYPT_DS_BITS(frame->fc[1])) { /* Bit 1 = FromDS, bit 0 = ToDS */
        case 0:
            if (memcmp(frame->addr2, frame->addr3, DOT11DECRYPT_MAC_LEN) == 0)
                return frame->addr1;
            else
                return frame->addr2;
        case 1:
            return frame->addr2;
        case 2:
            return frame->addr1;
        case 3:
            if (memcmp(frame->addr1, frame->addr2, DOT11DECRYPT_MAC_LEN) < 0)
                return frame->addr1;
            else
                return frame->addr2;

        default:
            return NULL;
    }
}

static const unsigned char *
Dot11DecryptGetBssidAddress(
    const DOT11DECRYPT_MAC_FRAME_ADDR4 *frame)
{
    switch(DOT11DECRYPT_DS_BITS(frame->fc[1])) { /* Bit 1 = FromDS, bit 0 = ToDS */
        case 0:
            return frame->addr3;
        case 1:
            return frame->addr1;
        case 2:
            return frame->addr2;
        case 3:
            if (memcmp(frame->addr1, frame->addr2, DOT11DECRYPT_MAC_LEN) > 0)
                return frame->addr1;
            else
                return frame->addr2;

        default:
            return NULL;
    }
}

/* From IEEE 802.11-2016 Table 9-131 Cipher suite selectors and
 * Table 12-4 Cipher suite key lengths */
static int Dot11DecryptGetTkLen(int cipher)
{
    switch (cipher) {
        case 1: return 40;   /* WEP-40 */
        case 2: return 256;  /* TKIP */
        case 3: return -1;   /* Reserved */
        case 4: return 128;  /* CCMP-128 */
        case 5: return 104;  /* WEP-104 */
        case 6: return 128;  /* BIP-CMAC-128 */
        case 7: return -1;   /* Group addressed traffic not allowed */
        case 8: return 128;  /* GCMP-128 */
        case 9: return 256;  /* GCMP-256 */
        case 10: return 256; /* CCMP-256 */
        case 11: return 128; /* BIP-GMAC-128 */
        case 12: return 256; /* BIP-GMAC-256 */
        case 13: return 256; /* BIP-CMAC-256 */
        default:
            ws_warning("Unknown cipher");
            return -1;
    }
}

/* From IEEE 802.11-2016 Table 12-8 Integrity and key-wrap algorithms */
static int Dot11DecryptGetKckLen(int akm)
{
    switch (akm) {
        case 1: return 128;
        case 2: return 128;
        case 3: return 128;
        case 4: return 128;
        case 5: return 128;
        case 6: return 128;
        case 8: return 128;
        case 9: return 128;
        case 11: return 128;
        case 12: return 192;
        case 13: return 192;
        case 18: return 128;
        default:
            /* Unknown / Not supported */
            ws_warning("Unknown akm");
            return -1;
    }
}

/* From IEEE 802.11-2016 Table 12-8 Integrity and key-wrap algorithms */
static int Dot11DecryptGetKekLen(int akm)
{
    switch (akm) {
        case 1: return 128;
        case 2: return 128;
        case 3: return 128;
        case 4: return 128;
        case 5: return 128;
        case 6: return 128;
        case 8: return 128;
        case 9: return 128;
        case 11: return 128;
        case 12: return 256;
        case 13: return 256;
        case 18: return 128;
        default:
            /* Unknown / Not supported */
            ws_warning("Unknown akm");
            return -1;
    }
}

/* From IEEE 802.11-2016 9.4.2.25.3 AKM suites and
 * Table 12-8 Integrity and key-wrap algorithms */
static int Dot11DecryptGetPtkLen(int akm, int cipher)
{
    int kck_len = Dot11DecryptGetKckLen(akm);
    int kek_len = Dot11DecryptGetKekLen(akm);
    int tk_len = Dot11DecryptGetTkLen(cipher);

    if (kck_len == -1 || kek_len == -1 || tk_len == -1) {
        ws_warning("Invalid PTK len");
        return -1;
    }
    return kck_len + kek_len + tk_len;
}

/* From IEEE 802.11-2016 12.7.1.2 PRF and Table 9-133 AKM suite selectors */
static int
Dot11DecryptGetDeriveFuncFromAkm(int akm)
{
    int func = -1;
    switch (akm) {
        case 1:
        case 2:
            func = DOT11DECRYPT_DERIVE_USING_PRF;
            break;
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
        case 11:
        case 12:
        case 13:
        case 18:
            func = DOT11DECRYPT_DERIVE_USING_KDF;
            break;
        default:
            /* Unknown / Not supported yet */
            break;
    }
    return func;
}

/* From IEEE 802.11-2016 12.7.1.2 PRF and Table 9-133 AKM suite selectors */
static int
Dot11DecryptGetHashAlgoFromAkm(int akm)
{
    int algo = -1;
    switch (akm) {
        case 1:
        case 2:
            algo = GCRY_MD_SHA1;
            break;
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
        case 11:
        case 18:
            algo = GCRY_MD_SHA256;
            break;
        case 12:
        case 13:
            algo = GCRY_MD_SHA384;
            break;
        default:
            /* Unknown / Not supported yet */
            break;
    }
    return algo;
}

/* derive the PTK from the BSSID, STA MAC, PMK, SNonce, ANonce */
/** From IEEE 802.11-2016 12.7.1.3 Pairwise key hierarchy:
 *  PRF-Length(PMK, "Pairwise key expansion",
 *      Min(AA, SPA) || Max(AA, SPA) ||
 *      Min(ANonce, SNonce) || Max(ANonce, SNonce))
 */
static uint8_t
Dot11DecryptDerivePtk(
    const DOT11DECRYPT_SEC_ASSOCIATION *sa,
    const unsigned char *pmk,
    size_t pmk_len,
    const unsigned char snonce[32],
    int key_version,
    int akm,
    int cipher,
    uint8_t *ptk, size_t *ptk_len)
{
    int algo = -1;
    int ptk_len_bits = -1;
    int derive_func;

    if (!sa || !pmk || !snonce || !ptk || !ptk_len) {
        ws_warning("Invalid input for PTK derivation");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }

    if (key_version == DOT11DECRYPT_WPA_KEY_VER_NOT_CCMP) {
        /* TKIP */
        ptk_len_bits = 512;
        derive_func = DOT11DECRYPT_DERIVE_USING_PRF;
        algo = GCRY_MD_SHA1;
    } else {
        /* From IEEE 802.11-2016 Table 12-8 Integrity and key-wrap algorithms */
        ptk_len_bits = Dot11DecryptGetPtkLen(akm, cipher);
        algo = Dot11DecryptGetHashAlgoFromAkm(akm);
        derive_func = Dot11DecryptGetDeriveFuncFromAkm(akm);
        ws_debug("ptk_len_bits: %d, algo: %d, cipher: %d", ptk_len_bits, algo, cipher);
    }

    if (ptk_len_bits == -1 || algo == -1) {
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }
    *ptk_len = ptk_len_bits / 8;

    static const char *const label = "Pairwise key expansion";
    uint8_t context[DOT11DECRYPT_MAC_LEN * 2 + 32 * 2];
    int offset = 0;

    /* Min(AA, SPA) || Max(AA, SPA) */
    if (memcmp(sa->saId.sta, sa->saId.bssid, DOT11DECRYPT_MAC_LEN) < 0)
    {
        memcpy(context + offset, sa->saId.sta, DOT11DECRYPT_MAC_LEN);
        offset += DOT11DECRYPT_MAC_LEN;
        memcpy(context + offset, sa->saId.bssid, DOT11DECRYPT_MAC_LEN);
        offset += DOT11DECRYPT_MAC_LEN;
    }
    else
    {
        memcpy(context + offset, sa->saId.bssid, DOT11DECRYPT_MAC_LEN);
        offset += DOT11DECRYPT_MAC_LEN;
        memcpy(context + offset, sa->saId.sta, DOT11DECRYPT_MAC_LEN);
        offset += DOT11DECRYPT_MAC_LEN;
    }

    /* Min(ANonce, SNonce) || Max(ANonce, SNonce) */
    if (memcmp(snonce, sa->wpa.nonce, 32) < 0 )
    {
        memcpy(context + offset, snonce, 32);
        offset += 32;
        memcpy(context + offset, sa->wpa.nonce, 32);
        offset += 32;
    }
    else
    {
        memcpy(context + offset, sa->wpa.nonce, 32);
        offset += 32;
        memcpy(context + offset, snonce, 32);
        offset += 32;
    }
    if (derive_func == DOT11DECRYPT_DERIVE_USING_PRF) {
        dot11decrypt_prf(pmk, pmk_len, label, context, offset, algo,
                         ptk, *ptk_len);
    } else {
        dot11decrypt_kdf(pmk, pmk_len, label, context, offset, algo,
                         ptk, *ptk_len);
    }
    DEBUG_DUMP("PTK", ptk, *ptk_len, LOG_LEVEL_DEBUG);
    return DOT11DECRYPT_RET_SUCCESS;
}

/**
 * For Fast BSS Transition AKMS derive PTK from sa, selected key and various information in
 * eapol key frame.
 * From IEEE 802.11-2016 12.7.1.7.1
 */
static uint8_t
Dot11DecryptFtDerivePtk(
    const PDOT11DECRYPT_CONTEXT ctx,
    const DOT11DECRYPT_SEC_ASSOCIATION *sa,
    const PDOT11DECRYPT_KEY_ITEM key,
    const uint8_t mdid[2],
    const uint8_t *snonce,
    const uint8_t *r0kh_id, size_t r0kh_id_len,
    const uint8_t *r1kh_id, size_t r1kh_id_len _U_,
    int akm, int cipher,
    uint8_t *ptk, size_t *ptk_len)
{
    int hash_algo = Dot11DecryptGetHashAlgoFromAkm(akm);
    uint8_t pmk_r0[DOT11DECRYPT_WPA_PMK_MAX_LEN];
    uint8_t pmk_r1[DOT11DECRYPT_WPA_PMK_MAX_LEN];
    uint8_t pmk_r0_name[16] = {0};
    uint8_t pmk_r1_name[16] = {0};
    uint8_t ptk_name[16];
    size_t pmk_r0_len = 0;
    size_t pmk_r1_len = 0;
    const uint8_t *xxkey = NULL;
    size_t xxkey_len;
    int ptk_len_bits;

    if (!sa || !key || !mdid || !snonce || !r0kh_id || !r1kh_id || !ptk || !ptk_len) {
        ws_warning("Invalid input for FT PTK derivation");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }
    ptk_len_bits = Dot11DecryptGetPtkLen(akm, cipher);
    if (ptk_len_bits == -1) {
        ws_warning("Invalid akm or cipher");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }
    *ptk_len = ptk_len_bits / 8;

    if (key->KeyType == DOT11DECRYPT_KEY_TYPE_MSK) {
        xxkey = Dot11DecryptGetXXKeyFromMSK(key->Msk.Msk,
                                            key->Msk.Len,
                                            akm,
                                            &xxkey_len);
    }
    if (!xxkey && key->KeyData.Wpa.PskLen > 0) {
        xxkey = key->KeyData.Wpa.Psk;
        xxkey_len = key->KeyData.Wpa.PskLen;
    }
    if (!xxkey) {
        ws_debug("no xxkey. Skipping");
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }
    if (!dot11decrypt_derive_pmk_r0(xxkey, xxkey_len,
                               ctx->pkt_ssid, ctx->pkt_ssid_len,
                               mdid,
                               r0kh_id, r0kh_id_len,
                               sa->saId.sta, hash_algo,
                               pmk_r0, &pmk_r0_len, pmk_r0_name)) {
        /* This can fail for bad size or a bad SHA256 sum. */
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    DEBUG_DUMP("PMK-R0", pmk_r0, pmk_r0_len, LOG_LEVEL_DEBUG);
    DEBUG_DUMP("PMKR0Name", pmk_r0_name, 16, LOG_LEVEL_DEBUG);

    if (!dot11decrypt_derive_pmk_r1(pmk_r0, pmk_r0_len, pmk_r0_name,
                               r1kh_id, sa->saId.sta, hash_algo,
                               pmk_r1, &pmk_r1_len, pmk_r1_name)) {
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    DEBUG_DUMP("PMK-R1", pmk_r1, pmk_r1_len, LOG_LEVEL_DEBUG);
    DEBUG_DUMP("PMKR1Name", pmk_r1_name, 16, LOG_LEVEL_DEBUG);

    if (!dot11decrypt_derive_ft_ptk(pmk_r1, pmk_r1_len, pmk_r1_name,
                               snonce, sa->wpa.nonce,
                               sa->saId.bssid, sa->saId.sta, hash_algo,
                               ptk, *ptk_len, ptk_name)) {
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    DEBUG_DUMP("PTK", ptk, *ptk_len, LOG_LEVEL_DEBUG);
    return DOT11DECRYPT_RET_SUCCESS;
}

#define MAX_SSID_LENGTH 32 /* maximum SSID length */

static int
Dot11DecryptRsnaPwd2PskStep(
    const uint8_t *ppBytes,
    const unsigned ppLength,
    const char *ssid,
    const size_t ssidLength,
    const int iterations,
    const int count,
    unsigned char *output)
{
    unsigned char digest[MAX_SSID_LENGTH+4] = { 0 };  /* SSID plus 4 bytes of count */
    int i, j;

    if (ssidLength > MAX_SSID_LENGTH) {
        /* This "should not happen" */
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    /* U1 = PRF(P, S || int(i)) */
    memcpy(digest, ssid, ssidLength);
    digest[ssidLength] = (unsigned char)((count>>24) & 0xff);
    digest[ssidLength+1] = (unsigned char)((count>>16) & 0xff);
    digest[ssidLength+2] = (unsigned char)((count>>8) & 0xff);
    digest[ssidLength+3] = (unsigned char)(count & 0xff);
    if (ws_hmac_buffer(GCRY_MD_SHA1, digest, digest, (uint32_t) ssidLength + 4, ppBytes, ppLength)) {
      return DOT11DECRYPT_RET_UNSUCCESS;
    }

    /* output = U1 */
    memcpy(output, digest, 20);
    for (i = 1; i < iterations; i++) {
        /* Un = PRF(P, Un-1) */
        if (ws_hmac_buffer(GCRY_MD_SHA1, digest, digest, HASH_SHA1_LENGTH, ppBytes, ppLength)) {
          return DOT11DECRYPT_RET_UNSUCCESS;
        }

        /* output = output xor Un */
        for (j = 0; j < 20; j++) {
            output[j] ^= digest[j];
        }
    }

    return DOT11DECRYPT_RET_SUCCESS;
}

static int
Dot11DecryptRsnaPwd2Psk(
    const struct DOT11DECRYPT_KEY_ITEMDATA_PWD *userPwd,
    unsigned char *output)
{
    unsigned char m_output[40] = { 0 };
    GByteArray *pp_ba = g_byte_array_new();

    g_byte_array_append(pp_ba, userPwd->Passphrase, (unsigned)userPwd->PassphraseLen);

    Dot11DecryptRsnaPwd2PskStep(pp_ba->data, pp_ba->len, userPwd->Ssid, userPwd->SsidLen, 4096, 1, m_output);
    Dot11DecryptRsnaPwd2PskStep(pp_ba->data, pp_ba->len, userPwd->Ssid, userPwd->SsidLen, 4096, 2, &m_output[20]);

    memcpy(output, m_output, DOT11DECRYPT_WPA_PWD_PSK_LEN);
    g_byte_array_free(pp_ba, true);

    return 0;
}

/*
 * Returns the decryption_key_t struct given a string describing the key.
 * Returns NULL if the input_string cannot be parsed.
 * XXX: Should return an error string explaining why parsing failed
 */
decryption_key_t*
parse_key_string(char* input_string, uint8_t key_type, char** error)
{
    GByteArray *ssid_ba = NULL, *key_ba;

    char **tokens;
    unsigned n = 0;
    decryption_key_t *dk;

    if(input_string == NULL || (strcmp(input_string, "") == 0)) {
        if (error) {
            *error = g_strdup("Key cannot be empty");
        }
        return NULL;
    }

    /*
     * Parse the input_string. WEP and WPA will be just a string
     * of hexadecimal characters (if key is wrong, null will be
     * returned...).
     * WPA-PWD should be in the form
     * <key data>[:<ssid>]
     * With WPA-PWD, we percent-decode the key data and ssid.
     * The percent itself ("%25") and the colon ("%3a") must be
     * percent-encoded, the latter so we can distinguish between the
     * separator and a colon in the key or ssid. Percent-encoding
     * for anything else is optional. (NUL is not allowed, either
     * percent-encoded or not.)
     */

    switch(key_type)
    {
    case DOT11DECRYPT_KEY_TYPE_WEP:
    case DOT11DECRYPT_KEY_TYPE_WEP_40:
    case DOT11DECRYPT_KEY_TYPE_WEP_104:

        key_ba = g_byte_array_new();

        if (!hex_str_to_bytes(input_string, key_ba, false)) {
            if (error) {
                *error = g_strdup("WEP key must be a hexadecimal string");
            }
            g_byte_array_free(key_ba, true);
            return NULL;
        }

        if (key_ba->len > 0 && key_ba->len <= DOT11DECRYPT_WEP_KEY_MAXLEN) {
            /* Key is correct! It was probably an 'old style' WEP key */
            /* Create the decryption_key_t structure, fill it and return it*/
            dk = g_new(decryption_key_t, 1);

            dk->type = DOT11DECRYPT_KEY_TYPE_WEP;
            dk->key  = key_ba;
            dk->bits = key_ba->len * 8;
            dk->ssid = NULL;

            return dk;
        }

        if (error) {
            *error = ws_strdup_printf("WEP key entered is %u bytes, and must be no more than %u", key_ba->len, DOT11DECRYPT_WEP_KEY_MAXLEN);
        }
        /* Key doesn't work */
        g_byte_array_free(key_ba, true);
        return NULL;

    case DOT11DECRYPT_KEY_TYPE_WPA_PWD:

        tokens = g_strsplit(input_string,":", 3);
        n = g_strv_length(tokens);

        if (n < 1 || n > 2)
        {
            /* Require either one or two tokens; more, and the user
             * may have meant a colon in the passphrase or SSID name
             */
            /* Free the array of strings */
            /* XXX: Return why parsing failed (":" must be escaped) */
            if (error) {
                *error = g_strdup("Only one ':' is allowed, as a separator between passphrase and SSID; others must be percent-encoded as \"%%3a\"");
            }
            g_strfreev(tokens);
            return NULL;
        }

        /*
         * The first token is the key
         */
        key_ba = g_byte_array_new();
        if (! uri_str_to_bytes(tokens[0], key_ba)) {
            /* Failed parsing as percent-encoded */
            if (error) {
                *error = g_strdup("WPA passphrase is treated as percent-encoded; use \"%%25\" for a literal \"%%\"");
            }
            g_byte_array_free(key_ba, true);
            g_strfreev(tokens);
            return NULL;
        }

        /* key length (after percent-decoding) should be between 8 and 63
         * octets (63 to distinguish from a PSK as 64 hex characters.)
         * XXX: 802.11-2016 Annex J assumes that each character in the
         * pass-phrase is ASCII printable ("has an encoding in the range
         * 32 to 126"), though this (and the entire algorithm for that
         * matter) is only considered a suggestion.
         * It is possible to apply PBKDF2 to any octet string, e.g. UTF-8.
         * (wpa_passphrase from wpa_supplicant will do so, for example.)
         */
        if( ((key_ba->len) > WPA_KEY_MAX_CHAR_SIZE) || ((key_ba->len) < WPA_KEY_MIN_CHAR_SIZE))
        {
            if (error) {
                *error = ws_strdup_printf("WPA passphrase entered is %u characters after percent-decoding and must be between %u and %u", key_ba->len, WPA_KEY_MIN_CHAR_SIZE, WPA_KEY_MAX_CHAR_SIZE);
            }
            g_byte_array_free(key_ba, true);

            /* Free the array of strings */
            g_strfreev(tokens);
            return NULL;
        }

        ssid_ba = NULL;
        if (n >= 2) /* more than two tokens found, means that the user specified the ssid */
        {
            ssid_ba = g_byte_array_new();
            if (! uri_str_to_bytes(tokens[1], ssid_ba)) {
                if (error) {
                    *error = g_strdup("WPA SSID is treated as percent-encoded; use \"%%25\" for a literal \"%%\".");
                }
                g_byte_array_free(key_ba, true);
                g_byte_array_free(ssid_ba, true);
                /* Free the array of strings */
                g_strfreev(tokens);
                return NULL;
            }

            if(ssid_ba->len > WPA_SSID_MAX_CHAR_SIZE)
            {
                if (error) {
                    *error = ws_strdup_printf("WPA SSID entered is %u characters after percent-decoding and must be no more than %u", ssid_ba->len, WPA_SSID_MAX_CHAR_SIZE);
                }
                g_byte_array_free(key_ba, true);
                g_byte_array_free(ssid_ba, true);

                /* Free the array of strings */
                g_strfreev(tokens);
                return NULL;
            }
        }

        /* Key was correct!!! Create the new decryption_key_t ... */
        dk = g_new(decryption_key_t, 1);

        dk->type = DOT11DECRYPT_KEY_TYPE_WPA_PWD;
        dk->key  = key_ba;
        dk->bits = 256; /* This is the length of the array pf bytes that will be generated using key+ssid ...*/
        dk->ssid = ssid_ba; /* NULL if ssid_ba is NULL */

        /* Free the array of strings */
        g_strfreev(tokens);
        return dk;

    case DOT11DECRYPT_KEY_TYPE_WPA_PSK:

        key_ba = g_byte_array_new();
        if (!hex_str_to_bytes(input_string, key_ba, false)) {
            if (error) {
                *error = g_strdup("WPA PSK/PMK must be a hexadecimal string");
            }
            g_byte_array_free(key_ba, true);
            return NULL;
        }

        /* Two tokens means that the user should have entered a WPA-BIN key ... */
        if((key_ba->len != DOT11DECRYPT_WPA_PWD_PSK_LEN &&
                     key_ba->len != DOT11DECRYPT_WPA_PMK_MAX_LEN))
        {
            if (error) {
                *error = ws_strdup_printf("WPA Pre-Master Key/Pairwise Master Key entered is %u bytes and must be %u or %u", key_ba->len, DOT11DECRYPT_WPA_PWD_PSK_LEN, DOT11DECRYPT_WPA_PMK_MAX_LEN);
            }
            g_byte_array_free(key_ba, true);
            return NULL;
        }

        /* Key was correct!!! Create the new decryption_key_t ... */
        dk = g_new(decryption_key_t, 1);

        dk->type = DOT11DECRYPT_KEY_TYPE_WPA_PSK;
        dk->key  = key_ba;
        dk->bits = (unsigned) dk->key->len * 8;
        dk->ssid = NULL;

        return dk;

    case DOT11DECRYPT_KEY_TYPE_TK:
        {
            /* From IEEE 802.11-2016 Table 12-4 Cipher suite key lengths */
            static const uint8_t allowed_key_lengths[] = {
// TBD          40 / 8,  /* WEP-40 */
// TBD          104 / 8, /* WEP-104 */
                128 / 8, /* CCMP-128, GCMP-128 */
                256 / 8, /* TKIP, GCMP-256, CCMP-256 */
            };
            bool key_length_ok = false;

            key_ba = g_byte_array_new();
            if (!hex_str_to_bytes(input_string, key_ba, false)) {
                if (error) {
                    *error = g_strdup("Temporal Key must be a hexadecimal string");
                }
                g_byte_array_free(key_ba, true);
                return NULL;
            }

            for (size_t i = 0; i < sizeof(allowed_key_lengths); i++) {
                if (key_ba->len == allowed_key_lengths[i]) {
                    key_length_ok = true;
                    break;
                }
            }
            if (!key_length_ok) {
                if (error) {
                    GString *err_string = g_string_new("Temporal Keys entered is ");
                    g_string_append_printf(err_string, "%u bytes and must be ", key_ba->len);
                    size_t i = 0;
                    for (; i + 1 < sizeof(allowed_key_lengths); i++) {
                        g_string_append_printf(err_string, "%u, ", allowed_key_lengths[i]);
                    }
                    g_string_append_printf(err_string, "or %u bytes.", allowed_key_lengths[i]);
                    *error = g_string_free(err_string, FALSE);
                }
                g_byte_array_free(key_ba, true);
                return NULL;
            }
            dk = g_new(decryption_key_t, 1);
            dk->type = DOT11DECRYPT_KEY_TYPE_TK;
            dk->key  = key_ba;
            dk->bits = (unsigned) dk->key->len * 8;
            dk->ssid = NULL;

            return dk;
        }
    case DOT11DECRYPT_KEY_TYPE_MSK:
        {
            key_ba = g_byte_array_new();
            if (!hex_str_to_bytes(input_string, key_ba, false)) {
                if (error) {
                    *error = g_strdup("Master Session Key must be a hexadecimal string");
                }
                g_byte_array_free(key_ba, true);
                return NULL;
            }

            if (key_ba->len < DOT11DECRYPT_MSK_MIN_LEN ||
                key_ba->len > DOT11DECRYPT_MSK_MAX_LEN)
            {
                if (error) {
                    *error = ws_strdup_printf("Master Session Key entered is %u bytes and must be between %u and %u", key_ba->len, DOT11DECRYPT_MSK_MIN_LEN, DOT11DECRYPT_MSK_MAX_LEN);
                }
                g_byte_array_free(key_ba, true);
                return NULL;
            }
            dk = g_new(decryption_key_t, 1);
            dk->type = DOT11DECRYPT_KEY_TYPE_MSK;
            dk->key  = key_ba;
            dk->bits = (unsigned)dk->key->len * 8;
            dk->ssid = NULL;
            return dk;
        }
    }

    /* Type not supported */
    if (error) {
        *error = g_strdup("Unknown key type not supported");
    }
    return NULL;
}

void
free_key_string(decryption_key_t *dk)
{
    if (dk->key)
        g_byte_array_free(dk->key, true);
    if (dk->ssid)
        g_byte_array_free(dk->ssid, true);
    g_free(dk);
}

static int
Dot11DecryptTDLSDeriveKey(
    PDOT11DECRYPT_SEC_ASSOCIATION sa,
    const uint8_t *data,
    unsigned offset_rsne,
    unsigned offset_fte,
    unsigned offset_timeout,
    unsigned offset_link,
    uint8_t action)
{

    gcry_md_hd_t sha256_handle;
    gcry_md_hd_t hmac_handle;
    const uint8_t *snonce, *anonce, *initiator, *responder, *bssid;
    uint8_t key_input[32];
    uint8_t mic[16], seq_num = action + 1;
    uint8_t zeros[16] = { 0 };
    gcry_mac_hd_t cmac_handle;
    size_t cmac_len = 16;
    size_t cmac_write_len;

    /* Get key input */
    anonce = &data[offset_fte + 20];
    snonce = &data[offset_fte + 52];

    if (gcry_md_open (&sha256_handle, GCRY_MD_SHA256, 0)) {
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    if (memcmp(anonce, snonce, DOT11DECRYPT_WPA_NONCE_LEN) < 0) {
        gcry_md_write(sha256_handle, anonce, DOT11DECRYPT_WPA_NONCE_LEN);
        gcry_md_write(sha256_handle, snonce, DOT11DECRYPT_WPA_NONCE_LEN);
    } else {
        gcry_md_write(sha256_handle, snonce, DOT11DECRYPT_WPA_NONCE_LEN);
        gcry_md_write(sha256_handle, anonce, DOT11DECRYPT_WPA_NONCE_LEN);
    }
    memcpy(key_input, gcry_md_read(sha256_handle, 0), 32);
    gcry_md_close(sha256_handle);

    /* Derive key */
    bssid = &data[offset_link + 2];
    initiator = &data[offset_link + 8];
    responder = &data[offset_link + 14];
    if (gcry_md_open(&hmac_handle, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC)) {
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    if (gcry_md_setkey(hmac_handle, key_input, 32)) {
        gcry_md_close(hmac_handle);
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    gcry_md_putc(hmac_handle, 1);
    gcry_md_putc(hmac_handle, 0);
    gcry_md_write(hmac_handle, "TDLS PMK", 8);
    if (memcmp(initiator, responder, DOT11DECRYPT_MAC_LEN) < 0) {
          gcry_md_write(hmac_handle, initiator, DOT11DECRYPT_MAC_LEN);
          gcry_md_write(hmac_handle, responder, DOT11DECRYPT_MAC_LEN);
    } else {
          gcry_md_write(hmac_handle, responder, DOT11DECRYPT_MAC_LEN);
          gcry_md_write(hmac_handle, initiator, DOT11DECRYPT_MAC_LEN);
    }
    gcry_md_write(hmac_handle, bssid, DOT11DECRYPT_MAC_LEN);
    gcry_md_putc(hmac_handle, 0);
    gcry_md_putc(hmac_handle, 1);
    memcpy(key_input, gcry_md_read(hmac_handle, 0), 32);
    gcry_md_close(hmac_handle);

    /* Check MIC */
    if (gcry_mac_open(&cmac_handle, GCRY_MAC_CMAC_AES, 0, NULL)) {
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    if (gcry_mac_setkey(cmac_handle, key_input, 16)) {
        gcry_mac_close(cmac_handle);
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    gcry_mac_write(cmac_handle, initiator, DOT11DECRYPT_MAC_LEN);
    gcry_mac_write(cmac_handle, responder, DOT11DECRYPT_MAC_LEN);
    gcry_mac_write(cmac_handle, &seq_num, 1);
    gcry_mac_write(cmac_handle, &data[offset_link], data[offset_link + 1] + 2);
    gcry_mac_write(cmac_handle, &data[offset_rsne], data[offset_rsne + 1] + 2);
    gcry_mac_write(cmac_handle, &data[offset_timeout], data[offset_timeout + 1] + 2);
    gcry_mac_write(cmac_handle, &data[offset_fte], 4);
    gcry_mac_write(cmac_handle, zeros, 16);
    cmac_write_len = data[offset_fte + 1] + 2;
    if (cmac_write_len < 20) {
        ws_warning("Bad MAC len");
        gcry_mac_close(cmac_handle);
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    gcry_mac_write(cmac_handle, &data[offset_fte + 20], cmac_write_len - 20);
    if (gcry_mac_read(cmac_handle, mic, &cmac_len) != GPG_ERR_NO_ERROR) {
        ws_warning("MAC read error");
        gcry_mac_close(cmac_handle);
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    if (memcmp(mic, &data[offset_fte + 4], 16)) {
        ws_debug("MIC verification failed");
        gcry_mac_close(cmac_handle);
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    gcry_mac_close(cmac_handle);
    /* TODO support other akm and ciphers? */
    sa->wpa.akm = 2;
    sa->wpa.cipher = 4;
    sa->wpa.ptk_len = Dot11DecryptGetPtkLen(sa->wpa.akm, sa->wpa.cipher) / 8;
    memcpy(DOT11DECRYPT_GET_TK(sa->wpa.ptk, sa->wpa.akm),
           key_input + 16, Dot11DecryptGetTkLen(sa->wpa.cipher) / 8);
    memcpy(sa->wpa.nonce, snonce, DOT11DECRYPT_WPA_NONCE_LEN);
    sa->validKey = true;
    sa->wpa.key_ver = DOT11DECRYPT_WPA_KEY_VER_AES_CCMP;
    ws_debug("MIC verified");
    return  DOT11DECRYPT_RET_SUCCESS;
}


#ifdef __cplusplus
}
#endif

/****************************************************************************/

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
