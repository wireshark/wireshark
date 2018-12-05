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

#include <glib.h>

#include <wsutil/wsgcrypt.h>
#include <wsutil/crc32.h>
#include <wsutil/pint.h>

#include <epan/proto.h> /* for DISSECTOR_ASSERT. */
#include <epan/tvbuff.h>
#include <epan/to_str.h>
#include <epan/strutil.h>
#include <epan/crypt/dot11decrypt_rijndael.h>

#include "dot11decrypt_system.h"
#include "dot11decrypt_int.h"

#include "dot11decrypt_debug.h"

#include "wep-wpadefs.h"


/****************************************************************************/

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

/****************************************************************************/



/****************************************************************************/
/*      Macro definitions                                                       */

extern const UINT32 crc32_table[256];
#define CRC(crc, ch)     (crc = (crc >> 8) ^ crc32_table[(crc ^ (ch)) & 0xff])

#define DOT11DECRYPT_GET_TK(ptk)    (ptk + 32)

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
static INT Dot11DecryptRsnaPwd2PskStep(
    const guint8 *ppbytes,
    const guint passLength,
    const CHAR *ssid,
    const size_t ssidLength,
    const INT iterations,
    const INT count,
    UCHAR *output)
    ;

/**
 * It calculates the passphrase-to-PSK mapping reccomanded for use with
 * RSNAs. This implementation uses the PBKDF2 method defined in the RFC
 * 2898.
 * @param passphrase [IN] pointer to a password (sequence of between 8 and
 * 63 ASCII encoded characters)
 * @param ssid [IN] pointer to the SSID string encoded in max 32 ASCII
 * encoded characters
 * @param output [OUT] calculated PSK (to use as PMK in WPA)
 * @note
 * Described in 802.11i-2004, page 165
 */
static INT Dot11DecryptRsnaPwd2Psk(
    const CHAR *passphrase,
    const CHAR *ssid,
    const size_t ssidLength,
    UCHAR *output)
    ;

static INT Dot11DecryptRsnaMng(
    UCHAR *decrypt_data,
    guint mac_header_len,
    guint *decrypt_len,
    PDOT11DECRYPT_KEY_ITEM key,
    DOT11DECRYPT_SEC_ASSOCIATION *sa,
    INT offset)
    ;

static INT Dot11DecryptWepMng(
    PDOT11DECRYPT_CONTEXT ctx,
    UCHAR *decrypt_data,
    guint mac_header_len,
    guint *decrypt_len,
    PDOT11DECRYPT_KEY_ITEM key,
    DOT11DECRYPT_SEC_ASSOCIATION *sa,
    INT offset)
    ;

static INT Dot11DecryptRsna4WHandshake(
    PDOT11DECRYPT_CONTEXT ctx,
    const UCHAR *data,
    DOT11DECRYPT_SEC_ASSOCIATION *sa,
    INT offset,
    const guint tot_len,
    UCHAR *decrypt_data,
    guint *decrypt_len,
    PDOT11DECRYPT_KEY_ITEM key);
/**
 * It checks whether the specified key is corrected or not.
 * @note
 * For a standard WEP key the length will be changed to the standard
 * length, and the type changed in a generic WEP key.
 * @param key [IN] pointer to the key to validate
 * @return
 * - TRUE: the key contains valid fields and values
 * - FALSE: the key has some invalid field or value
 */
static INT Dot11DecryptValidateKey(
    PDOT11DECRYPT_KEY_ITEM key)
    ;

static INT Dot11DecryptRsnaMicCheck(
    UCHAR *eapol,
    USHORT eapol_len,
    UCHAR KCK[DOT11DECRYPT_WPA_KCK_LEN],
    USHORT key_ver)
    ;

/**
 * @param ctx [IN] pointer to the current context
 * @param id [IN] id of the association (composed by BSSID and MAC of
 * the station)
 * @return
 * - index of the Security Association structure if found
 * - -1, if the specified addresses pair BSSID-STA MAC has not been found
 */
static INT Dot11DecryptGetSa(
    PDOT11DECRYPT_CONTEXT ctx,
    DOT11DECRYPT_SEC_ASSOCIATION_ID *id)
    ;

static INT Dot11DecryptStoreSa(
    PDOT11DECRYPT_CONTEXT ctx,
    DOT11DECRYPT_SEC_ASSOCIATION_ID *id)
    ;

static INT Dot11DecryptGetSaAddress(
    const DOT11DECRYPT_MAC_FRAME_ADDR4 *frame,
    DOT11DECRYPT_SEC_ASSOCIATION_ID *id)
    ;

static const UCHAR * Dot11DecryptGetStaAddress(
    const DOT11DECRYPT_MAC_FRAME_ADDR4 *frame)
    ;

static const UCHAR * Dot11DecryptGetBssidAddress(
    const DOT11DECRYPT_MAC_FRAME_ADDR4 *frame)
    ;

static void Dot11DecryptRsnaPrfX(
    DOT11DECRYPT_SEC_ASSOCIATION *sa,
    const UCHAR pmk[32],
    const UCHAR snonce[32],
    const INT x,        /*      for TKIP 512, for CCMP 384      */
    UCHAR *ptk)
    ;


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
 *  DOT11DECRYPT_RET_SUCCESS if Key has been sucessfully derived (and MIC verified)
 *  DOT11DECRYPT_RET_UNSUCCESS otherwise
 */
static INT
Dot11DecryptTDLSDeriveKey(
    PDOT11DECRYPT_SEC_ASSOCIATION sa,
    const guint8 *data,
    guint offset_rsne,
    guint offset_fte,
    guint offset_timeout,
    guint offset_link,
    guint8 action)
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

const guint8 broadcast_mac[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

#define EAPKEY_MIC_LEN  16  /* length of the MIC key for EAPoL_Key packet's MIC using MD5 */
#define NONCE_LEN 32

#define TKIP_GROUP_KEY_LEN 32
#define CCMP_GROUP_KEY_LEN 16

typedef struct {
    guint8  type;
    guint8  key_information[2];  /* Make this an array to avoid alignment issues */
    guint8  key_length[2];  /* Make this an array to avoid alignment issues */
    guint8  replay_counter[8];
    guint8  key_nonce[NONCE_LEN];
    guint8  key_iv[16];
    guint8  key_sequence_counter[8];  /* also called the RSC */
    guint8  key_id[8];
    guint8  key_mic[EAPKEY_MIC_LEN];
    guint8  key_data_len[2];  /* Make this an array rather than a U16 to avoid alignment shifting */
} EAPOL_RSN_KEY,  * P_EAPOL_RSN_KEY;

/* Minimum possible key data size (at least one GTK KDE with CCMP key) */
#define GROUP_KEY_MIN_LEN 8 + CCMP_GROUP_KEY_LEN
/* Minimum possible group key msg size (group key msg using CCMP as cipher)*/
#define GROUP_KEY_PAYLOAD_LEN_MIN sizeof(EAPOL_RSN_KEY) + GROUP_KEY_MIN_LEN

static void
Dot11DecryptCopyKey(PDOT11DECRYPT_SEC_ASSOCIATION sa, PDOT11DECRYPT_KEY_ITEM key)
{
    if (key!=NULL) {
        if (sa->key!=NULL)
            memcpy(key, sa->key, sizeof(DOT11DECRYPT_KEY_ITEM));
        else
            memset(key, 0, sizeof(DOT11DECRYPT_KEY_ITEM));
        memcpy(key->KeyData.Wpa.Ptk, sa->wpa.ptk, DOT11DECRYPT_WPA_PTK_LEN);
        if (sa->wpa.key_ver==DOT11DECRYPT_WPA_KEY_VER_NOT_CCMP)
            key->KeyType=DOT11DECRYPT_KEY_TYPE_TKIP;
        else if (sa->wpa.key_ver==DOT11DECRYPT_WPA_KEY_VER_AES_CCMP)
            key->KeyType=DOT11DECRYPT_KEY_TYPE_CCMP;
    }
}

static guint8*
Dot11DecryptRc4KeyData(const guint8 *decryption_key, guint decryption_key_len,
                       const guint8 *encrypted_keydata, guint encrypted_keydata_len)
{
    gcry_cipher_hd_t  rc4_handle;
    guint8 dummy[256] = { 0 };
    guint8 *decrypted_key = NULL;

    if (gcry_cipher_open (&rc4_handle, GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, 0)) {
        return NULL;
    }
    if (gcry_cipher_setkey(rc4_handle, decryption_key, decryption_key_len)) {
        gcry_cipher_close(rc4_handle);
        return NULL;
    }
    decrypted_key = (guint8 *)g_memdup(encrypted_keydata, encrypted_keydata_len);
    if (!decrypted_key) {
        return NULL;
    }

    /* Do dummy 256 iterations of the RC4 algorithm (per 802.11i, Draft 3.0, p. 97 line 6) */
    gcry_cipher_decrypt(rc4_handle, dummy, 256, NULL, 0);
    gcry_cipher_decrypt(rc4_handle, decrypted_key, encrypted_keydata_len, NULL, 0);
    gcry_cipher_close(rc4_handle);
    return decrypted_key;
}

/* XXX - what if this doesn't get the key? */
static INT
Dot11DecryptDecryptWPABroadcastKey(const EAPOL_RSN_KEY *pEAPKey, guint8 *decryption_key,
                                   PDOT11DECRYPT_SEC_ASSOCIATION sa, guint eapol_len,
                                   guint8 *decrypted_data,
                                   guint *decrypted_len)
{
    guint8 key_version;
    const guint8 *key_data;
    guint8 *decrypted_key = NULL;
    guint16 key_bytes_len = 0; /* Length of the total key data field */
    guint16 key_len;           /* Actual group key length */
    static DOT11DECRYPT_KEY_ITEM dummy_key; /* needed in case Dot11DecryptRsnaMng() wants the key structure */
    DOT11DECRYPT_SEC_ASSOCIATION *tmp_sa;

    *decrypted_len = 0;

    /* We skip verifying the MIC of the key. If we were implementing a WPA supplicant we'd want to verify, but for a sniffer it's not needed. */

    /* Preparation for decrypting the group key -  determine group key data length */
    /* depending on whether the pairwise key is TKIP or AES encryption key */
    key_version = DOT11DECRYPT_EAP_KEY_DESCR_VER(pEAPKey->key_information[1]);
    if (key_version == DOT11DECRYPT_WPA_KEY_VER_NOT_CCMP){
        /* TKIP */
        key_bytes_len = pntoh16(pEAPKey->key_length);
    }else if (key_version == DOT11DECRYPT_WPA_KEY_VER_AES_CCMP){
        /* AES */
        key_bytes_len = pntoh16(pEAPKey->key_data_len);

        /* AES keys must be at least 128 bits = 16 bytes. */
        if (key_bytes_len < 16) {
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }
    }

    if ((key_bytes_len < GROUP_KEY_MIN_LEN) ||
        (eapol_len < sizeof(EAPOL_RSN_KEY)) ||
        (key_bytes_len > eapol_len - sizeof(EAPOL_RSN_KEY))) {
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }

    /* Encrypted key is in the information element field of the EAPOL key packet */
    key_data = (const guint8 *)pEAPKey + sizeof(EAPOL_RSN_KEY);

    DEBUG_DUMP("Encrypted Broadcast key:", key_data, key_bytes_len);
    DEBUG_DUMP("KeyIV:", pEAPKey->key_iv, 16);
    DEBUG_DUMP("decryption_key:", decryption_key, 16);

    /* We are rekeying, save old sa */
    tmp_sa=(DOT11DECRYPT_SEC_ASSOCIATION *)g_malloc(sizeof(DOT11DECRYPT_SEC_ASSOCIATION));
    memcpy(tmp_sa, sa, sizeof(DOT11DECRYPT_SEC_ASSOCIATION));
    sa->next=tmp_sa;

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
        guint8 new_key[32];
        guint8 *data;

        /* The WPA group key just contains the GTK bytes so deducing the type is straightforward   */
        /* Note - WPA M3 doesn't contain a group key so we'll only be here for the group handshake */
        sa->wpa.key_ver = (key_bytes_len >=TKIP_GROUP_KEY_LEN)?DOT11DECRYPT_WPA_KEY_VER_NOT_CCMP:DOT11DECRYPT_WPA_KEY_VER_AES_CCMP;

        /* Build the full decryption key based on the IV and part of the pairwise key */
        memcpy(new_key, pEAPKey->key_iv, 16);
        memcpy(new_key+16, decryption_key, 16);
        DEBUG_DUMP("FullDecrKey:", new_key, 32);
        data = Dot11DecryptRc4KeyData(new_key, 32, key_data, key_bytes_len);
        if (!data) {
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }
        memcpy(decrypted_data, data, key_bytes_len);
        decrypted_key = decrypted_data;
        g_free(data);
    } else if (key_version == DOT11DECRYPT_WPA_KEY_VER_AES_CCMP){
        /* AES CCMP key */

        guint8 key_found;
        guint8 key_length;
        guint16 key_index;
        guint8 *data;

        /* Unwrap the key; the result is key_bytes_len in length */
        data = AES_unwrap(decryption_key, 16, key_data, key_bytes_len);
        if (!data) {
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }
        key_bytes_len -= 8; /* AES-WRAP adds 8 bytes */
        memcpy(decrypted_data, data, key_bytes_len);
        g_free(data);

        /* With WPA2 what we get after Broadcast Key decryption is an actual RSN structure.
           The key itself is stored as a GTK KDE
           WPA2 IE (1 byte) id = 0xdd, length (1 byte), GTK OUI (4 bytes), key index (1 byte) and 1 reserved byte. Thus we have to
           pass pointer to the actual key with 8 bytes offset */

        key_found = FALSE;
        key_index = 0;

        /* Parse Key data until we found GTK KDE */
        /* GTK KDE = 00-0F-AC 01 */
        while(key_index < (key_bytes_len - 6) && !key_found){
            guint8 rsn_id;
            guint32 type;

            /* Get RSN ID */
            rsn_id = decrypted_data[key_index];
            type = ((decrypted_data[key_index + 2] << 24) +
                    (decrypted_data[key_index + 3] << 16) +
                    (decrypted_data[key_index + 4] << 8) +
                     (decrypted_data[key_index + 5]));

            if (rsn_id == 0xdd && type == 0x000fac01) {
                key_found = TRUE;
            } else {
                key_index += decrypted_data[key_index+1]+2;
            }
        }

        if (key_found){
            if (decrypted_data[key_index+1] <= 6) {
                return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
            }
            key_length = decrypted_data[key_index+1] - 6;

            if (key_index+8 >= key_bytes_len ||
                key_length > key_bytes_len - key_index - 8) {
                return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
            }

            /* Skip over the GTK header info */
            decrypted_key = decrypted_data + key_index + 8;
        } else {
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }

        if (key_length == TKIP_GROUP_KEY_LEN)
            sa->wpa.key_ver = DOT11DECRYPT_WPA_KEY_VER_NOT_CCMP;
        else
            sa->wpa.key_ver = DOT11DECRYPT_WPA_KEY_VER_AES_CCMP;
    }

    key_len = (sa->wpa.key_ver==DOT11DECRYPT_WPA_KEY_VER_NOT_CCMP)?TKIP_GROUP_KEY_LEN:CCMP_GROUP_KEY_LEN;
    if (key_len > key_bytes_len) {
        /* the key required for this protocol is longer than the key that we just calculated */
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }

    *decrypted_len = key_bytes_len;

    /* Decrypted key is now in szEncryptedKey with len of key_len */
    DEBUG_DUMP("Broadcast key:", decrypted_key, key_len);

    /* Load the proper key material info into the SA */
    sa->key = &dummy_key;  /* we just need key to be not null because it is checked in Dot11DecryptRsnaMng().  The WPA key materials are actually in the .wpa structure */
    sa->validKey = TRUE;

    /* Since this is a GTK and its size is only 32 bytes (vs. the 64 byte size of a PTK), we fake it and put it in at a 32-byte offset so the  */
    /* Dot11DecryptRsnaMng() function will extract the right piece of the GTK for decryption. (The first 16 bytes of the GTK are used for decryption.) */
    memset(sa->wpa.ptk, 0, sizeof(sa->wpa.ptk));
    memcpy(sa->wpa.ptk+32, decrypted_key, key_len);
    return DOT11DECRYPT_RET_SUCCESS_HANDSHAKE;
}


/* Return a pointer the the requested SA. If it doesn't exist create it. */
static PDOT11DECRYPT_SEC_ASSOCIATION
Dot11DecryptGetSaPtr(
    PDOT11DECRYPT_CONTEXT ctx,
    DOT11DECRYPT_SEC_ASSOCIATION_ID *id)
{
    int sa_index;

    /* search for a cached Security Association for supplied BSSID and STA MAC  */
    if ((sa_index=Dot11DecryptGetSa(ctx, id))==-1) {
        /* create a new Security Association if it doesn't currently exist      */
        if ((sa_index=Dot11DecryptStoreSa(ctx, id))==-1) {
            return NULL;
        }
    }
    /* get the Security Association structure   */
    return &ctx->sa[sa_index];
}

static INT Dot11DecryptScanForKeys(
    PDOT11DECRYPT_CONTEXT ctx,
    const guint8 *data,
    const guint mac_header_len,
    const guint tot_len,
    DOT11DECRYPT_SEC_ASSOCIATION_ID id,
    UCHAR *decrypt_data,
    guint *decrypt_len,
    PDOT11DECRYPT_KEY_ITEM key
)
{
    guint tot_len_left;
    const UCHAR *addr;
    guint bodyLength;
    PDOT11DECRYPT_SEC_ASSOCIATION sta_sa;
    PDOT11DECRYPT_SEC_ASSOCIATION sa;
    guint offset = 0;
    const guint8 dot1x_header[] = {
        0xAA,             /* DSAP=SNAP */
        0xAA,             /* SSAP=SNAP */
        0x03,             /* Control field=Unnumbered frame */
        0x00, 0x00, 0x00, /* Org. code=encaps. Ethernet */
        0x88, 0x8E        /* Type: 802.1X authentication */
    };
    const guint8 bt_dot1x_header[] = {
        0xAA,             /* DSAP=SNAP */
        0xAA,             /* SSAP=SNAP */
        0x03,             /* Control field=Unnumbered frame */
        0x00, 0x19, 0x58, /* Org. code=Bluetooth SIG */
        0x00, 0x03        /* Type: Bluetooth Security */
    };
    const guint8 tdls_header[] = {
        0xAA,             /* DSAP=SNAP */
        0xAA,             /* SSAP=SNAP */
        0x03,             /* Control field=Unnumbered frame */
        0x00, 0x00, 0x00, /* Org. code=encaps. Ethernet */
        0x89, 0x0D,       /* Type: 802.11 - Fast Roaming Remote Request */
        0x02,             /* Payload Type: TDLS */
        0X0C              /* Action Category: TDLS */
    };

    const EAPOL_RSN_KEY *pEAPKey;
#ifdef DOT11DECRYPT_DEBUG
#define MSGBUF_LEN 255
    CHAR msgbuf[MSGBUF_LEN];
#endif
    DOT11DECRYPT_DEBUG_TRACE_START("Dot11DecryptScanForKeys");

    /* Callers provide these guarantees, so let's make them explicit. */
    DISSECTOR_ASSERT(tot_len <= DOT11DECRYPT_MAX_CAPLEN);

    /* cache offset in the packet data */
    offset = mac_header_len;

    /* Amount of data following the MAC header */
    tot_len_left = tot_len - mac_header_len;

    /* check if the packet has an LLC header and the packet is 802.1X authentication (IEEE 802.1X-2004, pg. 24) */
    if (tot_len_left >= 8 && (memcmp(data+offset, dot1x_header, 8) == 0 || memcmp(data+offset, bt_dot1x_header, 8) == 0)) {

        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "Authentication: EAPOL packet", DOT11DECRYPT_DEBUG_LEVEL_3);

        /* skip LLC header */
        offset+=8;
        tot_len_left-=8;

        if (tot_len_left < 4) {
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "Not EAPOL-Key", DOT11DECRYPT_DEBUG_LEVEL_3);
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }

        /* check if the packet is a EAPOL-Key (0x03) (IEEE 802.1X-2004, pg. 25) */
        if (data[offset+1]!=3) {
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "Not EAPOL-Key", DOT11DECRYPT_DEBUG_LEVEL_3);
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }

        /* get and check the body length (IEEE 802.1X-2004, pg. 25) */
        bodyLength=pntoh16(data+offset+2);
        if (((tot_len_left-4) < bodyLength) || (bodyLength < sizeof(EAPOL_RSN_KEY))) { /* Only check if frame is long enough for eapol header, ignore tailing garbage, see bug 9065 */
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "EAPOL body too short", DOT11DECRYPT_DEBUG_LEVEL_3);
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }

        /* skip EAPOL MPDU and go to the first byte of the body */
        offset+=4;
        tot_len_left-=4;

        pEAPKey = (const EAPOL_RSN_KEY *) (data+offset);

        if (tot_len_left < 1) {
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "Not EAPOL-Key", DOT11DECRYPT_DEBUG_LEVEL_3);
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }
        /* check if the key descriptor type is valid (IEEE 802.1X-2004, pg. 27) */
        if (/*pEAPKey->type!=0x1 &&*/ /* RC4 Key Descriptor Type (deprecated) */
            pEAPKey->type != DOT11DECRYPT_RSN_WPA2_KEY_DESCRIPTOR &&             /* IEEE 802.11 Key Descriptor Type  (WPA2) */
            pEAPKey->type != DOT11DECRYPT_RSN_WPA_KEY_DESCRIPTOR)           /* 254 = RSN_KEY_DESCRIPTOR - WPA,              */
        {
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "Not valid key descriptor type", DOT11DECRYPT_DEBUG_LEVEL_3);
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }

        /* start with descriptor body */
        offset+=1;

        /* search for a cached Security Association for current BSSID and AP */
        sa = Dot11DecryptGetSaPtr(ctx, &id);
        if (sa == NULL){
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "No SA for BSSID found", DOT11DECRYPT_DEBUG_LEVEL_3);
            return DOT11DECRYPT_RET_REQ_DATA;
        }

        /* It could be a Pairwise Key exchange, check */
        if (Dot11DecryptRsna4WHandshake(ctx, data, sa, offset, tot_len,
                                        decrypt_data, decrypt_len, key) == DOT11DECRYPT_RET_SUCCESS_HANDSHAKE)
        {
            return DOT11DECRYPT_RET_SUCCESS_HANDSHAKE;
        }

        if (mac_header_len + GROUP_KEY_PAYLOAD_LEN_MIN > tot_len) {
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "Message too short for Group Key", DOT11DECRYPT_DEBUG_LEVEL_3);
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }

        /* Verify the bitfields: Key = 0(groupwise) Mic = 1 Ack = 1 Secure = 1 */
        if (DOT11DECRYPT_EAP_KEY(data[offset+1])!=0 ||
            DOT11DECRYPT_EAP_ACK(data[offset+1])!=1 ||
            DOT11DECRYPT_EAP_MIC(data[offset]) != 1 ||
            DOT11DECRYPT_EAP_SEC(data[offset]) != 1){

            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "Key bitfields not correct for Group Key", DOT11DECRYPT_DEBUG_LEVEL_3);
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }

        /* force STA address to be the broadcast MAC so we create an SA for the groupkey */
        memcpy(id.sta, broadcast_mac, DOT11DECRYPT_MAC_LEN);

        /* get the Security Association structure for the broadcast MAC and AP */
        sa = Dot11DecryptGetSaPtr(ctx, &id);
        if (sa == NULL){
            return DOT11DECRYPT_RET_REQ_DATA;
        }

        /* Get the SA for the STA, since we need its pairwise key to decrpyt the group key */

        /* get STA address */
        if ( (addr=Dot11DecryptGetStaAddress((const DOT11DECRYPT_MAC_FRAME_ADDR4 *)(data))) != NULL) {
            memcpy(id.sta, addr, DOT11DECRYPT_MAC_LEN);
#ifdef DOT11DECRYPT_DEBUG
            g_snprintf(msgbuf, MSGBUF_LEN, "ST_MAC: %2X.%2X.%2X.%2X.%2X.%2X\t", id.sta[0],id.sta[1],id.sta[2],id.sta[3],id.sta[4],id.sta[5]);
#endif
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", msgbuf, DOT11DECRYPT_DEBUG_LEVEL_3);
        } else {
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "SA not found", DOT11DECRYPT_DEBUG_LEVEL_5);
            return DOT11DECRYPT_RET_REQ_DATA;
        }

        sta_sa = Dot11DecryptGetSaPtr(ctx, &id);
        if (sta_sa == NULL){
            return DOT11DECRYPT_RET_REQ_DATA;
        }

        /* Try to extract the group key and install it in the SA */
        Dot11DecryptCopyKey(sta_sa, key); /* save key used for decrypting broadcast key */
        return (Dot11DecryptDecryptWPABroadcastKey(pEAPKey, sta_sa->wpa.ptk+16, sa, tot_len-offset+1,
                                                   decrypt_data, decrypt_len));

    } else if (tot_len_left >= 10 && memcmp(data+offset, tdls_header, 10) == 0) {
        const guint8 *initiator, *responder;
        guint8 action;
        guint status, offset_rsne = 0, offset_fte = 0, offset_link = 0, offset_timeout = 0;
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "Authentication: TDLS Action Frame", DOT11DECRYPT_DEBUG_LEVEL_3);

        /* Skip LLC header, after this we have at least
         * DOT11DECRYPT_CRYPTED_DATA_MINLEN-10 = 7 bytes in "data[offset]". That
         * TDLS payload contains a TDLS Action field (802.11-2016 9.6.13) */
        offset+=10;
        tot_len_left-=10;

        /* check if the packet is a TDLS response or confirm */
        if (tot_len_left < 1) {
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "Not EAPOL-Key", DOT11DECRYPT_DEBUG_LEVEL_3);
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }
        action = data[offset];
        if (action!=1 && action!=2) {
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "Not Response nor confirm", DOT11DECRYPT_DEBUG_LEVEL_3);
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }
        offset++;
        tot_len_left--;

        /* Check for SUCCESS (0) or SUCCESS_POWER_SAVE_MODE (85) Status Code */
        if (tot_len_left < 5) {
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "Not EAPOL-Key", DOT11DECRYPT_DEBUG_LEVEL_3);
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }
        status=pntoh16(data+offset);
        if (status != 0 && status != 85) {
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "TDLS setup not successful", DOT11DECRYPT_DEBUG_LEVEL_3);
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }

        /* skip Token + capabilities */
        offset+=5;

        /* search for RSN, Fast BSS Transition, Link Identifier and Timeout Interval IEs */

        while(offset < (tot_len - 2)) {
            guint8 element_id = data[offset];
            guint8 length = data[offset + 1];
            guint min_length = length;
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
                return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
            }
            offset += 2 + length;
        }

        if (offset_rsne == 0 || offset_fte == 0 ||
            offset_timeout == 0 || offset_link == 0)
        {
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "Cannot Find all necessary IEs", DOT11DECRYPT_DEBUG_LEVEL_3);
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }

        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "Found RSNE/Fast BSS/Timeout Interval/Link IEs", DOT11DECRYPT_DEBUG_LEVEL_3);

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

        sa = Dot11DecryptGetSaPtr(ctx, &id);
        if (sa == NULL){
            return DOT11DECRYPT_RET_REQ_DATA;
        }

        if (sa->validKey) {
            if (memcmp(sa->wpa.nonce, data + offset_fte + 52, DOT11DECRYPT_WPA_NONCE_LEN) == 0) {
                /* Already have valid key for this SA, no need to redo key derivation */
                return DOT11DECRYPT_RET_SUCCESS_HANDSHAKE;
            } else {
                /* We are opening a new session with the same two STA, save previous sa  */
                DOT11DECRYPT_SEC_ASSOCIATION *tmp_sa = g_new(DOT11DECRYPT_SEC_ASSOCIATION, 1);
                memcpy(tmp_sa, sa, sizeof(DOT11DECRYPT_SEC_ASSOCIATION));
                sa->next=tmp_sa;
                sa->validKey = FALSE;
            }
        }

        if (Dot11DecryptTDLSDeriveKey(sa, data, offset_rsne, offset_fte, offset_timeout, offset_link, action)
            == DOT11DECRYPT_RET_SUCCESS) {
            DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptScanForKeys");
            return DOT11DECRYPT_RET_SUCCESS_HANDSHAKE;
        }
    } else {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptScanForKeys", "Skipping: not an EAPOL packet", DOT11DECRYPT_DEBUG_LEVEL_3);
    }

    DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptScanForKeys");
    return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
}


INT Dot11DecryptPacketProcess(
    PDOT11DECRYPT_CONTEXT ctx,
    const guint8 *data,
    const guint mac_header_len,
    const guint tot_len,
    UCHAR *decrypt_data,
    guint *decrypt_len,
    PDOT11DECRYPT_KEY_ITEM key,
    gboolean scanHandshake)
{
    DOT11DECRYPT_SEC_ASSOCIATION_ID id;
    DISSECTOR_ASSERT(decrypt_data);
    DISSECTOR_ASSERT(decrypt_len);

#ifdef DOT11DECRYPT_DEBUG
#define MSGBUF_LEN 255
    CHAR msgbuf[MSGBUF_LEN];
#endif

    DOT11DECRYPT_DEBUG_TRACE_START("Dot11DecryptPacketProcess");

    if (decrypt_len) {
        *decrypt_len = 0;
    }
    if (ctx==NULL) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptPacketProcess", "NULL context", DOT11DECRYPT_DEBUG_LEVEL_5);
        DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptPacketProcess");
        return DOT11DECRYPT_RET_REQ_DATA;
    }
    if (data==NULL || tot_len==0) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptPacketProcess", "NULL data or length=0", DOT11DECRYPT_DEBUG_LEVEL_5);
        DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptPacketProcess");
        return DOT11DECRYPT_RET_REQ_DATA;
    }

    /* check if the packet is of data or robust managment type */
    if (!((DOT11DECRYPT_TYPE(data[0])==DOT11DECRYPT_TYPE_DATA) ||
          (DOT11DECRYPT_TYPE(data[0])==DOT11DECRYPT_TYPE_MANAGEMENT &&
           (DOT11DECRYPT_SUBTYPE(data[0])==DOT11DECRYPT_SUBTYPE_DISASS ||
            DOT11DECRYPT_SUBTYPE(data[0])==DOT11DECRYPT_SUBTYPE_DEAUTHENTICATION ||
            DOT11DECRYPT_SUBTYPE(data[0])==DOT11DECRYPT_SUBTYPE_ACTION)))) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptPacketProcess", "not data nor robust mgmt packet", DOT11DECRYPT_DEBUG_LEVEL_5);
        return DOT11DECRYPT_RET_NO_DATA;
    }

    /* check correct packet size, to avoid wrong elaboration of encryption algorithms */
    if (tot_len < (UINT)(mac_header_len+DOT11DECRYPT_CRYPTED_DATA_MINLEN)) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptPacketProcess", "minimum length violated", DOT11DECRYPT_DEBUG_LEVEL_5);
        return DOT11DECRYPT_RET_WRONG_DATA_SIZE;
    }

    /* Assume that the decrypt_data field is no more than this size. */
    if (tot_len > DOT11DECRYPT_MAX_CAPLEN) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptPacketProcess", "length too large", DOT11DECRYPT_DEBUG_LEVEL_3);
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    /* get STA/BSSID address */
    if (Dot11DecryptGetSaAddress((const DOT11DECRYPT_MAC_FRAME_ADDR4 *)(data), &id) != DOT11DECRYPT_RET_SUCCESS) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptPacketProcess", "STA/BSSID not found", DOT11DECRYPT_DEBUG_LEVEL_5);
        return DOT11DECRYPT_RET_REQ_DATA;
    }

    /* check if data is encrypted (use the WEP bit in the Frame Control field) */
    if (DOT11DECRYPT_WEP(data[1])==0) {
        if (scanHandshake) {
            /* data is sent in cleartext, check if is an authentication message or end the process */
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptPacketProcess", "Unencrypted data", DOT11DECRYPT_DEBUG_LEVEL_3);
            return (Dot11DecryptScanForKeys(ctx, data, mac_header_len, tot_len, id,
                                            decrypt_data, decrypt_len, key));
        }
        return DOT11DECRYPT_RET_NO_DATA_ENCRYPTED;
    } else {
        PDOT11DECRYPT_SEC_ASSOCIATION sa;
        int offset = 0;

        /* get the Security Association structure for the STA and AP */
        sa = Dot11DecryptGetSaPtr(ctx, &id);
        if (sa == NULL){
            return DOT11DECRYPT_RET_REQ_DATA;
        }

        /* cache offset in the packet data (to scan encryption data) */
        offset = mac_header_len;

        /* create new header and data to modify */
        *decrypt_len = tot_len;
        memcpy(decrypt_data, data, *decrypt_len);

        /* encrypted data */
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptPacketProcess", "Encrypted data", DOT11DECRYPT_DEBUG_LEVEL_3);

        /* check the Extension IV to distinguish between WEP encryption and WPA encryption */
        /* refer to IEEE 802.11i-2004, 8.2.1.2, pag.35 for WEP,    */
        /*          IEEE 802.11i-2004, 8.3.2.2, pag. 45 for TKIP,  */
        /*          IEEE 802.11i-2004, 8.3.3.2, pag. 57 for CCMP   */
        if (DOT11DECRYPT_EXTIV(data[offset+3])==0) {
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptPacketProcess", "WEP encryption", DOT11DECRYPT_DEBUG_LEVEL_3);
            return Dot11DecryptWepMng(ctx, decrypt_data, mac_header_len, decrypt_len, key, sa, offset);
        } else {
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptPacketProcess", "TKIP or CCMP encryption", DOT11DECRYPT_DEBUG_LEVEL_3);

            /* If index >= 1, then use the group key.  This will not work if the AP is using
               more than one group key simultaneously.  I've not seen this in practice, however.
               Usually an AP will rotate between the two key index values of 1 and 2 whenever
               it needs to change the group key to be used. */
            if (DOT11DECRYPT_KEY_INDEX(data[offset+3])>=1){

                DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptPacketProcess", "The key index >= 1. This is encrypted with a group key.", DOT11DECRYPT_DEBUG_LEVEL_3);

                /* force STA address to broadcast MAC so we load the SA for the groupkey */
                memcpy(id.sta, broadcast_mac, DOT11DECRYPT_MAC_LEN);

#ifdef DOT11DECRYPT_DEBUG
                g_snprintf(msgbuf, MSGBUF_LEN, "ST_MAC: %2X.%2X.%2X.%2X.%2X.%2X\t", id.sta[0],id.sta[1],id.sta[2],id.sta[3],id.sta[4],id.sta[5]);
                DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptPacketProcess", msgbuf, DOT11DECRYPT_DEBUG_LEVEL_3);
#endif

                /* search for a cached Security Association for current BSSID and broadcast MAC */
                sa = Dot11DecryptGetSaPtr(ctx, &id);
                if (sa == NULL)
                    return DOT11DECRYPT_RET_REQ_DATA;
            }

            /* Decrypt the packet using the appropriate SA */
            if (Dot11DecryptRsnaMng(decrypt_data, mac_header_len, decrypt_len, key, sa, offset) == DOT11DECRYPT_RET_SUCCESS) {
                /* If we successfully decrypted a packet, scan it to see if it contains a key handshake.
                   The group key handshake could be sent at any time the AP wants to change the key (such as when
                   it is using key rotation) and it also could be a rekey for the Pairwise key. So we must scan every packet. */
                if (scanHandshake) {
                    if (Dot11DecryptScanForKeys(ctx, decrypt_data, mac_header_len, *decrypt_len, id,
                                                decrypt_data, decrypt_len, key) == DOT11DECRYPT_RET_SUCCESS_HANDSHAKE) {
                        /* Keys found */
                        return DOT11DECRYPT_RET_SUCCESS_HANDSHAKE;
                    }
                }
                return DOT11DECRYPT_RET_SUCCESS; /* No keys found but decryption was successful */
            }
        }
    }
    return DOT11DECRYPT_RET_UNSUCCESS;
}

INT Dot11DecryptSetKeys(
    PDOT11DECRYPT_CONTEXT ctx,
    DOT11DECRYPT_KEY_ITEM keys[],
    const size_t keys_nr)
{
    INT i;
    INT success;
    DOT11DECRYPT_DEBUG_TRACE_START("Dot11DecryptSetKeys");

    if (ctx==NULL || keys==NULL) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptSetKeys", "NULL context or NULL keys array", DOT11DECRYPT_DEBUG_LEVEL_3);
        DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptSetKeys");
        return 0;
    }

    if (keys_nr>DOT11DECRYPT_MAX_KEYS_NR) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptSetKeys", "Keys number greater than maximum", DOT11DECRYPT_DEBUG_LEVEL_3);
        DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptSetKeys");
        return 0;
    }

    /* clean key and SA collections before setting new ones */
    Dot11DecryptInitContext(ctx);

    /* check and insert keys */
    for (i=0, success=0; i<(INT)keys_nr; i++) {
        if (Dot11DecryptValidateKey(keys+i)==TRUE) {
            if (keys[i].KeyType==DOT11DECRYPT_KEY_TYPE_WPA_PWD) {
                DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptSetKeys", "Set a WPA-PWD key", DOT11DECRYPT_DEBUG_LEVEL_4);
                Dot11DecryptRsnaPwd2Psk(keys[i].UserPwd.Passphrase, keys[i].UserPwd.Ssid, keys[i].UserPwd.SsidLen, keys[i].KeyData.Wpa.Psk);
            }
#ifdef DOT11DECRYPT_DEBUG
            else if (keys[i].KeyType==DOT11DECRYPT_KEY_TYPE_WPA_PMK) {
                DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptSetKeys", "Set a WPA-PMK key", DOT11DECRYPT_DEBUG_LEVEL_4);
            } else if (keys[i].KeyType==DOT11DECRYPT_KEY_TYPE_WEP) {
                DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptSetKeys", "Set a WEP key", DOT11DECRYPT_DEBUG_LEVEL_4);
            } else {
                DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptSetKeys", "Set a key", DOT11DECRYPT_DEBUG_LEVEL_4);
            }
#endif
            memcpy(&ctx->keys[success], &keys[i], sizeof(keys[i]));
            success++;
        }
    }

    ctx->keys_nr=success;

    DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptSetKeys");
    return success;
}

static void
Dot11DecryptCleanKeys(
    PDOT11DECRYPT_CONTEXT ctx)
{
    DOT11DECRYPT_DEBUG_TRACE_START("Dot11DecryptCleanKeys");

    if (ctx==NULL) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptCleanKeys", "NULL context", DOT11DECRYPT_DEBUG_LEVEL_5);
        DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptCleanKeys");
        return;
    }

    memset(ctx->keys, 0, sizeof(DOT11DECRYPT_KEY_ITEM) * DOT11DECRYPT_MAX_KEYS_NR);

    ctx->keys_nr=0;

    DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptCleanKeys", "Keys collection cleaned!", DOT11DECRYPT_DEBUG_LEVEL_5);
    DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptCleanKeys");
}

static void
Dot11DecryptRecurseCleanSA(
    PDOT11DECRYPT_SEC_ASSOCIATION sa)
{
    if (sa->next != NULL) {
        Dot11DecryptRecurseCleanSA(sa->next);
        g_free(sa->next);
        sa->next = NULL;
    }
}

static void
Dot11DecryptCleanSecAssoc(
    PDOT11DECRYPT_CONTEXT ctx)
{
    PDOT11DECRYPT_SEC_ASSOCIATION psa;
    int i;

    for (psa = ctx->sa, i = 0; i < DOT11DECRYPT_MAX_SEC_ASSOCIATIONS_NR; i++, psa++) {
        /* To iterate is human, to recurse, divine */
        Dot11DecryptRecurseCleanSA(psa);
    }
}

INT Dot11DecryptGetKeys(
    const PDOT11DECRYPT_CONTEXT ctx,
    DOT11DECRYPT_KEY_ITEM keys[],
    const size_t keys_nr)
{
    UINT i;
    UINT j;
    DOT11DECRYPT_DEBUG_TRACE_START("Dot11DecryptGetKeys");

    if (ctx==NULL) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptGetKeys", "NULL context", DOT11DECRYPT_DEBUG_LEVEL_5);
        DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptGetKeys");
        return 0;
    } else if (keys==NULL) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptGetKeys", "NULL keys array", DOT11DECRYPT_DEBUG_LEVEL_5);
        DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptGetKeys");
        return (INT)ctx->keys_nr;
    } else {
        for (i=0, j=0; i<ctx->keys_nr && i<keys_nr && i<DOT11DECRYPT_MAX_KEYS_NR; i++) {
            memcpy(&keys[j], &ctx->keys[i], sizeof(keys[j]));
            j++;
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptGetKeys", "Got a key", DOT11DECRYPT_DEBUG_LEVEL_5);
        }

        DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptGetKeys");
        return j;
    }
}

/*
 * XXX - This won't be reliable if a packet containing SSID "B" shows
 * up in the middle of a 4-way handshake for SSID "A".
 * We should probably use a small array or hash table to keep multiple
 * SSIDs.
 */
INT Dot11DecryptSetLastSSID(
    PDOT11DECRYPT_CONTEXT ctx,
    CHAR *pkt_ssid,
    size_t pkt_ssid_len)
{
    if (!ctx || !pkt_ssid || pkt_ssid_len < 1 || pkt_ssid_len > WPA_SSID_MAX_SIZE)
        return DOT11DECRYPT_RET_UNSUCCESS;

    memcpy(ctx->pkt_ssid, pkt_ssid, pkt_ssid_len);
    ctx->pkt_ssid_len = pkt_ssid_len;

    return DOT11DECRYPT_RET_SUCCESS;
}

INT Dot11DecryptInitContext(
    PDOT11DECRYPT_CONTEXT ctx)
{
    DOT11DECRYPT_DEBUG_TRACE_START("Dot11DecryptInitContext");

    if (ctx==NULL) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptInitContext", "NULL context", DOT11DECRYPT_DEBUG_LEVEL_5);
        DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptInitContext");
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    Dot11DecryptCleanKeys(ctx);

    ctx->first_free_index=0;
    ctx->index=-1;
    ctx->sa_index=-1;
    ctx->pkt_ssid_len = 0;

    memset(ctx->sa, 0, DOT11DECRYPT_MAX_SEC_ASSOCIATIONS_NR * sizeof(DOT11DECRYPT_SEC_ASSOCIATION));

    DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptInitContext", "Context initialized!", DOT11DECRYPT_DEBUG_LEVEL_5);
    DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptInitContext");
    return DOT11DECRYPT_RET_SUCCESS;
}

INT Dot11DecryptDestroyContext(
    PDOT11DECRYPT_CONTEXT ctx)
{
    DOT11DECRYPT_DEBUG_TRACE_START("Dot11DecryptDestroyContext");

    if (ctx==NULL) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptDestroyContext", "NULL context", DOT11DECRYPT_DEBUG_LEVEL_5);
        DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptDestroyContext");
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    Dot11DecryptCleanKeys(ctx);
    Dot11DecryptCleanSecAssoc(ctx);

    ctx->first_free_index=0;
    ctx->index=-1;
    ctx->sa_index=-1;

    DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptDestroyContext", "Context destroyed!", DOT11DECRYPT_DEBUG_LEVEL_5);
    DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptDestroyContext");
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

static INT
Dot11DecryptRsnaMng(
    UCHAR *decrypt_data,
    guint mac_header_len,
    guint *decrypt_len,
    PDOT11DECRYPT_KEY_ITEM key,
    DOT11DECRYPT_SEC_ASSOCIATION *sa,
    INT offset)
{
    INT ret_value=1;
    UCHAR *try_data;
    guint try_data_len = *decrypt_len;

    if (*decrypt_len == 0) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsnaMng", "Invalid decryption length", DOT11DECRYPT_DEBUG_LEVEL_3);
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    /* allocate a temp buffer for the decryption loop */
    try_data=(UCHAR *)g_malloc(try_data_len);

    /* start of loop added by GCS */
    for(/* sa */; sa != NULL ;sa=sa->next) {

       if (sa->validKey==FALSE) {
           DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsnaMng", "Key not yet valid", DOT11DECRYPT_DEBUG_LEVEL_3);
           continue;
       }

       /* copy the encrypted data into a temp buffer */
       memcpy(try_data, decrypt_data, *decrypt_len);

       if (sa->wpa.key_ver==1) {
           /* CCMP -> HMAC-MD5 is the EAPOL-Key MIC, RC4 is the EAPOL-Key encryption algorithm */
           DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsnaMng", "TKIP", DOT11DECRYPT_DEBUG_LEVEL_3);
           DEBUG_DUMP("ptk", sa->wpa.ptk, 64);
           DEBUG_DUMP("ptk portion used", DOT11DECRYPT_GET_TK(sa->wpa.ptk), 16);

           if (*decrypt_len < (guint)offset) {
               DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsnaMng", "Invalid decryption length", DOT11DECRYPT_DEBUG_LEVEL_3);
               g_free(try_data);
               return DOT11DECRYPT_RET_UNSUCCESS;
           }
           if (*decrypt_len < DOT11DECRYPT_RSNA_MICLEN+DOT11DECRYPT_WEP_ICV) {
               DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsnaMng", "Invalid decryption length", DOT11DECRYPT_DEBUG_LEVEL_3);
               g_free(try_data);
               return DOT11DECRYPT_RET_UNSUCCESS;
           }

           ret_value=Dot11DecryptTkipDecrypt(try_data+offset, *decrypt_len-offset, try_data+DOT11DECRYPT_TA_OFFSET, DOT11DECRYPT_GET_TK(sa->wpa.ptk));
           if (ret_value){
               DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsnaMng", "TKIP failed!", DOT11DECRYPT_DEBUG_LEVEL_3);
               continue;
           }

           DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsnaMng", "TKIP DECRYPTED!!!", DOT11DECRYPT_DEBUG_LEVEL_3);
           /* remove MIC and ICV from the end of packet */
           *decrypt_len-=DOT11DECRYPT_RSNA_MICLEN+DOT11DECRYPT_WEP_ICV;
           break;
       } else {
           /* AES-CCMP -> HMAC-SHA1-128 is the EAPOL-Key MIC, AES wep_key wrap is the EAPOL-Key encryption algorithm */
           DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsnaMng", "CCMP", DOT11DECRYPT_DEBUG_LEVEL_3);

           if (*decrypt_len < DOT11DECRYPT_RSNA_MICLEN) {
               DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsnaMng", "Invalid decryption length", DOT11DECRYPT_DEBUG_LEVEL_3);
               g_free(try_data);
               return DOT11DECRYPT_RET_UNSUCCESS;
           }

           ret_value=Dot11DecryptCcmpDecrypt(try_data, mac_header_len, (INT)*decrypt_len, DOT11DECRYPT_GET_TK(sa->wpa.ptk));
           if (ret_value)
              continue;

           DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsnaMng", "CCMP DECRYPTED!!!", DOT11DECRYPT_DEBUG_LEVEL_3);
           /* remove MIC from the end of packet */
           *decrypt_len-=DOT11DECRYPT_RSNA_MICLEN;
           break;
       }
    }
    /* end of loop */

    /* none of the keys worked */
    if(sa == NULL) {
        g_free(try_data);
        return ret_value;
    }

    if (*decrypt_len > try_data_len || *decrypt_len < 8) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsnaMng", "Invalid decryption length", DOT11DECRYPT_DEBUG_LEVEL_3);
        g_free(try_data);
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    /* copy the decrypted data into the decrypt buffer GCS*/
    memcpy(decrypt_data, try_data, *decrypt_len);
    g_free(try_data);

    /* remove protection bit */
    decrypt_data[1]&=0xBF;

    /* remove TKIP/CCMP header */
    offset = mac_header_len;
    *decrypt_len-=8;
    memmove(decrypt_data+offset, decrypt_data+offset+8, *decrypt_len-offset);

    Dot11DecryptCopyKey(sa, key);

    return DOT11DECRYPT_RET_SUCCESS;
}

static INT
Dot11DecryptWepMng(
    PDOT11DECRYPT_CONTEXT ctx,
    UCHAR *decrypt_data,
    guint mac_header_len,
    guint *decrypt_len,
    PDOT11DECRYPT_KEY_ITEM key,
    DOT11DECRYPT_SEC_ASSOCIATION *sa,
    INT offset)
{
    UCHAR wep_key[DOT11DECRYPT_WEP_KEY_MAXLEN+DOT11DECRYPT_WEP_IVLEN];
    size_t keylen;
    INT ret_value=1;
    INT key_index;
    DOT11DECRYPT_KEY_ITEM *tmp_key;
    UINT8 useCache=FALSE;
    UCHAR *try_data;
    guint try_data_len = *decrypt_len;

    try_data = (UCHAR *)g_malloc(try_data_len);

    if (sa->key!=NULL)
        useCache=TRUE;

    for (key_index=0; key_index<(INT)ctx->keys_nr; key_index++) {
        /* use the cached one, or try all keys */
        if (!useCache) {
            tmp_key=&ctx->keys[key_index];
        } else {
            if (sa->key!=NULL && sa->key->KeyType==DOT11DECRYPT_KEY_TYPE_WEP) {
                DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptWepMng", "Try cached WEP key...", DOT11DECRYPT_DEBUG_LEVEL_3);
                tmp_key=sa->key;
            } else {
                DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptWepMng", "Cached key is not valid, try another WEP key...", DOT11DECRYPT_DEBUG_LEVEL_3);
                tmp_key=&ctx->keys[key_index];
            }
        }

        /* obviously, try only WEP keys... */
        if (tmp_key->KeyType==DOT11DECRYPT_KEY_TYPE_WEP) {
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptWepMng", "Try WEP key...", DOT11DECRYPT_DEBUG_LEVEL_3);

            memset(wep_key, 0, sizeof(wep_key));
            memcpy(try_data, decrypt_data, *decrypt_len);

            /* Costruct the WEP seed: copy the IV in first 3 bytes and then the WEP key (refer to 802-11i-2004, 8.2.1.4.3, pag. 36) */
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
            /* the tried key is the correct one, cached in the Security Association */

            sa->key=tmp_key;

            if (key!=NULL) {
                memcpy(key, sa->key, sizeof(DOT11DECRYPT_KEY_ITEM));
                key->KeyType=DOT11DECRYPT_KEY_TYPE_WEP;
            }

            break;
        } else {
            /* the cached key was not valid, try other keys */

            if (useCache==TRUE) {
                useCache=FALSE;
                key_index--;
            }
        }
    }

    g_free(try_data);
    if (ret_value)
        return DOT11DECRYPT_RET_UNSUCCESS;

    DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptWepMng", "WEP DECRYPTED!!!", DOT11DECRYPT_DEBUG_LEVEL_3);

    /* remove ICV (4bytes) from the end of packet */
    *decrypt_len-=4;

    if (*decrypt_len < 4) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptWepMng", "Decryption length too short", DOT11DECRYPT_DEBUG_LEVEL_3);
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    /* remove protection bit */
    decrypt_data[1]&=0xBF;

    /* remove IC header */
    offset = mac_header_len;
    *decrypt_len-=4;
    memmove(decrypt_data+offset, decrypt_data+offset+DOT11DECRYPT_WEP_IVLEN+DOT11DECRYPT_WEP_KIDLEN, *decrypt_len-offset);

    return DOT11DECRYPT_RET_SUCCESS;
}

/* Refer to IEEE 802.11i-2004, 8.5.3, pag. 85 */
static INT
Dot11DecryptRsna4WHandshake(
    PDOT11DECRYPT_CONTEXT ctx,
    const UCHAR *data,
    DOT11DECRYPT_SEC_ASSOCIATION *sa,
    INT offset,
    const guint tot_len,
    UCHAR *decrypt_data,
    guint *decrypt_len,
    PDOT11DECRYPT_KEY_ITEM key)
{
    DOT11DECRYPT_KEY_ITEM *tmp_key, *tmp_pkt_key, pkt_key;
    DOT11DECRYPT_SEC_ASSOCIATION *tmp_sa;
    INT key_index;
    INT ret_value=1;
    UCHAR useCache=FALSE;
    UCHAR eapol[DOT11DECRYPT_EAPOL_MAX_LEN];
    USHORT eapol_len;

    if (sa->key!=NULL)
        useCache=TRUE;

    if (tot_len-offset < 2) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsna4WHandshake", "Too short to determine the message type", DOT11DECRYPT_DEBUG_LEVEL_5);
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }

    /* a 4-way handshake packet use a Pairwise key type (IEEE 802.11i-2004, pg. 79) */
    if (DOT11DECRYPT_EAP_KEY(data[offset+1])!=1) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsna4WHandshake", "Group/STAKey message (not used)", DOT11DECRYPT_DEBUG_LEVEL_5);
        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
    }

    /* TODO timeouts? */

    /* TODO consider key-index */

    /* TODO considera Deauthentications */

    DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsna4WHandshake", "4-way handshake...", DOT11DECRYPT_DEBUG_LEVEL_5);

    /* manage 4-way handshake packets; this step completes the 802.1X authentication process (IEEE 802.11i-2004, pag. 85) */

    /* message 1: Authenticator->Supplicant (Sec=0, Mic=0, Ack=1, Inst=0, Key=1(pairwise), KeyRSC=0, Nonce=ANonce, MIC=0) */
    if (DOT11DECRYPT_EAP_INST(data[offset+1])==0 &&
        DOT11DECRYPT_EAP_ACK(data[offset+1])==1 &&
        DOT11DECRYPT_EAP_MIC(data[offset])==0)
    {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsna4WHandshake", "4-way handshake message 1", DOT11DECRYPT_DEBUG_LEVEL_3);

        /* On reception of Message 1, the Supplicant determines whether the Key Replay Counter field value has been        */
        /* used before with the current PMKSA. If the Key Replay Counter field value is less than or equal to the current  */
        /* local value, the Supplicant discards the message.                                                               */
        /* -> not checked, the Authenticator will be send another Message 1 (hopefully!)                                   */

        /* This saves the sa since we are reauthenticating which will overwrite our current sa GCS*/
        if( sa->handshake >= 2) {
            tmp_sa= g_new(DOT11DECRYPT_SEC_ASSOCIATION, 1);
            memcpy(tmp_sa, sa, sizeof(DOT11DECRYPT_SEC_ASSOCIATION));
            sa->validKey=FALSE;
            sa->next=tmp_sa;
        }

        /* save ANonce (from authenticator) to derive the PTK with the SNonce (from the 2 message) */
        if (tot_len-(offset+12) < 32) {
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsna4WHandshake", "Too short to contain ANonce", DOT11DECRYPT_DEBUG_LEVEL_5);
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }
        memcpy(sa->wpa.nonce, data+offset+12, 32);

        /* get the Key Descriptor Version (to select algorithm used in decryption -CCMP or TKIP-) */
        sa->wpa.key_ver=DOT11DECRYPT_EAP_KEY_DESCR_VER(data[offset+1]);

        sa->handshake=1;

        return DOT11DECRYPT_RET_SUCCESS_HANDSHAKE;
    }

    /* message 2|4: Supplicant->Authenticator (Sec=0|1, Mic=1, Ack=0, Inst=0, Key=1(pairwise), KeyRSC=0, Nonce=SNonce|0, MIC=MIC(KCK,EAPOL)) */
    if (DOT11DECRYPT_EAP_INST(data[offset+1])==0 &&
        DOT11DECRYPT_EAP_ACK(data[offset+1])==0 &&
        DOT11DECRYPT_EAP_MIC(data[offset])==1)
    {
        /* Check key data length to differentiate between message 2 or 4, same as in epan/dissectors/packet-ieee80211.c */
        if (tot_len-(offset+92) < 2) {
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsna4WHandshake", "Too short to have a key data length", DOT11DECRYPT_DEBUG_LEVEL_5);
            return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
        }
        if (pntoh16(data+offset+92)) {
            /* message 2 */
            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsna4WHandshake", "4-way handshake message 2", DOT11DECRYPT_DEBUG_LEVEL_3);

            /* On reception of Message 2, the Authenticator checks that the key replay counter corresponds to the */
            /* outstanding Message 1. If not, it silently discards the message.                                   */
            /* If the calculated MIC does not match the MIC that the Supplicant included in the EAPOL-Key frame,  */
            /* the Authenticator silently discards Message 2.                                                     */
            /* -> not checked; the Supplicant will send another message 2 (hopefully!)                            */

            /* now you can derive the PTK */
            for (key_index=0; key_index<(INT)ctx->keys_nr || useCache; key_index++) {
                /* use the cached one, or try all keys */
                if (!useCache) {
                    DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsna4WHandshake", "Try WPA key...", DOT11DECRYPT_DEBUG_LEVEL_3);
                    tmp_key=&ctx->keys[key_index];
                } else {
                    /* there is a cached key in the security association, if it's a WPA key try it... */
                    if (sa->key!=NULL &&
                        (sa->key->KeyType==DOT11DECRYPT_KEY_TYPE_WPA_PWD ||
                         sa->key->KeyType==DOT11DECRYPT_KEY_TYPE_WPA_PSK ||
                         sa->key->KeyType==DOT11DECRYPT_KEY_TYPE_WPA_PMK)) {
                            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsna4WHandshake", "Try cached WPA key...", DOT11DECRYPT_DEBUG_LEVEL_3);
                            tmp_key=sa->key;
                    } else {
                        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsna4WHandshake", "Cached key is of a wrong type, try WPA key...", DOT11DECRYPT_DEBUG_LEVEL_3);
                        tmp_key=&ctx->keys[key_index];
                    }
                }

                /* obviously, try only WPA keys... */
                if (tmp_key->KeyType==DOT11DECRYPT_KEY_TYPE_WPA_PWD ||
                    tmp_key->KeyType==DOT11DECRYPT_KEY_TYPE_WPA_PSK ||
                    tmp_key->KeyType==DOT11DECRYPT_KEY_TYPE_WPA_PMK)
                {
                    if (tmp_key->KeyType == DOT11DECRYPT_KEY_TYPE_WPA_PWD && tmp_key->UserPwd.SsidLen == 0 && ctx->pkt_ssid_len > 0 && ctx->pkt_ssid_len <= DOT11DECRYPT_WPA_SSID_MAX_LEN) {
                        /* We have a "wildcard" SSID.  Use the one from the packet. */
                        memcpy(&pkt_key, tmp_key, sizeof(pkt_key));
                        memcpy(&pkt_key.UserPwd.Ssid, ctx->pkt_ssid, ctx->pkt_ssid_len);
                         pkt_key.UserPwd.SsidLen = ctx->pkt_ssid_len;
                        Dot11DecryptRsnaPwd2Psk(pkt_key.UserPwd.Passphrase, pkt_key.UserPwd.Ssid,
                            pkt_key.UserPwd.SsidLen, pkt_key.KeyData.Wpa.Psk);
                        tmp_pkt_key = &pkt_key;
                    } else {
                        tmp_pkt_key = tmp_key;
                    }

                    /* derive the PTK from the BSSID, STA MAC, PMK, SNonce, ANonce */
                    Dot11DecryptRsnaPrfX(sa,                            /* authenticator nonce, bssid, station mac */
                                     tmp_pkt_key->KeyData.Wpa.Psk,      /* PSK == PMK */
                                     data+offset+12,                /* supplicant nonce */
                                     512,
                                     sa->wpa.ptk);

                    /* verify the MIC (compare the MIC in the packet included in this message with a MIC calculated with the PTK) */
                    eapol_len=pntoh16(data+offset-3)+4;
                    if ((guint)(tot_len-(offset-5)) < (eapol_len<DOT11DECRYPT_EAPOL_MAX_LEN?eapol_len:DOT11DECRYPT_EAPOL_MAX_LEN)) {
                        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsna4WHandshake", "Too short to contain ANonce", DOT11DECRYPT_DEBUG_LEVEL_5);
                        return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
                    }
                    memcpy(eapol, &data[offset-5], (eapol_len<DOT11DECRYPT_EAPOL_MAX_LEN?eapol_len:DOT11DECRYPT_EAPOL_MAX_LEN));
                    ret_value=Dot11DecryptRsnaMicCheck(eapol,           /*      eapol frame (header also) */
                                                   eapol_len,       /*      eapol frame length        */
                                                   sa->wpa.ptk,     /*      Key Confirmation Key      */
                                                   DOT11DECRYPT_EAP_KEY_DESCR_VER(data[offset+1])); /*  EAPOL-Key description version */

                    /* If the MIC is valid, the Authenticator checks that the RSN information element bit-wise matches       */
                    /* that from the (Re)Association Request message.                                                        */
                    /*              i) TODO If these are not exactly the same, the Authenticator uses MLME-DEAUTHENTICATE.request */
                    /* primitive to terminate the association.                                                               */
                    /*              ii) If they do match bit-wise, the Authenticator constructs Message 3.                   */
                }

                if (!ret_value &&
                    (tmp_key->KeyType==DOT11DECRYPT_KEY_TYPE_WPA_PWD ||
                    tmp_key->KeyType==DOT11DECRYPT_KEY_TYPE_WPA_PSK ||
                    tmp_key->KeyType==DOT11DECRYPT_KEY_TYPE_WPA_PMK))
                {
                    /* the temporary key is the correct one, cached in the Security Association */

                    sa->key=tmp_key;
                    break;
                } else {
                    /* the cached key was not valid, try other keys */

                    if (useCache==TRUE) {
                        useCache=FALSE;
                        key_index--;
                    }
                }
            }

            if (ret_value) {
                DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsna4WHandshake", "handshake step failed", DOT11DECRYPT_DEBUG_LEVEL_3);
                return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
            }

            sa->handshake=2;
            sa->validKey=TRUE; /* we can use the key to decode, even if we have not captured the other eapol packets */

            return DOT11DECRYPT_RET_SUCCESS_HANDSHAKE;
        } else {
        /* message 4 */

            /* TODO "Note that when the 4-Way Handshake is first used Message 4 is sent in the clear." */

            /* TODO check MIC and Replay Counter                                                                     */
            /* On reception of Message 4, the Authenticator verifies that the Key Replay Counter field value is one  */
            /* that it used on this 4-Way Handshake; if it is not, it silently discards the message.                 */
            /* If the calculated MIC does not match the MIC that the Supplicant included in the EAPOL-Key frame, the */
            /* Authenticator silently discards Message 4.                                                            */

            DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsna4WHandshake", "4-way handshake message 4", DOT11DECRYPT_DEBUG_LEVEL_3);

            sa->handshake=4;

            return DOT11DECRYPT_RET_SUCCESS_HANDSHAKE;
        }
    }

    /* message 3: Authenticator->Supplicant (Sec=1, Mic=1, Ack=1, Inst=0/1, Key=1(pairwise), KeyRSC=???, Nonce=ANonce, MIC=1) */
    if (DOT11DECRYPT_EAP_ACK(data[offset+1])==1 &&
        DOT11DECRYPT_EAP_MIC(data[offset])==1)
    {
        const EAPOL_RSN_KEY *pEAPKey;
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptRsna4WHandshake", "4-way handshake message 3", DOT11DECRYPT_DEBUG_LEVEL_3);

        /* On reception of Message 3, the Supplicant silently discards the message if the Key Replay Counter field     */
        /* value has already been used or if the ANonce value in Message 3 differs from the ANonce value in Message 1. */
        /* -> not checked, the Authenticator will send another message 3 (hopefully!)                                  */

        /* TODO check page 88 (RNS) */

        /* If using WPA2 PSK, message 3 will contain an RSN for the group key (GTK KDE).
           In order to properly support decrypting WPA2-PSK packets, we need to parse this to get the group key. */
        pEAPKey = (const EAPOL_RSN_KEY *)(&(data[offset-1]));
        if (pEAPKey->type == DOT11DECRYPT_RSN_WPA2_KEY_DESCRIPTOR){
            PDOT11DECRYPT_SEC_ASSOCIATION broadcast_sa;
            DOT11DECRYPT_SEC_ASSOCIATION_ID id;

            /* Get broadcacst SA for the current BSSID */
            memcpy(id.sta, broadcast_mac, DOT11DECRYPT_MAC_LEN);
            memcpy(id.bssid, sa->saId.bssid, DOT11DECRYPT_MAC_LEN);
            broadcast_sa = Dot11DecryptGetSaPtr(ctx, &id);

            if (broadcast_sa == NULL){
                return DOT11DECRYPT_RET_REQ_DATA;
            }
            Dot11DecryptCopyKey(sa, key); /* save key used for decrypting broadcast key */
            return (Dot11DecryptDecryptWPABroadcastKey(pEAPKey, sa->wpa.ptk+16, broadcast_sa, tot_len-offset+1,
                                                       decrypt_data, decrypt_len));
        }
    }

    return DOT11DECRYPT_RET_NO_VALID_HANDSHAKE;
}

static INT
Dot11DecryptRsnaMicCheck(
    UCHAR *eapol,
    USHORT eapol_len,
    UCHAR KCK[DOT11DECRYPT_WPA_KCK_LEN],
    USHORT key_ver)
{
    UCHAR mic[DOT11DECRYPT_WPA_MICKEY_LEN];
    UCHAR c_mic[HASH_SHA1_LENGTH] = { 0 };  /* MIC 16 byte, the HMAC-SHA1 use a buffer of 20 bytes */
    int algo;

    /* copy the MIC from the EAPOL packet */
    memcpy(mic, eapol+DOT11DECRYPT_WPA_MICKEY_OFFSET+4, DOT11DECRYPT_WPA_MICKEY_LEN);

    /* set to 0 the MIC in the EAPOL packet (to calculate the MIC) */
    memset(eapol+DOT11DECRYPT_WPA_MICKEY_OFFSET+4, 0, DOT11DECRYPT_WPA_MICKEY_LEN);

    if (key_ver==DOT11DECRYPT_WPA_KEY_VER_NOT_CCMP) {
        /* use HMAC-MD5 for the EAPOL-Key MIC */
        algo = GCRY_MD_MD5;
    } else if (key_ver==DOT11DECRYPT_WPA_KEY_VER_AES_CCMP) {
        /* use HMAC-SHA1-128 for the EAPOL-Key MIC */
        algo = GCRY_MD_SHA1;
    } else {
        /* key descriptor version not recognized */
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    if (ws_hmac_buffer(algo, c_mic, eapol, eapol_len, KCK, DOT11DECRYPT_WPA_KCK_LEN)) {
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    /* compare calculated MIC with the Key MIC and return result (0 means success) */
    return memcmp(mic, c_mic, DOT11DECRYPT_WPA_MICKEY_LEN);
}

static INT
Dot11DecryptValidateKey(
    PDOT11DECRYPT_KEY_ITEM key)
{
    size_t len;
    UCHAR ret=TRUE;
    DOT11DECRYPT_DEBUG_TRACE_START("Dot11DecryptValidateKey");

    if (key==NULL) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptValidateKey", "NULL key", DOT11DECRYPT_DEBUG_LEVEL_5);
        DOT11DECRYPT_DEBUG_TRACE_START("Dot11DecryptValidateKey");
        return FALSE;
    }

    switch (key->KeyType) {
        case DOT11DECRYPT_KEY_TYPE_WEP:
            /* check key size limits */
            len=key->KeyData.Wep.WepKeyLen;
            if (len<DOT11DECRYPT_WEP_KEY_MINLEN || len>DOT11DECRYPT_WEP_KEY_MAXLEN) {
                DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptValidateKey", "WEP key: key length not accepted", DOT11DECRYPT_DEBUG_LEVEL_5);
                ret=FALSE;
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
                DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptValidateKey", "WPA-PWD key: passphrase length not accepted", DOT11DECRYPT_DEBUG_LEVEL_5);
                ret=FALSE;
            }

            len=key->UserPwd.SsidLen;
            if (len>DOT11DECRYPT_WPA_SSID_MAX_LEN) {
                DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptValidateKey", "WPA-PWD key: ssid length not accepted", DOT11DECRYPT_DEBUG_LEVEL_5);
                ret=FALSE;
            }

            break;

        case DOT11DECRYPT_KEY_TYPE_WPA_PSK:
            break;

        case DOT11DECRYPT_KEY_TYPE_WPA_PMK:
            break;

        default:
            ret=FALSE;
    }

    DOT11DECRYPT_DEBUG_TRACE_END("Dot11DecryptValidateKey");
    return ret;
}

static INT
Dot11DecryptGetSa(
    PDOT11DECRYPT_CONTEXT ctx,
    DOT11DECRYPT_SEC_ASSOCIATION_ID *id)
{
    INT sa_index;
    if (ctx->sa_index!=-1) {
        /* at least one association was stored                               */
        /* search for the association from sa_index to 0 (most recent added) */
        for (sa_index=ctx->sa_index; sa_index>=0; sa_index--) {
            if (ctx->sa[sa_index].used) {
                if (memcmp(id, &(ctx->sa[sa_index].saId), sizeof(DOT11DECRYPT_SEC_ASSOCIATION_ID))==0) {
                    ctx->index=sa_index;
                    return sa_index;
                }
            }
        }
    }

    return -1;
}

static INT
Dot11DecryptStoreSa(
    PDOT11DECRYPT_CONTEXT ctx,
    DOT11DECRYPT_SEC_ASSOCIATION_ID *id)
{
    INT last_free;
    if (ctx->first_free_index>=DOT11DECRYPT_MAX_SEC_ASSOCIATIONS_NR) {
        /* there is no empty space available. FAILURE */
        return -1;
    }
    if (ctx->sa[ctx->first_free_index].used) {
        /* last addition was in the middle of the array (and the first_free_index was just incremented by 1)   */
        /* search for a free space from the first_free_index to DOT11DECRYPT_STA_INFOS_NR (to avoid free blocks in */
        /*              the middle)                                                                            */
        for (last_free=ctx->first_free_index; last_free<DOT11DECRYPT_MAX_SEC_ASSOCIATIONS_NR; last_free++)
            if (!ctx->sa[last_free].used)
                break;

        if (last_free>=DOT11DECRYPT_MAX_SEC_ASSOCIATIONS_NR) {
            /* there is no empty space available. FAILURE */
            return -1;
        }

        /* store first free space index */
        ctx->first_free_index=last_free;
    }

    /* use this info */
    ctx->index=ctx->first_free_index;

    /* reset the info structure */
    memset(ctx->sa+ctx->index, 0, sizeof(DOT11DECRYPT_SEC_ASSOCIATION));

    ctx->sa[ctx->index].used=1;

    /* set the info structure */
    memcpy(&(ctx->sa[ctx->index].saId), id, sizeof(DOT11DECRYPT_SEC_ASSOCIATION_ID));

    /* increment by 1 the first_free_index (heuristic) */
    ctx->first_free_index++;

    /* set the sa_index if the added index is greater the the sa_index */
    if (ctx->index > ctx->sa_index)
        ctx->sa_index=ctx->index;

    return ctx->index;
}


static INT
Dot11DecryptGetSaAddress(
    const DOT11DECRYPT_MAC_FRAME_ADDR4 *frame,
    DOT11DECRYPT_SEC_ASSOCIATION_ID *id)
{
#ifdef DOT11DECRYPT_DEBUG
#define MSGBUF_LEN 255
    CHAR msgbuf[MSGBUF_LEN];
#endif

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
        const UCHAR *addr;

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

#ifdef DOT11DECRYPT_DEBUG
    g_snprintf(msgbuf, MSGBUF_LEN, "BSSID_MAC: %02X.%02X.%02X.%02X.%02X.%02X\t",
               id->bssid[0],id->bssid[1],id->bssid[2],id->bssid[3],id->bssid[4],id->bssid[5]);
    DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptGetSaAddress", msgbuf, DOT11DECRYPT_DEBUG_LEVEL_3);
    g_snprintf(msgbuf, MSGBUF_LEN, "STA_MAC: %02X.%02X.%02X.%02X.%02X.%02X\t",
               id->sta[0],id->sta[1],id->sta[2],id->sta[3],id->sta[4],id->sta[5]);
    DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptGetSaAddress", msgbuf, DOT11DECRYPT_DEBUG_LEVEL_3);
#endif

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

static const UCHAR *
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

static const UCHAR *
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

/* Function used to derive the PTK. Refer to IEEE 802.11I-2004, pag. 74
 * and IEEE 802.11i-2004, pag. 164 */
static void
Dot11DecryptRsnaPrfX(
    DOT11DECRYPT_SEC_ASSOCIATION *sa,
    const UCHAR pmk[32],
    const UCHAR snonce[32],
    const INT x,        /*      for TKIP 512, for CCMP 384 */
    UCHAR *ptk)
{
    UINT8 i;
    UCHAR R[100];
    INT offset=sizeof("Pairwise key expansion");
    UCHAR output[80]; /* allow for sha1 overflow. */

    memset(R, 0, 100);

    memcpy(R, "Pairwise key expansion", offset);

    /* Min(AA, SPA) || Max(AA, SPA) */
    if (memcmp(sa->saId.sta, sa->saId.bssid, DOT11DECRYPT_MAC_LEN) < 0)
    {
        memcpy(R + offset, sa->saId.sta, DOT11DECRYPT_MAC_LEN);
        memcpy(R + offset+DOT11DECRYPT_MAC_LEN, sa->saId.bssid, DOT11DECRYPT_MAC_LEN);
    }
    else
    {
        memcpy(R + offset, sa->saId.bssid, DOT11DECRYPT_MAC_LEN);
        memcpy(R + offset+DOT11DECRYPT_MAC_LEN, sa->saId.sta, DOT11DECRYPT_MAC_LEN);
    }

    offset+=DOT11DECRYPT_MAC_LEN*2;

    /* Min(ANonce,SNonce) || Max(ANonce,SNonce) */
    if( memcmp(snonce, sa->wpa.nonce, 32) < 0 )
    {
        memcpy(R + offset, snonce, 32);
        memcpy(R + offset + 32, sa->wpa.nonce, 32);
    }
    else
    {
        memcpy(R + offset, sa->wpa.nonce, 32);
        memcpy(R + offset + 32, snonce, 32);
    }

    offset+=32*2;

    for(i = 0; i < (x+159)/160; i++)
    {
        R[offset] = i;
        if (ws_hmac_buffer(GCRY_MD_SHA1, &output[HASH_SHA1_LENGTH * i], R, 100, pmk, 32)) {
          return;
        }
    }
    memcpy(ptk, output, x/8);
}

#define MAX_SSID_LENGTH 32 /* maximum SSID length */

static INT
Dot11DecryptRsnaPwd2PskStep(
    const guint8 *ppBytes,
    const guint ppLength,
    const CHAR *ssid,
    const size_t ssidLength,
    const INT iterations,
    const INT count,
    UCHAR *output)
{
    UCHAR digest[MAX_SSID_LENGTH+4] = { 0 };  /* SSID plus 4 bytes of count */
    INT i, j;

    if (ssidLength > MAX_SSID_LENGTH) {
        /* This "should not happen" */
        return DOT11DECRYPT_RET_UNSUCCESS;
    }

    /* U1 = PRF(P, S || INT(i)) */
    memcpy(digest, ssid, ssidLength);
    digest[ssidLength] = (UCHAR)((count>>24) & 0xff);
    digest[ssidLength+1] = (UCHAR)((count>>16) & 0xff);
    digest[ssidLength+2] = (UCHAR)((count>>8) & 0xff);
    digest[ssidLength+3] = (UCHAR)(count & 0xff);
    if (ws_hmac_buffer(GCRY_MD_SHA1, digest, digest, (guint32) ssidLength + 4, ppBytes, ppLength)) {
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

static INT
Dot11DecryptRsnaPwd2Psk(
    const CHAR *passphrase,
    const CHAR *ssid,
    const size_t ssidLength,
    UCHAR *output)
{
    UCHAR m_output[40] = { 0 };
    GByteArray *pp_ba = g_byte_array_new();

    if (!uri_str_to_bytes(passphrase, pp_ba)) {
        g_byte_array_free(pp_ba, TRUE);
        return 0;
    }

    Dot11DecryptRsnaPwd2PskStep(pp_ba->data, pp_ba->len, ssid, ssidLength, 4096, 1, m_output);
    Dot11DecryptRsnaPwd2PskStep(pp_ba->data, pp_ba->len, ssid, ssidLength, 4096, 2, &m_output[20]);

    memcpy(output, m_output, DOT11DECRYPT_WPA_PSK_LEN);
    g_byte_array_free(pp_ba, TRUE);

    return 0;
}

/*
 * Returns the decryption_key_t struct given a string describing the key.
 * Returns NULL if the input_string cannot be parsed.
 */
decryption_key_t*
parse_key_string(gchar* input_string, guint8 key_type)
{
    gchar *key, *tmp_str;
    gchar *ssid;

    GString    *key_string = NULL;
    GByteArray *ssid_ba = NULL, *key_ba;
    gboolean    res;

    gchar **tokens;
    guint n = 0;
    decryption_key_t *dk;

    if(input_string == NULL)
        return NULL;

    /*
     * Parse the input_string. WEP and WPA will be just a string
     * of hexadecimal characters (if key is wrong, null will be
     * returned...).
     * WPA-PWD should be in the form
     * <key data>[:<ssid>]
     */

    switch(key_type)
    {
    case DOT11DECRYPT_KEY_TYPE_WEP:
    case DOT11DECRYPT_KEY_TYPE_WEP_40:
    case DOT11DECRYPT_KEY_TYPE_WEP_104:

       key_ba = g_byte_array_new();
       res = hex_str_to_bytes(input_string, key_ba, FALSE);

       if (res && key_ba->len > 0) {
           /* Key is correct! It was probably an 'old style' WEP key */
           /* Create the decryption_key_t structure, fill it and return it*/
           dk = (decryption_key_t *)g_malloc(sizeof(decryption_key_t));

           dk->type = DOT11DECRYPT_KEY_TYPE_WEP;
           /* XXX - The current key handling code in the GUI requires
            * no separators and lower case */
           tmp_str = bytes_to_str(NULL, key_ba->data, key_ba->len);
           dk->key  = g_string_new(tmp_str);
           g_string_ascii_down(dk->key);
           dk->bits = key_ba->len * 8;
           dk->ssid = NULL;

           wmem_free(NULL, tmp_str);
           g_byte_array_free(key_ba, TRUE);
           return dk;
       }

       /* Key doesn't work */
       g_byte_array_free(key_ba, TRUE);
       return NULL;

    case DOT11DECRYPT_KEY_TYPE_WPA_PWD:

        tokens = g_strsplit(input_string,":",0);

        /* Tokens is a null termiated array of strings ... */
        while(tokens[n] != NULL)
            n++;

        if(n < 1)
        {
            /* Free the array of strings */
            g_strfreev(tokens);
            return NULL;
        }

        /*
         * The first token is the key
         */
        key = g_strdup(tokens[0]);

        ssid = NULL;
        /* Maybe there is a second token (an ssid, if everything else is ok) */
        if(n >= 2)
        {
           ssid = g_strdup(tokens[1]);
        }

        /* Create a new string */
        key_string = g_string_new(key);
        ssid_ba = NULL;

        /* Two (or more) tokens mean that the user entered a WPA-PWD key ... */
        if( ((key_string->len) > WPA_KEY_MAX_CHAR_SIZE) || ((key_string->len) < WPA_KEY_MIN_CHAR_SIZE))
        {
            g_string_free(key_string, TRUE);

            g_free(key);
            g_free(ssid);

            /* Free the array of strings */
            g_strfreev(tokens);
            return NULL;
        }

        if(ssid != NULL) /* more than two tokens found, means that the user specified the ssid */
        {
            ssid_ba = g_byte_array_new();
            if (! uri_str_to_bytes(ssid, ssid_ba)) {
                g_string_free(key_string, TRUE);
                g_byte_array_free(ssid_ba, TRUE);
                g_free(key);
                g_free(ssid);
                /* Free the array of strings */
                g_strfreev(tokens);
                return NULL;
            }

            if(ssid_ba->len > WPA_SSID_MAX_CHAR_SIZE)
            {
                g_string_free(key_string, TRUE);
                g_byte_array_free(ssid_ba, TRUE);

                g_free(key);
                g_free(ssid);

                /* Free the array of strings */
                g_strfreev(tokens);
                return NULL;
            }
        }

        /* Key was correct!!! Create the new decryption_key_t ... */
        dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));

        dk->type = DOT11DECRYPT_KEY_TYPE_WPA_PWD;
        dk->key  = g_string_new(key);
        dk->bits = 256; /* This is the length of the array pf bytes that will be generated using key+ssid ...*/
        dk->ssid = byte_array_dup(ssid_ba); /* NULL if ssid_ba is NULL */

        g_string_free(key_string, TRUE);
        if (ssid_ba != NULL)
            g_byte_array_free(ssid_ba, TRUE);

        g_free(key);
        g_free(ssid);

        /* Free the array of strings */
        g_strfreev(tokens);
        return dk;

    case DOT11DECRYPT_KEY_TYPE_WPA_PSK:

        key_ba = g_byte_array_new();
        res = hex_str_to_bytes(input_string, key_ba, FALSE);

        /* Two tokens means that the user should have entered a WPA-BIN key ... */
        if(!res || ((key_ba->len) != WPA_PSK_KEY_SIZE))
        {
            g_byte_array_free(key_ba, TRUE);

            /* No ssid has been created ... */
            return NULL;
        }

        /* Key was correct!!! Create the new decryption_key_t ... */
        dk = (decryption_key_t*)g_malloc(sizeof(decryption_key_t));

        dk->type = DOT11DECRYPT_KEY_TYPE_WPA_PSK;
        dk->key  = g_string_new(input_string);
        dk->bits = (guint) dk->key->len * 4;
        dk->ssid = NULL;

        g_byte_array_free(key_ba, TRUE);
        return dk;
    }

    /* Type not supported */
    return NULL;
}

void
free_key_string(decryption_key_t *dk)
{
    if (dk->key)
        g_string_free(dk->key, TRUE);
    if (dk->ssid)
        g_byte_array_free(dk->ssid, TRUE);
    g_free(dk);
}

/*
 * Returns a newly allocated string representing the given decryption_key_t
 * struct, or NULL if something is wrong...
 */
gchar*
get_key_string(decryption_key_t* dk)
{
    gchar* output_string = NULL;

    if(dk == NULL || dk->key == NULL)
        return NULL;

    switch(dk->type) {
        case DOT11DECRYPT_KEY_TYPE_WEP:
            output_string = g_strdup(dk->key->str);
            break;
        case DOT11DECRYPT_KEY_TYPE_WPA_PWD:
            if(dk->ssid == NULL)
                output_string = g_strdup(dk->key->str);
            else {
                gchar* ssid = format_uri(NULL, dk->ssid, ":");
                output_string = g_strdup_printf("%s:%s",
                    dk->key->str, ssid);
                wmem_free(NULL, ssid);
            }
            break;
        case DOT11DECRYPT_KEY_TYPE_WPA_PMK:
            output_string = g_strdup(dk->key->str);
            break;
        default:
            return NULL;
    }

    return output_string;
}

static INT
Dot11DecryptTDLSDeriveKey(
    PDOT11DECRYPT_SEC_ASSOCIATION sa,
    const guint8 *data,
#if GCRYPT_VERSION_NUMBER >= 0x010600
    guint offset_rsne,
#else
    guint offset_rsne _U_,
#endif
    guint offset_fte,
#if GCRYPT_VERSION_NUMBER >= 0x010600
    guint offset_timeout,
#else
    guint offset_timeout _U_,
#endif
    guint offset_link,
#if GCRYPT_VERSION_NUMBER >= 0x010600
    guint8 action)
#else
    guint8 action _U_)
#endif
{

    gcry_md_hd_t sha256_handle;
    gcry_md_hd_t hmac_handle;
    const guint8 *snonce, *anonce, *initiator, *responder, *bssid;
    guint8 key_input[32];
#if GCRYPT_VERSION_NUMBER >= 0x010600
    guint8 mic[16], seq_num = action + 1;
    guint8 zeros[16] = { 0 };
    gcry_mac_hd_t cmac_handle;
    size_t cmac_len = 16;
    size_t cmac_write_len;
#endif

    /* Get key input */
    anonce = &data[offset_fte + 20];
    snonce = &data[offset_fte + 52];

    gcry_md_open (&sha256_handle, GCRY_MD_SHA256, 0);
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
#if GCRYPT_VERSION_NUMBER >= 0x010600
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
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptTDLSDeriveKey", "Bad MAC len", DOT11DECRYPT_DEBUG_LEVEL_3);
        gcry_mac_close(cmac_handle);
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    gcry_mac_write(cmac_handle, &data[offset_fte + 20], cmac_write_len - 20);
    if (gcry_mac_read(cmac_handle, mic, &cmac_len) != GPG_ERR_NO_ERROR) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptTDLSDeriveKey", "MAC read error", DOT11DECRYPT_DEBUG_LEVEL_3);
        gcry_mac_close(cmac_handle);
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    if (memcmp(mic, &data[offset_fte + 4], 16)) {
        DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptTDLSDeriveKey", "MIC verification failed", DOT11DECRYPT_DEBUG_LEVEL_3);
        gcry_mac_close(cmac_handle);
        return DOT11DECRYPT_RET_UNSUCCESS;
    }
    gcry_mac_close(cmac_handle);
#else
    DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptTDLSDeriveKey", "MIC verification failed, need libgcrypt >= 1.6", DOT11DECRYPT_DEBUG_LEVEL_3);
    return DOT11DECRYPT_RET_UNSUCCESS;
#endif
    memcpy(DOT11DECRYPT_GET_TK(sa->wpa.ptk), &key_input[16], 16);
    memcpy(sa->wpa.nonce, snonce, DOT11DECRYPT_WPA_NONCE_LEN);
    sa->validKey = TRUE;
    sa->wpa.key_ver = DOT11DECRYPT_WPA_KEY_VER_AES_CCMP;
    DOT11DECRYPT_DEBUG_PRINT_LINE("Dot11DecryptTDLSDeriveKey", "MIC verified", DOT11DECRYPT_DEBUG_LEVEL_3);
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
