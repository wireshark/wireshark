/* airpdcap.c
 *
 * $Id$
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/****************************************************************************/
/*      File includes                                                           */

#include "config.h"

#include <epan/tvbuff.h>
#include <wsutil/crc32.h>
#include <epan/strutil.h>
#include <epan/emem.h>
#include <epan/pint.h>
#include <epan/crypt/rc4.h>
#include <epan/crypt/airpdcap_rijndael.h>

#include "airpdcap_system.h"
#include "airpdcap_int.h"

#include "sha1.h"
#include "md5.h"

#include "airpdcap_debug.h"

#include "wep-wpadefs.h"


/****************************************************************************/

/****************************************************************************/
/*      Constant definitions                                                    */

#define AIRPDCAP_SHA_DIGEST_LEN 20

/*      EAPOL definitions                                                       */
/**
 * Length of the EAPOL-Key key confirmation key (KCK) used to calculate
 * MIC over EAPOL frame and validate an EAPOL packet (128 bits)
 */
#define AIRPDCAP_WPA_KCK_LEN    16
/**
 *Offset of the Key MIC in the EAPOL packet body
 */
#define AIRPDCAP_WPA_MICKEY_OFFSET      77
/**
 * Maximum length of the EAPOL packet (it depends on the maximum MAC
 * frame size)
 */
#define AIRPDCAP_WPA_MAX_EAPOL_LEN      4095
/**
 * EAPOL Key Descriptor Version 1, used for all EAPOL-Key frames to and
 * from a STA when neither the group nor pairwise ciphers are CCMP for
 * Key Descriptor 1.
 * @note
 * Defined in 802.11i-2004, page 78
 */
#define AIRPDCAP_WPA_KEY_VER_NOT_CCMP   1
/**
 * EAPOL Key Descriptor Version 2, used for all EAPOL-Key frames to and
 * from a STA when either the pairwise or the group cipher is AES-CCMP
 * for Key Descriptor 2.
 * /note
 * Defined in 802.11i-2004, page 78
 */
#define AIRPDCAP_WPA_KEY_VER_AES_CCMP   2

/** Define EAPOL Key Descriptor type values:  use 254 for WPA and 2 for WPA2 **/
#define AIRPDCAP_RSN_WPA_KEY_DESCRIPTOR 254
#define AIRPDCAP_RSN_WPA2_KEY_DESCRIPTOR 2

/****************************************************************************/



/****************************************************************************/
/*      Macro definitions                                                       */

extern const UINT32 crc32_table[256];
#define CRC(crc, ch)     (crc = (crc >> 8) ^ crc32_table[(crc ^ (ch)) & 0xff])

#define AIRPDCAP_GET_TK(ptk)    (ptk + 32)

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
 * @param password [IN] pointer to a password (sequence of between 8 and
 * 63 ASCII encoded characters)
 * @param ssid [IN] pointer to the SSID string encoded in max 32 ASCII
 * encoded characters
 * @param iterations [IN] times to hash the password (4096 for WPA)
 * @param count [IN] ???
 * @param output [OUT] pointer to a preallocated buffer of
 * AIRPDCAP_SHA_DIGEST_LEN characters that will contain a part of the key
 */
static INT AirPDcapRsnaPwd2PskStep(
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
 * @param password [IN] pointer to a password (sequence of between 8 and
 * 63 ASCII encoded characters)
 * @param ssid [IN] pointer to the SSID string encoded in max 32 ASCII
 * encoded characters
 * @param output [OUT] calculated PSK (to use as PMK in WPA)
 * @note
 * Described in 802.11i-2004, page 165
 */
static INT AirPDcapRsnaPwd2Psk(
    const CHAR *passphrase,
    const CHAR *ssid,
    const size_t ssidLength,
    UCHAR *output)
    ;

static INT AirPDcapRsnaMng(
    UCHAR *decrypt_data,
    guint mac_header_len,
    guint *decrypt_len,
    PAIRPDCAP_KEY_ITEM key,
    AIRPDCAP_SEC_ASSOCIATION *sa,
    INT offset)
    ;

static INT AirPDcapWepMng(
    PAIRPDCAP_CONTEXT ctx,
    UCHAR *decrypt_data,
    guint mac_header_len,
    guint *decrypt_len,
    PAIRPDCAP_KEY_ITEM key,
    AIRPDCAP_SEC_ASSOCIATION *sa,
    INT offset)
    ;

static INT AirPDcapRsna4WHandshake(
    PAIRPDCAP_CONTEXT ctx,
    const UCHAR *data,
    AIRPDCAP_SEC_ASSOCIATION *sa,
    PAIRPDCAP_KEY_ITEM key,
    INT offset)
    ;
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
static INT AirPDcapValidateKey(
    PAIRPDCAP_KEY_ITEM key)
    ;

static INT AirPDcapRsnaMicCheck(
    UCHAR *eapol,
    USHORT eapol_len,
    UCHAR KCK[AIRPDCAP_WPA_KCK_LEN],
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
static INT AirPDcapGetSa(
    PAIRPDCAP_CONTEXT ctx,
    AIRPDCAP_SEC_ASSOCIATION_ID *id)
    ;

static INT AirPDcapStoreSa(
    PAIRPDCAP_CONTEXT ctx,
    AIRPDCAP_SEC_ASSOCIATION_ID *id)
    ;

static const UCHAR * AirPDcapGetStaAddress(
    const AIRPDCAP_MAC_FRAME_ADDR4 *frame)
    ;

static const UCHAR * AirPDcapGetBssidAddress(
    const AIRPDCAP_MAC_FRAME_ADDR4 *frame)
    ;

static void AirPDcapRsnaPrfX(
    AIRPDCAP_SEC_ASSOCIATION *sa,
    const UCHAR pmk[32],
    const UCHAR snonce[32],
    const INT x,        /*      for TKIP 512, for CCMP 384      */
    UCHAR *ptk)
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


/* NOTE : this assumes the WPA RSN IE format.  If it were to be a generic RSN IE, then
   we would need to change the structure since it could be variable length depending on the number
   of unicast OUI and auth OUI. */
typedef struct {
    guint8 bElementID;
    guint8 bLength;
    guint8  OUI[4];
    guint16 iVersion;
    guint8  multicastOUI[4];
    guint16 iUnicastCount;      /* this should always be 1 for WPA client */
    guint8  unicastOUI[4];
    guint16 iAuthCount;         /* this should always be 1 for WPA client */
    guint8  authOUI[4];
    guint16 iWPAcap;
} RSN_IE;

#define EAPKEY_MIC_LEN  16  /* length of the MIC key for EAPoL_Key packet's MIC using MD5 */
#define NONCE_LEN 32

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
    guint8  ie[sizeof(RSN_IE)]; /* Make this an array to avoid alignment issues */
} EAPOL_RSN_KEY,  * P_EAPOL_RSN_KEY;



/* A note about some limitations with the WPA decryption:

Unless someone takes the time to restructure the current method used for maintaining decryption keys, there
will be some anomalies observed when using the decryption feature.

Currently, there is only one pairwise (unicast) key and one group (broadcast) key saved for each security association
(SA).  As a result, if a wireless sniffer session captures the traffic of a station (STA) associating with an AP
more than once, or captures a STA roaming, then you will not be able to arbitrarilly click on different encrypted
packets in the trace and observe their internal decrypted structure.  This is because when you click on a packet,
Wireshark immediately performs the decryption routine with whatever the last key used was.  It does not maintain a
cache of all the keys that were used by this STA/AP pairing.

However, if you are just looking at the summary lines of a capture, it will appear that everything was decrypted properly.
This is because when first performing a capture or initially reading a capture file, Wireshark will first
process the packets in order. As it encounters new EAPOL packets, it will update its internal key list with the
newfound key. Then it will use that key for decrypting subsequent packets. Each time a new key is found, the old key
is overwritten. So, if you then click on a packet that was previously decrypted properly, it might suddenly no longer
be decrypted because a later EAPOL key had caused the internal decryption key to be updated.

For broadcast packets, there is a clunky work-around. If the AP is using group-key rotation, you simply have to find the appropriate
EAPOL group key packet (usually size is 211 bytes and will have a protocol type of EAPOL and Info field of Key). If you click on it
and then click on the broadcast packet you are trying to decrypt, the packet will be decrypted properly. By first
clicking on the EAPOL packet for the group-key, you will force Wireshark to parse that packet and load the group-key it
contains.  That group key will then be used for decrypting all subsequent broadcast packets you click on.

Ideally, it would be best to maintain an expanding list of SA keys. Perhaps we could associate packet number ranges
that they apply to.  Then, whenever we need to decrypt a packet, we can determine which key to use based on whether
it is broadcast or unicast and within what packet number range it falls.

Either that, or store two versions of encrypted packets - the orginal packet and it's successfully
decrypted version.  Then Wireshark wouldn't have to decrypt packets on the fly if they were already successfully decrypted.

*/


static void
AirPDcapDecryptWPABroadcastKey(const EAPOL_RSN_KEY *pEAPKey, guint8  *decryption_key, PAIRPDCAP_SEC_ASSOCIATION sa)
{
    guint8  new_key[32];
    guint8 key_version;
    guint8  *szEncryptedKey;
    guint16 key_len = 0;
    static AIRPDCAP_KEY_ITEM dummy_key; /* needed in case AirPDcapRsnaMng() wants the key structure */

    /* We skip verifying the MIC of the key. If we were implementing a WPA supplicant we'd want to verify, but for a sniffer it's not needed. */

    /* Preparation for decrypting the group key -  determine group key data length */
    /* depending on whether it's a TKIP or AES encryption key */
    key_version = AIRPDCAP_EAP_KEY_DESCR_VER(pEAPKey->key_information[1]);
    if (key_version == AIRPDCAP_WPA_KEY_VER_NOT_CCMP){
        /* TKIP */
        key_len = pntohs(pEAPKey->key_length);
    }else if (key_version == AIRPDCAP_WPA_KEY_VER_AES_CCMP){
        /* AES */
        key_len = pntohs(pEAPKey->key_data_len);
    }
    if (key_len > sizeof(RSN_IE) || key_len == 0) { /* Don't read past the end of pEAPKey->ie */
        return;
    }

    /* Encrypted key is in the information element field of the EAPOL key packet */
    szEncryptedKey = (guint8 *)g_memdup(pEAPKey->ie, key_len);

    DEBUG_DUMP("Encrypted Broadcast key:", szEncryptedKey, key_len);
    DEBUG_DUMP("KeyIV:", pEAPKey->key_iv, 16);
    DEBUG_DUMP("decryption_key:", decryption_key, 16);

    /* Build the full decryption key based on the IV and part of the pairwise key */
    memcpy(new_key, pEAPKey->key_iv, 16);
    memcpy(new_key+16, decryption_key, 16);
    DEBUG_DUMP("FullDecrKey:", new_key, 32);

    if (key_version == AIRPDCAP_WPA_KEY_VER_NOT_CCMP){
        guint8 dummy[256];
        /* TKIP key */
        /* Per 802.11i, Draft 3.0 spec, section 8.5.2, p. 97, line 4-8, */
        /* group key is decrypted using RC4.  Concatenate the IV with the 16 byte EK (PTK+16) to get the decryption key */

        rc4_state_struct rc4_state;
        crypt_rc4_init(&rc4_state, new_key, sizeof(new_key));

        /* Do dummy 256 iterations of the RC4 algorithm (per 802.11i, Draft 3.0, p. 97 line 6) */
        crypt_rc4(&rc4_state, dummy, 256);
        crypt_rc4(&rc4_state, szEncryptedKey, key_len);

    } else if (key_version == AIRPDCAP_WPA_KEY_VER_AES_CCMP){
        /* AES CCMP key */

        guint8 key_found;
        guint16 key_index;
        guint8 *decrypted_data;

        /* This storage is needed for the AES_unwrap function */
        decrypted_data = (guint8 *) g_malloc(key_len);

        AES_unwrap(decryption_key, 16, szEncryptedKey,  key_len, decrypted_data);

        /* With WPA2 what we get after Broadcast Key decryption is an actual RSN structure.
           The key itself is stored as a GTK KDE
           WPA2 IE (1 byte) id = 0xdd, length (1 byte), GTK OUI (4 bytes), key index (1 byte) and 1 reserved byte. Thus we have to
           pass pointer to the actual key with 8 bytes offset */

        key_found = FALSE;
        key_index = 0;
        while(key_index < key_len && !key_found){
            guint8 rsn_id;

            /* Get RSN ID */
            rsn_id = decrypted_data[key_index];

            if (rsn_id != 0xdd){
                key_index += decrypted_data[key_index+1]+2;
            }else{
                key_found = TRUE;
            }
        }

        if (key_found){
            /* Skip over the GTK header info, and don't copy past the end of the encrypted data */
            memcpy(szEncryptedKey, decrypted_data+key_index+8, key_len-key_index-8);
        }

        g_free(decrypted_data);
    }

    /* Decrypted key is now in szEncryptedKey with len of key_len */
    DEBUG_DUMP("Broadcast key:", szEncryptedKey, key_len);

    /* Load the proper key material info into the SA */
    sa->key = &dummy_key;  /* we just need key to be not null because it is checked in AirPDcapRsnaMng().  The WPA key materials are actually in the .wpa structure */
    sa->validKey = TRUE;
    sa->wpa.key_ver = key_version;

    /* Since this is a GTK and it's size is only 32 bytes (vs. the 64 byte size of a PTK), we fake it and put it in at a 32-byte offset so the  */
    /* AirPDcapRsnaMng() function will extract the right piece of the GTK for decryption. (The first 16 bytes of the GTK are used for decryption.) */
    memset(sa->wpa.ptk, 0, sizeof(sa->wpa.ptk));
    memcpy(sa->wpa.ptk+32, szEncryptedKey, key_len);
    g_free(szEncryptedKey);
}


/* Return a pointer the the requested SA. If it doesn't exist create it. */
static PAIRPDCAP_SEC_ASSOCIATION
AirPDcapGetSaPtr(
    PAIRPDCAP_CONTEXT ctx,
    AIRPDCAP_SEC_ASSOCIATION_ID *id)
{
    int sa_index;

    /* search for a cached Security Association for supplied BSSID and STA MAC  */
    if ((sa_index=AirPDcapGetSa(ctx, id))==-1) {
        /* create a new Security Association if it doesn't currently exist      */
        if ((sa_index=AirPDcapStoreSa(ctx, id))==-1) {
            return NULL;
        }
    }
    /* get the Security Association structure   */
    return &ctx->sa[sa_index];
}

#define GROUP_KEY_PAYLOAD_LEN (8+4+sizeof(EAPOL_RSN_KEY))
static INT AirPDcapScanForGroupKey(
    PAIRPDCAP_CONTEXT ctx,
    const guint8 *data,
    const guint mac_header_len,
    const guint tot_len
)
{
    const UCHAR *address;
    AIRPDCAP_SEC_ASSOCIATION_ID id;
    guint bodyLength;
    PAIRPDCAP_SEC_ASSOCIATION sta_sa;
    PAIRPDCAP_SEC_ASSOCIATION sa;
    int offset = 0;
    const guint8 dot1x_header[] = {
        0xAA,             /* DSAP=SNAP */
        0xAA,             /* SSAP=SNAP */
        0x03,             /* Control field=Unnumbered frame */
        0x00, 0x00, 0x00, /* Org. code=encaps. Ethernet */
        0x88, 0x8E        /* Type: 802.1X authentication */
    };

    const EAPOL_RSN_KEY *pEAPKey;
#ifdef _DEBUG
    CHAR msgbuf[255];
#endif

    AIRPDCAP_DEBUG_TRACE_START("AirPDcapScanForGroupKey");

    if (mac_header_len + GROUP_KEY_PAYLOAD_LEN < tot_len) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForGroupKey", "Message too short", AIRPDCAP_DEBUG_LEVEL_3);
        return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
    }

    /* cache offset in the packet data */
    offset = mac_header_len;

    /* check if the packet has an LLC header and the packet is 802.1X authentication (IEEE 802.1X-2004, pg. 24) */
    if (memcmp(data+offset, dot1x_header, 8) == 0) {

        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForGroupKey", "Authentication: EAPOL packet", AIRPDCAP_DEBUG_LEVEL_3);

        /* skip LLC header */
        offset+=8;


        /* check if the packet is a EAPOL-Key (0x03) (IEEE 802.1X-2004, pg. 25) */
        if (data[offset+1]!=3) {
            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForGroupKey", "Not EAPOL-Key", AIRPDCAP_DEBUG_LEVEL_3);
            return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
        }

        /* get and check the body length (IEEE 802.1X-2004, pg. 25) */
        bodyLength=pntohs(data+offset+2);
        if ((tot_len-offset-4) < bodyLength) {
            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForGroupKey", "EAPOL body too short", AIRPDCAP_DEBUG_LEVEL_3);
            return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
        }

        /* skip EAPOL MPDU and go to the first byte of the body */
        offset+=4;

        pEAPKey = (const EAPOL_RSN_KEY *) (data+offset);

        /* check if the key descriptor type is valid (IEEE 802.1X-2004, pg. 27) */
        if (/*pEAPKey->type!=0x1 &&*/ /* RC4 Key Descriptor Type (deprecated) */
            pEAPKey->type != AIRPDCAP_RSN_WPA2_KEY_DESCRIPTOR &&             /* IEEE 802.11 Key Descriptor Type  (WPA2) */
            pEAPKey->type != AIRPDCAP_RSN_WPA_KEY_DESCRIPTOR)           /* 254 = RSN_KEY_DESCRIPTOR - WPA,              */
        {
            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForGroupKey", "Not valid key descriptor type", AIRPDCAP_DEBUG_LEVEL_3);
            return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
        }

        /* start with descriptor body */
        offset+=1;

        /* Verify the bitfields: Key = 0(groupwise) Mic = 1 Ack = 1 Secure = 1 */
        if (AIRPDCAP_EAP_KEY(data[offset+1])!=0 ||
            AIRPDCAP_EAP_ACK(data[offset+1])!=1 ||
            AIRPDCAP_EAP_MIC(data[offset]) != 1 ||
            AIRPDCAP_EAP_SEC(data[offset]) != 1){

            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForGroupKey", "Key bitfields not correct", AIRPDCAP_DEBUG_LEVEL_3);
            return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
        }

        /* get BSSID */
        if ( (address=AirPDcapGetBssidAddress((const AIRPDCAP_MAC_FRAME_ADDR4 *)(data))) != NULL) {
            memcpy(id.bssid, address, AIRPDCAP_MAC_LEN);
#ifdef _DEBUG
            sprintf(msgbuf, "BSSID: %2X.%2X.%2X.%2X.%2X.%2X\t", id.bssid[0],id.bssid[1],id.bssid[2],id.bssid[3],id.bssid[4],id.bssid[5]);
#endif
            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForGroupKey", msgbuf, AIRPDCAP_DEBUG_LEVEL_3);
        } else {
            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForGroupKey", "BSSID not found", AIRPDCAP_DEBUG_LEVEL_5);
            return AIRPDCAP_RET_REQ_DATA;
        }

        /* force STA address to be the broadcast MAC so we create an SA for the groupkey */
        memcpy(id.sta, broadcast_mac, AIRPDCAP_MAC_LEN);

        /* get the Security Association structure for the broadcast MAC and AP */
        sa = AirPDcapGetSaPtr(ctx, &id);
        if (sa == NULL){
            return AIRPDCAP_RET_UNSUCCESS;
        }

        /* Get the SA for the STA, since we need its pairwise key to decrpyt the group key */

        /* get STA address */
        if ( (address=AirPDcapGetStaAddress((const AIRPDCAP_MAC_FRAME_ADDR4 *)(data))) != NULL) {
            memcpy(id.sta, address, AIRPDCAP_MAC_LEN);
#ifdef _DEBUG
            sprintf(msgbuf, "ST_MAC: %2X.%2X.%2X.%2X.%2X.%2X\t", id.sta[0],id.sta[1],id.sta[2],id.sta[3],id.sta[4],id.sta[5]);
#endif
            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForGroupKey", msgbuf, AIRPDCAP_DEBUG_LEVEL_3);
        } else {
            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForGroupKey", "SA not found", AIRPDCAP_DEBUG_LEVEL_5);
            return AIRPDCAP_RET_REQ_DATA;
        }

        sta_sa = AirPDcapGetSaPtr(ctx, &id);
        if (sta_sa == NULL){
            return AIRPDCAP_RET_UNSUCCESS;
        }

        /* Extract the group key and install it in the SA */
        AirPDcapDecryptWPABroadcastKey(pEAPKey, sta_sa->wpa.ptk+16, sa);

    }else{
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForGroupKey", "Skipping: not an EAPOL packet", AIRPDCAP_DEBUG_LEVEL_3);
    }

    AIRPDCAP_DEBUG_TRACE_END("AirPDcapScanForGroupKey");
    return 0;
}


INT AirPDcapPacketProcess(
    PAIRPDCAP_CONTEXT ctx,
    const guint8 *data,
    const guint mac_header_len,
    const guint tot_len,
    UCHAR *decrypt_data,
    guint *decrypt_len,
    PAIRPDCAP_KEY_ITEM key,
    gboolean mngHandshake,
    gboolean mngDecrypt)
{
    const UCHAR *address;
    AIRPDCAP_SEC_ASSOCIATION_ID id;
    PAIRPDCAP_SEC_ASSOCIATION sa;
    int offset = 0;
    guint bodyLength;
    const guint8 dot1x_header[] = {
        0xAA,             /* DSAP=SNAP */
        0xAA,             /* SSAP=SNAP */
        0x03,             /* Control field=Unnumbered frame */
        0x00, 0x00, 0x00, /* Org. code=encaps. Ethernet */
        0x88, 0x8E        /* Type: 802.1X authentication */
    };

#ifdef _DEBUG
    CHAR msgbuf[255];
#endif

    AIRPDCAP_DEBUG_TRACE_START("AirPDcapPacketProcess");

    if (ctx==NULL) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "NULL context", AIRPDCAP_DEBUG_LEVEL_5);
        AIRPDCAP_DEBUG_TRACE_END("AirPDcapPacketProcess");
        return AIRPDCAP_RET_UNSUCCESS;
    }
    if (data==NULL || tot_len==0) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "NULL data or length=0", AIRPDCAP_DEBUG_LEVEL_5);
        AIRPDCAP_DEBUG_TRACE_END("AirPDcapPacketProcess");
        return AIRPDCAP_RET_UNSUCCESS;
    }

    /* check if the packet is of data type */
    if (AIRPDCAP_TYPE(data[0])!=AIRPDCAP_TYPE_DATA) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "not data packet", AIRPDCAP_DEBUG_LEVEL_5);
        return AIRPDCAP_RET_NO_DATA;
    }

    /* check correct packet size, to avoid wrong elaboration of encryption algorithms */
    if (tot_len < (UINT)(mac_header_len+AIRPDCAP_CRYPTED_DATA_MINLEN)) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "minimum length violated", AIRPDCAP_DEBUG_LEVEL_5);
        return AIRPDCAP_RET_WRONG_DATA_SIZE;
    }

    /* get BSSID */
    if ( (address=AirPDcapGetBssidAddress((const AIRPDCAP_MAC_FRAME_ADDR4 *)(data))) != NULL) {
        memcpy(id.bssid, address, AIRPDCAP_MAC_LEN);
#ifdef _DEBUG
        sprintf(msgbuf, "BSSID: %2X.%2X.%2X.%2X.%2X.%2X\t", id.bssid[0],id.bssid[1],id.bssid[2],id.bssid[3],id.bssid[4],id.bssid[5]);
#endif
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", msgbuf, AIRPDCAP_DEBUG_LEVEL_3);
    } else {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "BSSID not found", AIRPDCAP_DEBUG_LEVEL_5);
        return AIRPDCAP_RET_REQ_DATA;
    }

    /* get STA address */
    if ( (address=AirPDcapGetStaAddress((const AIRPDCAP_MAC_FRAME_ADDR4 *)(data))) != NULL) {
        memcpy(id.sta, address, AIRPDCAP_MAC_LEN);
#ifdef _DEBUG
        sprintf(msgbuf, "ST_MAC: %2X.%2X.%2X.%2X.%2X.%2X\t", id.sta[0],id.sta[1],id.sta[2],id.sta[3],id.sta[4],id.sta[5]);
#endif
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", msgbuf, AIRPDCAP_DEBUG_LEVEL_3);
    } else {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "SA not found", AIRPDCAP_DEBUG_LEVEL_5);
        return AIRPDCAP_RET_REQ_DATA;
    }

    /* get the Security Association structure for the STA and AP */
    sa = AirPDcapGetSaPtr(ctx, &id);
    if (sa == NULL){
        return AIRPDCAP_RET_UNSUCCESS;
    }

    /* cache offset in the packet data (to scan encryption data) */
    offset = mac_header_len;

    /* check if data is encrypted (use the WEP bit in the Frame Control field) */
    if (AIRPDCAP_WEP(data[1])==0)
    {
        if (mngHandshake) {
            /* data is sent in cleartext, check if is an authentication message or end the process */
            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "Unencrypted data", AIRPDCAP_DEBUG_LEVEL_3);

            /* check if the packet as an LLC header and the packet is 802.1X authentication (IEEE 802.1X-2004, pg. 24) */
            if (memcmp(data+offset, dot1x_header, 8) == 0) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "Authentication: EAPOL packet", AIRPDCAP_DEBUG_LEVEL_3);

                /* skip LLC header */
                offset+=8;

                /* check the version of the EAPOL protocol used (IEEE 802.1X-2004, pg. 24) */
                /* TODO EAPOL protocol version to check? */
#if 0
                if (data[offset]!=2) {
                    AIRPDCAP_DEBUG_PRINT_LINE("EAPOL protocol version not recognized", AIRPDCAP_DEBUG_LEVEL_5);
                    return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
                }
#endif

                /* check if the packet is a EAPOL-Key (0x03) (IEEE 802.1X-2004, pg. 25) */
                if (data[offset+1]!=3) {
                    AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "Not EAPOL-Key", AIRPDCAP_DEBUG_LEVEL_5);
                    return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
                }

                /* get and check the body length (IEEE 802.1X-2004, pg. 25) */
                bodyLength=pntohs(data+offset+2);
                if ((tot_len-offset-4) < bodyLength) {
                    AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "EAPOL body too short", AIRPDCAP_DEBUG_LEVEL_5);
                    return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
                }

                /* skip EAPOL MPDU and go to the first byte of the body */
                offset+=4;

                /* check if the key descriptor type is valid (IEEE 802.1X-2004, pg. 27) */
                if (/*data[offset]!=0x1 &&*/    /* RC4 Key Descriptor Type (deprecated) */
                    data[offset]!=0x2 &&        /* IEEE 802.11 Key Descriptor Type      */
                    data[offset]!=0xFE)         /* TODO what's this value???            */
                {
                    AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "Not valid key descriptor type", AIRPDCAP_DEBUG_LEVEL_5);
                    return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
                }

                /* start with descriptor body */
                offset+=1;

                /* manage the 4-way handshake to define the key */
                return AirPDcapRsna4WHandshake(ctx, data, sa, key, offset);
            } else {
                /* cleartext message, not authentication */
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "No authentication data", AIRPDCAP_DEBUG_LEVEL_5);
                return AIRPDCAP_RET_NO_DATA_ENCRYPTED;
            }
        }
    } else {
        if (mngDecrypt) {

            if (decrypt_data==NULL)
                return AIRPDCAP_RET_UNSUCCESS;

            /* create new header and data to modify */
            *decrypt_len = tot_len;
            memcpy(decrypt_data, data, *decrypt_len);

            /* encrypted data */
            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "Encrypted data", AIRPDCAP_DEBUG_LEVEL_3);

            /* check the Extension IV to distinguish between WEP encryption and WPA encryption */
            /* refer to IEEE 802.11i-2004, 8.2.1.2, pag.35 for WEP,    */
            /*          IEEE 802.11i-2004, 8.3.2.2, pag. 45 for TKIP,  */
            /*          IEEE 802.11i-2004, 8.3.3.2, pag. 57 for CCMP   */
            if (AIRPDCAP_EXTIV(data[offset+3])==0) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "WEP encryption", AIRPDCAP_DEBUG_LEVEL_3);
                return AirPDcapWepMng(ctx, decrypt_data, mac_header_len, decrypt_len, key, sa, offset);
            } else {
                INT status;
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "TKIP or CCMP encryption", AIRPDCAP_DEBUG_LEVEL_3);

                /* If index >= 1, then use the group key.  This will not work if the AP is using
                   more than one group key simultaneously.  I've not seen this in practice, however.
                   Usually an AP will rotate between the two key index values of 1 and 2 whenever
                   it needs to change the group key to be used. */
                if (AIRPDCAP_KEY_INDEX(data[offset+3])>=1){

                    AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "The key index = 1. This is encrypted with a group key.", AIRPDCAP_DEBUG_LEVEL_3);

                    /* force STA address to broadcast MAC so we load the SA for the groupkey */
                    memcpy(id.sta, broadcast_mac, AIRPDCAP_MAC_LEN);

#ifdef _DEBUG
                    sprintf(msgbuf, "ST_MAC: %2X.%2X.%2X.%2X.%2X.%2X\t", id.sta[0],id.sta[1],id.sta[2],id.sta[3],id.sta[4],id.sta[5]);
                    AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", msgbuf, AIRPDCAP_DEBUG_LEVEL_3);
#endif

                    /* search for a cached Security Association for current BSSID and broadcast MAC */
                    sa = AirPDcapGetSaPtr(ctx, &id);
                    if (sa == NULL){
                        return AIRPDCAP_RET_UNSUCCESS;
                    }
                }

                /* Decrypt the packet using the appropriate SA */
                status = AirPDcapRsnaMng(decrypt_data, mac_header_len, decrypt_len, key, sa, offset);

                /* If we successfully decrypted a packet, scan it to see if it contains a group key handshake.
                   The group key handshake could be sent at any time the AP wants to change the key (such as when
                   it is using key rotation) so we must scan every packet. */
                if (status == AIRPDCAP_RET_SUCCESS)
                    AirPDcapScanForGroupKey(ctx, decrypt_data, mac_header_len, *decrypt_len);
                return status;
            }
        }
    }

    return AIRPDCAP_RET_UNSUCCESS;
}

INT AirPDcapSetKeys(
    PAIRPDCAP_CONTEXT ctx,
    AIRPDCAP_KEY_ITEM keys[],
    const size_t keys_nr)
{
    INT i;
    INT success;
    AIRPDCAP_DEBUG_TRACE_START("AirPDcapSetKeys");

    if (ctx==NULL || keys==NULL) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapSetKeys", "NULL context or NULL keys array", AIRPDCAP_DEBUG_LEVEL_3);
        AIRPDCAP_DEBUG_TRACE_END("AirPDcapSetKeys");
        return 0;
    }

    if (keys_nr>AIRPDCAP_MAX_KEYS_NR) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapSetKeys", "Keys number greater than maximum", AIRPDCAP_DEBUG_LEVEL_3);
        AIRPDCAP_DEBUG_TRACE_END("AirPDcapSetKeys");
        return 0;
    }

    /* clean key and SA collections before setting new ones */
    AirPDcapInitContext(ctx);

    /* check and insert keys */
    for (i=0, success=0; i<(INT)keys_nr; i++) {
        if (AirPDcapValidateKey(keys+i)==TRUE) {
            if (keys[i].KeyType==AIRPDCAP_KEY_TYPE_WPA_PWD) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapSetKeys", "Set a WPA-PWD key", AIRPDCAP_DEBUG_LEVEL_4);
                AirPDcapRsnaPwd2Psk(keys[i].UserPwd.Passphrase, keys[i].UserPwd.Ssid, keys[i].UserPwd.SsidLen, keys[i].KeyData.Wpa.Psk);
            }
#ifdef _DEBUG
            else if (keys[i].KeyType==AIRPDCAP_KEY_TYPE_WPA_PMK) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapSetKeys", "Set a WPA-PMK key", AIRPDCAP_DEBUG_LEVEL_4);
            } else if (keys[i].KeyType==AIRPDCAP_KEY_TYPE_WEP) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapSetKeys", "Set a WEP key", AIRPDCAP_DEBUG_LEVEL_4);
            } else {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapSetKeys", "Set a key", AIRPDCAP_DEBUG_LEVEL_4);
            }
#endif
            memcpy(&ctx->keys[success], &keys[i], sizeof(keys[i]));
            success++;
        }
    }

    ctx->keys_nr=success;

    AIRPDCAP_DEBUG_TRACE_END("AirPDcapSetKeys");
    return success;
}

static void
AirPDcapCleanKeys(
    PAIRPDCAP_CONTEXT ctx)
{
    AIRPDCAP_DEBUG_TRACE_START("AirPDcapCleanKeys");

    if (ctx==NULL) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapCleanKeys", "NULL context", AIRPDCAP_DEBUG_LEVEL_5);
        AIRPDCAP_DEBUG_TRACE_END("AirPDcapCleanKeys");
        return;
    }

    memset(ctx->keys, 0, sizeof(AIRPDCAP_KEY_ITEM) * AIRPDCAP_MAX_KEYS_NR);

    ctx->keys_nr=0;

    AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapCleanKeys", "Keys collection cleaned!", AIRPDCAP_DEBUG_LEVEL_5);
    AIRPDCAP_DEBUG_TRACE_END("AirPDcapCleanKeys");
}

INT AirPDcapGetKeys(
    const PAIRPDCAP_CONTEXT ctx,
    AIRPDCAP_KEY_ITEM keys[],
    const size_t keys_nr)
{
    UINT i;
    UINT j;
    AIRPDCAP_DEBUG_TRACE_START("AirPDcapGetKeys");

    if (ctx==NULL) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapGetKeys", "NULL context", AIRPDCAP_DEBUG_LEVEL_5);
        AIRPDCAP_DEBUG_TRACE_END("AirPDcapGetKeys");
        return 0;
    } else if (keys==NULL) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapGetKeys", "NULL keys array", AIRPDCAP_DEBUG_LEVEL_5);
        AIRPDCAP_DEBUG_TRACE_END("AirPDcapGetKeys");
        return (INT)ctx->keys_nr;
    } else {
        for (i=0, j=0; i<ctx->keys_nr && i<keys_nr && i<AIRPDCAP_MAX_KEYS_NR; i++) {
            memcpy(&keys[j], &ctx->keys[i], sizeof(keys[j]));
            j++;
            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapGetKeys", "Got a key", AIRPDCAP_DEBUG_LEVEL_5);
        }

        AIRPDCAP_DEBUG_TRACE_END("AirPDcapGetKeys");
        return j;
    }
}

/*
 * XXX - This won't be reliable if a packet containing SSID "B" shows
 * up in the middle of a 4-way handshake for SSID "A".
 * We should probably use a small array or hash table to keep multiple
 * SSIDs.
 */
INT AirPDcapSetLastSSID(
    PAIRPDCAP_CONTEXT ctx,
    CHAR *pkt_ssid,
    size_t pkt_ssid_len)
{
    if (!ctx || !pkt_ssid || pkt_ssid_len < 1 || pkt_ssid_len > WPA_SSID_MAX_SIZE)
        return AIRPDCAP_RET_UNSUCCESS;

    memcpy(ctx->pkt_ssid, pkt_ssid, pkt_ssid_len);
    ctx->pkt_ssid_len = pkt_ssid_len;

    return AIRPDCAP_RET_SUCCESS;
}

INT AirPDcapInitContext(
    PAIRPDCAP_CONTEXT ctx)
{
    AIRPDCAP_DEBUG_TRACE_START("AirPDcapInitContext");

    if (ctx==NULL) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapInitContext", "NULL context", AIRPDCAP_DEBUG_LEVEL_5);
        AIRPDCAP_DEBUG_TRACE_END("AirPDcapInitContext");
        return AIRPDCAP_RET_UNSUCCESS;
    }

    AirPDcapCleanKeys(ctx);

    ctx->first_free_index=0;
    ctx->index=-1;
    ctx->sa_index=-1;
    ctx->pkt_ssid_len = 0;

    memset(ctx->sa, 0, AIRPDCAP_MAX_SEC_ASSOCIATIONS_NR * sizeof(AIRPDCAP_SEC_ASSOCIATION));

    AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapInitContext", "Context initialized!", AIRPDCAP_DEBUG_LEVEL_5);
    AIRPDCAP_DEBUG_TRACE_END("AirPDcapInitContext");
    return AIRPDCAP_RET_SUCCESS;
}

INT AirPDcapDestroyContext(
    PAIRPDCAP_CONTEXT ctx)
{
    AIRPDCAP_DEBUG_TRACE_START("AirPDcapDestroyContext");

    if (ctx==NULL) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapDestroyContext", "NULL context", AIRPDCAP_DEBUG_LEVEL_5);
        AIRPDCAP_DEBUG_TRACE_END("AirPDcapDestroyContext");
        return AIRPDCAP_RET_UNSUCCESS;
    }

    AirPDcapCleanKeys(ctx);

    ctx->first_free_index=0;
    ctx->index=-1;
    ctx->sa_index=-1;

    AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapDestroyContext", "Context destroyed!", AIRPDCAP_DEBUG_LEVEL_5);
    AIRPDCAP_DEBUG_TRACE_END("AirPDcapDestroyContext");
    return AIRPDCAP_RET_SUCCESS;
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
AirPDcapRsnaMng(
    UCHAR *decrypt_data,
    guint mac_header_len,
    guint *decrypt_len,
    PAIRPDCAP_KEY_ITEM key,
    AIRPDCAP_SEC_ASSOCIATION *sa,
    INT offset)
{
    INT ret_value=1;
    UCHAR *try_data;
    guint try_data_len = *decrypt_len;

    if (sa->key==NULL) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsnaMng", "No key associated", AIRPDCAP_DEBUG_LEVEL_3);
        return AIRPDCAP_RET_REQ_DATA;
    }
    if (sa->validKey==FALSE) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsnaMng", "Key not yet valid", AIRPDCAP_DEBUG_LEVEL_3);
        return AIRPDCAP_RET_UNSUCCESS;
    }

    /* allocate a temp buffer for the decryption loop */
    try_data=(UCHAR *)ep_alloc(try_data_len);

    /* start of loop added by GCS */
    for(/* sa */; sa != NULL ;sa=sa->next) {

        if (*decrypt_len > try_data_len) {
            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsnaMng", "Invalid decryption length", AIRPDCAP_DEBUG_LEVEL_3);
            return AIRPDCAP_RET_UNSUCCESS;
        }

       /* copy the encrypted data into a temp buffer */
       memcpy(try_data, decrypt_data, *decrypt_len);

       if (sa->wpa.key_ver==1) {
           /* CCMP -> HMAC-MD5 is the EAPOL-Key MIC, RC4 is the EAPOL-Key encryption algorithm */
           AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsnaMng", "TKIP", AIRPDCAP_DEBUG_LEVEL_3);
           DEBUG_DUMP("ptk", sa->wpa.ptk, 64);
           DEBUG_DUMP("ptk portion used", AIRPDCAP_GET_TK(sa->wpa.ptk), 16);

           ret_value=AirPDcapTkipDecrypt(try_data+offset, *decrypt_len-offset, try_data+AIRPDCAP_TA_OFFSET, AIRPDCAP_GET_TK(sa->wpa.ptk));
           if (ret_value){
               AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsnaMng", "TKIP failed!", AIRPDCAP_DEBUG_LEVEL_3);
               continue;
           }

           AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsnaMng", "TKIP DECRYPTED!!!", AIRPDCAP_DEBUG_LEVEL_3);
           /* remove MIC (8bytes) and ICV (4bytes) from the end of packet */
           *decrypt_len-=12;
           break;
       } else {
           /* AES-CCMP -> HMAC-SHA1-128 is the EAPOL-Key MIC, AES wep_key wrap is the EAPOL-Key encryption algorithm */
           AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsnaMng", "CCMP", AIRPDCAP_DEBUG_LEVEL_3);

           ret_value=AirPDcapCcmpDecrypt(try_data, mac_header_len, (INT)*decrypt_len, AIRPDCAP_GET_TK(sa->wpa.ptk));
           if (ret_value)
              continue;

           AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsnaMng", "CCMP DECRYPTED!!!", AIRPDCAP_DEBUG_LEVEL_3);
           /* remove MIC (8bytes) from the end of packet */
           *decrypt_len-=8;
           break;
       }
    }
    /* end of loop */

    /* none of the keys worked */
    if(sa == NULL)
        return ret_value;

    if (*decrypt_len > try_data_len || *decrypt_len < 8) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsnaMng", "Invalid decryption length", AIRPDCAP_DEBUG_LEVEL_3);
        return AIRPDCAP_RET_UNSUCCESS;
    }

    /* copy the decrypted data into the decrypt buffer GCS*/
    memcpy(decrypt_data, try_data, *decrypt_len);

    /* remove protection bit */
    decrypt_data[1]&=0xBF;

    /* remove TKIP/CCMP header */
    offset = mac_header_len;
    *decrypt_len-=8;
    memmove(decrypt_data+offset, decrypt_data+offset+8, *decrypt_len-offset);

    if (key!=NULL) {
        memcpy(key, sa->key, sizeof(AIRPDCAP_KEY_ITEM));

        if (sa->wpa.key_ver==AIRPDCAP_WPA_KEY_VER_NOT_CCMP)
            key->KeyType=AIRPDCAP_KEY_TYPE_TKIP;
        else if (sa->wpa.key_ver==AIRPDCAP_WPA_KEY_VER_AES_CCMP)
            key->KeyType=AIRPDCAP_KEY_TYPE_CCMP;
    }

    return AIRPDCAP_RET_SUCCESS;
}

static INT
AirPDcapWepMng(
    PAIRPDCAP_CONTEXT ctx,
    UCHAR *decrypt_data,
    guint mac_header_len,
    guint *decrypt_len,
    PAIRPDCAP_KEY_ITEM key,
    AIRPDCAP_SEC_ASSOCIATION *sa,
    INT offset)
{
    UCHAR wep_key[AIRPDCAP_WEP_KEY_MAXLEN+AIRPDCAP_WEP_IVLEN];
    size_t keylen;
    INT ret_value=1;
    INT key_index;
    AIRPDCAP_KEY_ITEM *tmp_key;
    UINT8 useCache=FALSE;
    UCHAR *try_data;
    guint try_data_len = *decrypt_len;

    try_data = (UCHAR *)ep_alloc(try_data_len);

    if (sa->key!=NULL)
        useCache=TRUE;

    for (key_index=0; key_index<(INT)ctx->keys_nr; key_index++) {
        /* use the cached one, or try all keys */
        if (!useCache) {
            tmp_key=&ctx->keys[key_index];
        } else {
            if (sa->key!=NULL && sa->key->KeyType==AIRPDCAP_KEY_TYPE_WEP) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapWepMng", "Try cached WEP key...", AIRPDCAP_DEBUG_LEVEL_3);
                tmp_key=sa->key;
            } else {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapWepMng", "Cached key is not valid, try another WEP key...", AIRPDCAP_DEBUG_LEVEL_3);
                tmp_key=&ctx->keys[key_index];
            }
        }

        /* obviously, try only WEP keys... */
        if (tmp_key->KeyType==AIRPDCAP_KEY_TYPE_WEP)
        {
            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapWepMng", "Try WEP key...", AIRPDCAP_DEBUG_LEVEL_3);

            memset(wep_key, 0, sizeof(wep_key));
            memcpy(try_data, decrypt_data, *decrypt_len);

            /* Costruct the WEP seed: copy the IV in first 3 bytes and then the WEP key (refer to 802-11i-2004, 8.2.1.4.3, pag. 36) */
            memcpy(wep_key, try_data+mac_header_len, AIRPDCAP_WEP_IVLEN);
            keylen=tmp_key->KeyData.Wep.WepKeyLen;
            memcpy(wep_key+AIRPDCAP_WEP_IVLEN, tmp_key->KeyData.Wep.WepKey, keylen);

            ret_value=AirPDcapWepDecrypt(wep_key,
                keylen+AIRPDCAP_WEP_IVLEN,
                try_data + (mac_header_len+AIRPDCAP_WEP_IVLEN+AIRPDCAP_WEP_KIDLEN),
                *decrypt_len-(mac_header_len+AIRPDCAP_WEP_IVLEN+AIRPDCAP_WEP_KIDLEN+AIRPDCAP_CRC_LEN));

            if (ret_value == AIRPDCAP_RET_SUCCESS)
                memcpy(decrypt_data, try_data, *decrypt_len);
        }

        if (!ret_value && tmp_key->KeyType==AIRPDCAP_KEY_TYPE_WEP) {
            /* the tried key is the correct one, cached in the Security Association */

            sa->key=tmp_key;

            if (key!=NULL) {
                memcpy(key, &sa->key, sizeof(AIRPDCAP_KEY_ITEM));
                key->KeyType=AIRPDCAP_KEY_TYPE_WEP;
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

    if (ret_value)
        return ret_value;

    AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapWepMng", "WEP DECRYPTED!!!", AIRPDCAP_DEBUG_LEVEL_3);

    /* remove ICV (4bytes) from the end of packet */
    *decrypt_len-=4;

    if (*decrypt_len < 4) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapWepMng", "Decryption length too short", AIRPDCAP_DEBUG_LEVEL_3);
        return AIRPDCAP_RET_UNSUCCESS;
    }

    /* remove protection bit */
    decrypt_data[1]&=0xBF;

    /* remove IC header */
    offset = mac_header_len;
    *decrypt_len-=4;
    memcpy(decrypt_data+offset, decrypt_data+offset+AIRPDCAP_WEP_IVLEN+AIRPDCAP_WEP_KIDLEN, *decrypt_len-offset);

    return AIRPDCAP_RET_SUCCESS;
}

/* Refer to IEEE 802.11i-2004, 8.5.3, pag. 85 */
static INT
AirPDcapRsna4WHandshake(
    PAIRPDCAP_CONTEXT ctx,
    const UCHAR *data,
    AIRPDCAP_SEC_ASSOCIATION *sa,
    PAIRPDCAP_KEY_ITEM key,
    INT offset)
{
    AIRPDCAP_KEY_ITEM *tmp_key, pkt_key;
    AIRPDCAP_SEC_ASSOCIATION *tmp_sa;
    INT key_index;
    INT ret_value=1;
    UCHAR useCache=FALSE;
    UCHAR eapol[AIRPDCAP_EAPOL_MAX_LEN];
    USHORT eapol_len;

    if (sa->key!=NULL)
        useCache=TRUE;

    /* a 4-way handshake packet use a Pairwise key type (IEEE 802.11i-2004, pg. 79) */
    if (AIRPDCAP_EAP_KEY(data[offset+1])!=1) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "Group/STAKey message (not used)", AIRPDCAP_DEBUG_LEVEL_5);
        return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
    }

    /* TODO timeouts? */

    /* This saves the sa since we are reauthenticating which will overwrite our current sa GCS*/
    if(sa->handshake == 4) {
        tmp_sa=(AIRPDCAP_SEC_ASSOCIATION *)se_alloc(sizeof(AIRPDCAP_SEC_ASSOCIATION));
        memcpy(tmp_sa, sa, sizeof(AIRPDCAP_SEC_ASSOCIATION));
        sa->next=tmp_sa;
    }

    /* TODO consider key-index */

    /* TODO considera Deauthentications */

    AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "4-way handshake...", AIRPDCAP_DEBUG_LEVEL_5);

    /* manage 4-way handshake packets; this step completes the 802.1X authentication process (IEEE 802.11i-2004, pag. 85) */

    /* message 1: Authenticator->Supplicant (Sec=0, Mic=0, Ack=1, Inst=0, Key=1(pairwise), KeyRSC=0, Nonce=ANonce, MIC=0) */
    if (AIRPDCAP_EAP_INST(data[offset+1])==0 &&
        AIRPDCAP_EAP_ACK(data[offset+1])==1 &&
        AIRPDCAP_EAP_MIC(data[offset])==0)
    {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "4-way handshake message 1", AIRPDCAP_DEBUG_LEVEL_3);

        /* On reception of Message 1, the Supplicant determines whether the Key Replay Counter field value has been        */
        /* used before with the current PMKSA. If the Key Replay Counter field value is less than or equal to the current  */
        /* local value, the Supplicant discards the message.                                                               */
        /* -> not checked, the Authenticator will be send another Message 1 (hopefully!)                                   */

        /* save ANonce (from authenticator) to derive the PTK with the SNonce (from the 2 message) */
        memcpy(sa->wpa.nonce, data+offset+12, 32);

        /* get the Key Descriptor Version (to select algorithm used in decryption -CCMP or TKIP-) */
        sa->wpa.key_ver=AIRPDCAP_EAP_KEY_DESCR_VER(data[offset+1]);

        sa->handshake=1;

        return AIRPDCAP_RET_SUCCESS_HANDSHAKE;
    }

    /* message 2|4: Supplicant->Authenticator (Sec=0|1, Mic=1, Ack=0, Inst=0, Key=1(pairwise), KeyRSC=0, Nonce=SNonce|0, MIC=MIC(KCK,EAPOL)) */
    if (AIRPDCAP_EAP_INST(data[offset+1])==0 &&
        AIRPDCAP_EAP_ACK(data[offset+1])==0 &&
        AIRPDCAP_EAP_MIC(data[offset])==1)
    {
        if (AIRPDCAP_EAP_SEC(data[offset])==0) {

            /* PATCH: some implementations set secure bit to 0 also in the 4th message */
            /*          to recognize which message is this check if wep_key data length is 0     */
            /*          in the 4th message                                                       */
            if (data[offset+92]!=0 || data[offset+93]!=0) {
                /* message 2 */
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "4-way handshake message 2", AIRPDCAP_DEBUG_LEVEL_3);

                /* On reception of Message 2, the Authenticator checks that the key replay counter corresponds to the */
                /* outstanding Message 1. If not, it silently discards the message.                                   */
                /* If the calculated MIC does not match the MIC that the Supplicant included in the EAPOL-Key frame,  */
                /* the Authenticator silently discards Message 2.                                                     */
                /* -> not checked; the Supplicant will send another message 2 (hopefully!)                            */

                /* now you can derive the PTK */
                for (key_index=0; key_index<(INT)ctx->keys_nr || useCache; key_index++) {
                    /* use the cached one, or try all keys */
                    if (!useCache) {
                        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "Try WPA key...", AIRPDCAP_DEBUG_LEVEL_3);
                        tmp_key=&ctx->keys[key_index];
                    } else {
                        /* there is a cached key in the security association, if it's a WPA key try it... */
                        if (sa->key!=NULL &&
                            (sa->key->KeyType==AIRPDCAP_KEY_TYPE_WPA_PWD ||
                             sa->key->KeyType==AIRPDCAP_KEY_TYPE_WPA_PSK ||
                             sa->key->KeyType==AIRPDCAP_KEY_TYPE_WPA_PMK)) {
                                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "Try cached WPA key...", AIRPDCAP_DEBUG_LEVEL_3);
                                tmp_key=sa->key;
                        } else {
                            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "Cached key is of a wrong type, try WPA key...", AIRPDCAP_DEBUG_LEVEL_3);
                            tmp_key=&ctx->keys[key_index];
                        }
                    }

                    /* obviously, try only WPA keys... */
                    if (tmp_key->KeyType==AIRPDCAP_KEY_TYPE_WPA_PWD ||
                        tmp_key->KeyType==AIRPDCAP_KEY_TYPE_WPA_PSK ||
                        tmp_key->KeyType==AIRPDCAP_KEY_TYPE_WPA_PMK)
                    {
                        if (tmp_key->KeyType == AIRPDCAP_KEY_TYPE_WPA_PWD && tmp_key->UserPwd.SsidLen == 0 && ctx->pkt_ssid_len > 0 && ctx->pkt_ssid_len <= AIRPDCAP_WPA_SSID_MAX_LEN) {
                            /* We have a "wildcard" SSID.  Use the one from the packet. */
                            memcpy(&pkt_key, tmp_key, sizeof(pkt_key));
                            memcpy(&pkt_key.UserPwd.Ssid, ctx->pkt_ssid, ctx->pkt_ssid_len);
                             pkt_key.UserPwd.SsidLen = ctx->pkt_ssid_len;
                            AirPDcapRsnaPwd2Psk(pkt_key.UserPwd.Passphrase, pkt_key.UserPwd.Ssid,
                                pkt_key.UserPwd.SsidLen, pkt_key.KeyData.Wpa.Psk);
                            tmp_key = &pkt_key;
                        }

                        /* derive the PTK from the BSSID, STA MAC, PMK, SNonce, ANonce */
                        AirPDcapRsnaPrfX(sa,                            /* authenticator nonce, bssid, station mac */
                                         tmp_key->KeyData.Wpa.Pmk,      /* PMK */
                                         data+offset+12,                /* supplicant nonce */
                                         512,
                                         sa->wpa.ptk);

                        /* verify the MIC (compare the MIC in the packet included in this message with a MIC calculated with the PTK) */
                        eapol_len=pntohs(data+offset-3)+4;
                        memcpy(eapol, &data[offset-5], (eapol_len<AIRPDCAP_EAPOL_MAX_LEN?eapol_len:AIRPDCAP_EAPOL_MAX_LEN));
                        ret_value=AirPDcapRsnaMicCheck(eapol,           /*      eapol frame (header also) */
                                                       eapol_len,       /*      eapol frame length        */
                                                       sa->wpa.ptk,     /*      Key Confirmation Key      */
                                                       AIRPDCAP_EAP_KEY_DESCR_VER(data[offset+1])); /*  EAPOL-Key description version */

                        /* If the MIC is valid, the Authenticator checks that the RSN information element bit-wise matches       */
                        /* that from the (Re)Association Request message.                                                        */
                        /*              i) TODO If these are not exactly the same, the Authenticator uses MLME-DEAUTHENTICATE.request */
                        /* primitive to terminate the association.                                                               */
                        /*              ii) If they do match bit-wise, the Authenticator constructs Message 3.                   */
                    }

                    if (!ret_value &&
                        (tmp_key->KeyType==AIRPDCAP_KEY_TYPE_WPA_PWD ||
                        tmp_key->KeyType==AIRPDCAP_KEY_TYPE_WPA_PSK ||
                        tmp_key->KeyType==AIRPDCAP_KEY_TYPE_WPA_PMK))
                    {
                        /* the temporary key is the correct one, cached in the Security Association */

                        sa->key=tmp_key;

                        if (key!=NULL) {
                            memcpy(key, &tmp_key, sizeof(AIRPDCAP_KEY_ITEM));
                            if (AIRPDCAP_EAP_KEY_DESCR_VER(data[offset+1])==AIRPDCAP_WPA_KEY_VER_NOT_CCMP)
                                key->KeyType=AIRPDCAP_KEY_TYPE_TKIP;
                            else if (AIRPDCAP_EAP_KEY_DESCR_VER(data[offset+1])==AIRPDCAP_WPA_KEY_VER_AES_CCMP)
                                key->KeyType=AIRPDCAP_KEY_TYPE_CCMP;
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

                if (ret_value) {
                    AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "handshake step failed", AIRPDCAP_DEBUG_LEVEL_3);
                    return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
                }

                sa->handshake=2;

                return AIRPDCAP_RET_SUCCESS_HANDSHAKE;
            } else {
                /* message 4 */

                /* TODO "Note that when the 4-Way Handshake is first used Message 4 is sent in the clear." */

                /* TODO check MIC and Replay Counter                                                                     */
                /* On reception of Message 4, the Authenticator verifies that the Key Replay Counter field value is one  */
                /* that it used on this 4-Way Handshake; if it is not, it silently discards the message.                 */
                /* If the calculated MIC does not match the MIC that the Supplicant included in the EAPOL-Key frame, the */
                /* Authenticator silently discards Message 4.                                                            */

                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "4-way handshake message 4 (patched)", AIRPDCAP_DEBUG_LEVEL_3);

                sa->handshake=4;

                sa->validKey=TRUE;

                return AIRPDCAP_RET_SUCCESS_HANDSHAKE;
            }
            /* END OF PATCH      */
            /*                   */
        } else {
            /* message 4 */

            /* TODO "Note that when the 4-Way Handshake is first used Message 4 is sent in the clear." */

            /* TODO check MIC and Replay Counter                                                                     */
            /* On reception of Message 4, the Authenticator verifies that the Key Replay Counter field value is one  */
            /* that it used on this 4-Way Handshake; if it is not, it silently discards the message.                 */
            /* If the calculated MIC does not match the MIC that the Supplicant included in the EAPOL-Key frame, the */
            /* Authenticator silently discards Message 4.                                                            */

            AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "4-way handshake message 4", AIRPDCAP_DEBUG_LEVEL_3);

            sa->handshake=4;

            sa->validKey=TRUE;

            return AIRPDCAP_RET_SUCCESS_HANDSHAKE;
        }
    }

    /* message 3: Authenticator->Supplicant (Sec=1, Mic=1, Ack=1, Inst=0/1, Key=1(pairwise), KeyRSC=???, Nonce=ANonce, MIC=1) */
    if (AIRPDCAP_EAP_ACK(data[offset+1])==1 &&
        AIRPDCAP_EAP_MIC(data[offset])==1)
    {
        const EAPOL_RSN_KEY *pEAPKey;
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "4-way handshake message 3", AIRPDCAP_DEBUG_LEVEL_3);

        /* On reception of Message 3, the Supplicant silently discards the message if the Key Replay Counter field     */
        /* value has already been used or if the ANonce value in Message 3 differs from the ANonce value in Message 1. */
        /* -> not checked, the Authenticator will send another message 3 (hopefully!)                                  */

        /* TODO check page 88 (RNS) */

        /* If using WPA2 PSK, message 3 will contain an RSN for the group key (GTK KDE).
           In order to properly support decrypting WPA2-PSK packets, we need to parse this to get the group key. */
        pEAPKey = (const EAPOL_RSN_KEY *)(&(data[offset-1]));
        if (pEAPKey->type == AIRPDCAP_RSN_WPA2_KEY_DESCRIPTOR){
            PAIRPDCAP_SEC_ASSOCIATION broadcast_sa;
            AIRPDCAP_SEC_ASSOCIATION_ID id;

            /* Get broadcacst SA for the current BSSID */
            memcpy(id.sta, broadcast_mac, AIRPDCAP_MAC_LEN);
            memcpy(id.bssid, sa->saId.bssid, AIRPDCAP_MAC_LEN);
            broadcast_sa = AirPDcapGetSaPtr(ctx, &id);

            if (broadcast_sa == NULL){
                return AIRPDCAP_RET_UNSUCCESS;
            }
            AirPDcapDecryptWPABroadcastKey(pEAPKey, sa->wpa.ptk+16, broadcast_sa);
        }

        return AIRPDCAP_RET_SUCCESS_HANDSHAKE;
    }

    return AIRPDCAP_RET_UNSUCCESS;
}

static INT
AirPDcapRsnaMicCheck(
    UCHAR *eapol,
    USHORT eapol_len,
    UCHAR KCK[AIRPDCAP_WPA_KCK_LEN],
    USHORT key_ver)
{
    UCHAR mic[AIRPDCAP_WPA_MICKEY_LEN];
    UCHAR c_mic[20];  /* MIC 16 byte, the HMAC-SHA1 use a buffer of 20 bytes */

    /* copy the MIC from the EAPOL packet */
    memcpy(mic, eapol+AIRPDCAP_WPA_MICKEY_OFFSET+4, AIRPDCAP_WPA_MICKEY_LEN);

    /* set to 0 the MIC in the EAPOL packet (to calculate the MIC) */
    memset(eapol+AIRPDCAP_WPA_MICKEY_OFFSET+4, 0, AIRPDCAP_WPA_MICKEY_LEN);

    if (key_ver==AIRPDCAP_WPA_KEY_VER_NOT_CCMP) {
        /* use HMAC-MD5 for the EAPOL-Key MIC */
        md5_hmac(eapol, eapol_len, KCK, AIRPDCAP_WPA_KCK_LEN, c_mic);
    } else if (key_ver==AIRPDCAP_WPA_KEY_VER_AES_CCMP) {
        /* use HMAC-SHA1-128 for the EAPOL-Key MIC */
        sha1_hmac(KCK, AIRPDCAP_WPA_KCK_LEN, eapol, eapol_len, c_mic);
    } else
        /* key descriptor version not recognized */
        return AIRPDCAP_RET_UNSUCCESS;

    /* compare calculated MIC with the Key MIC and return result (0 means success) */
    return memcmp(mic, c_mic, AIRPDCAP_WPA_MICKEY_LEN);
}

static INT
AirPDcapValidateKey(
    PAIRPDCAP_KEY_ITEM key)
{
    size_t len;
    UCHAR ret=TRUE;
    AIRPDCAP_DEBUG_TRACE_START("AirPDcapValidateKey");

    if (key==NULL) {
        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapValidateKey", "NULL key", AIRPDCAP_DEBUG_LEVEL_5);
        AIRPDCAP_DEBUG_TRACE_START("AirPDcapValidateKey");
        return FALSE;
    }

    switch (key->KeyType) {
        case AIRPDCAP_KEY_TYPE_WEP:
            /* check key size limits */
            len=key->KeyData.Wep.WepKeyLen;
            if (len<AIRPDCAP_WEP_KEY_MINLEN || len>AIRPDCAP_WEP_KEY_MAXLEN) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapValidateKey", "WEP key: key length not accepted", AIRPDCAP_DEBUG_LEVEL_5);
                ret=FALSE;
            }
            break;

        case AIRPDCAP_KEY_TYPE_WEP_40:
            /* set the standard length and use a generic WEP key type */
            key->KeyData.Wep.WepKeyLen=AIRPDCAP_WEP_40_KEY_LEN;
            key->KeyType=AIRPDCAP_KEY_TYPE_WEP;
            break;

        case AIRPDCAP_KEY_TYPE_WEP_104:
            /* set the standard length and use a generic WEP key type */
            key->KeyData.Wep.WepKeyLen=AIRPDCAP_WEP_104_KEY_LEN;
            key->KeyType=AIRPDCAP_KEY_TYPE_WEP;
            break;

        case AIRPDCAP_KEY_TYPE_WPA_PWD:
            /* check passphrase and SSID size limits */
            len=strlen(key->UserPwd.Passphrase);
            if (len<AIRPDCAP_WPA_PASSPHRASE_MIN_LEN || len>AIRPDCAP_WPA_PASSPHRASE_MAX_LEN) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapValidateKey", "WPA-PWD key: passphrase length not accepted", AIRPDCAP_DEBUG_LEVEL_5);
                ret=FALSE;
            }

            len=key->UserPwd.SsidLen;
            if (len>AIRPDCAP_WPA_SSID_MAX_LEN) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapValidateKey", "WPA-PWD key: ssid length not accepted", AIRPDCAP_DEBUG_LEVEL_5);
                ret=FALSE;
            }

            break;

        case AIRPDCAP_KEY_TYPE_WPA_PSK:
            break;

        case AIRPDCAP_KEY_TYPE_WPA_PMK:
            break;

        default:
            ret=FALSE;
    }

    AIRPDCAP_DEBUG_TRACE_END("AirPDcapValidateKey");
    return ret;
}

static INT
AirPDcapGetSa(
    PAIRPDCAP_CONTEXT ctx,
    AIRPDCAP_SEC_ASSOCIATION_ID *id)
{
    INT sa_index;

    if (ctx->sa_index!=-1) {
        /* at least one association was stored                               */
        /* search for the association from sa_index to 0 (most recent added) */
        for (sa_index=ctx->sa_index; sa_index>=0; sa_index--) {
            if (ctx->sa[sa_index].used) {
                if (memcmp(id, &(ctx->sa[sa_index].saId), sizeof(AIRPDCAP_SEC_ASSOCIATION_ID))==0) {
                    ctx->index=sa_index;
                    return sa_index;
                }
            }
        }
    }

    return -1;
}

static INT
AirPDcapStoreSa(
    PAIRPDCAP_CONTEXT ctx,
    AIRPDCAP_SEC_ASSOCIATION_ID *id)
{
    INT last_free;

    if (ctx->sa[ctx->first_free_index].used) {
        /* last addition was in the middle of the array (and the first_free_index was just incremented by 1)   */
        /* search for a free space from the first_free_index to AIRPDCAP_STA_INFOS_NR (to avoid free blocks in */
        /*              the middle)                                                                            */
        for (last_free=ctx->first_free_index; last_free<AIRPDCAP_MAX_SEC_ASSOCIATIONS_NR; last_free++)
            if (!ctx->sa[last_free].used)
                break;

        if (last_free>=AIRPDCAP_MAX_SEC_ASSOCIATIONS_NR) {
            /* there is no empty space available. FAILURE */
            return -1;
        }

        /* store first free space index */
        ctx->first_free_index=last_free;
    }

    /* use this info */
    ctx->index=ctx->first_free_index;

    /* reset the info structure */
    memset(ctx->sa+ctx->index, 0, sizeof(AIRPDCAP_SEC_ASSOCIATION));

    ctx->sa[ctx->index].used=1;

    /* set the info structure */
    memcpy(&(ctx->sa[ctx->index].saId), id, sizeof(AIRPDCAP_SEC_ASSOCIATION_ID));

    /* increment by 1 the first_free_index (heuristic) */
    ctx->first_free_index++;

    /* set the sa_index if the added index is greater the the sa_index */
    if (ctx->index > ctx->sa_index)
        ctx->sa_index=ctx->index;

    return ctx->index;
}

/*
 * AirPDcapGetBssidAddress() and AirPDcapGetBssidAddress() are used for
 * key caching.  In each case, it's more important to return a value than
 * to return a _correct_ value, so we fudge addresses in some cases, e.g.
 * the BSSID in bridged connections.
 * FromDS    ToDS    Sta    BSSID
 * 0         0       addr2  addr3
 * 0         1       addr2  addr1
 * 1         0       addr1  addr2
 * 1         1       addr2  addr1
 */

static const UCHAR *
AirPDcapGetStaAddress(
    const AIRPDCAP_MAC_FRAME_ADDR4 *frame)
{
    switch(AIRPDCAP_DS_BITS(frame->fc[1])) { /* Bit 1 = FromDS, bit 0 = ToDS */
        case 0:
        case 1:
        case 3:
            return frame->addr2;
        case 2:
            return frame->addr1;
        default:
            return NULL;
    }
}

static const UCHAR *
AirPDcapGetBssidAddress(
    const AIRPDCAP_MAC_FRAME_ADDR4 *frame)
{
    switch(AIRPDCAP_DS_BITS(frame->fc[1])) { /* Bit 1 = FromDS, bit 0 = ToDS */
        case 0:
            return frame->addr3;
        case 1:
        case 3:
            return frame->addr1;
        case 2:
            return frame->addr2;
        default:
            return NULL;
    }
}

/* Function used to derive the PTK. Refer to IEEE 802.11I-2004, pag. 74 */
static void
AirPDcapRsnaPrfX(
    AIRPDCAP_SEC_ASSOCIATION *sa,
    const UCHAR pmk[32],
    const UCHAR snonce[32],
    const INT x,        /*      for TKIP 512, for CCMP 384 */
    UCHAR *ptk)
{
    UINT8 i;
    UCHAR R[100];
    INT offset=sizeof("Pairwise key expansion");

    memset(R, 0, 100);

    memcpy(R, "Pairwise key expansion", offset);

    /* Min(AA, SPA) || Max(AA, SPA) */
    if (memcmp(sa->saId.sta, sa->saId.bssid, AIRPDCAP_MAC_LEN) < 0)
    {
        memcpy(R + offset, sa->saId.sta, AIRPDCAP_MAC_LEN);
        memcpy(R + offset+AIRPDCAP_MAC_LEN, sa->saId.bssid, AIRPDCAP_MAC_LEN);
    }
    else
    {
        memcpy(R + offset, sa->saId.bssid, AIRPDCAP_MAC_LEN);
        memcpy(R + offset+AIRPDCAP_MAC_LEN, sa->saId.sta, AIRPDCAP_MAC_LEN);
    }

    offset+=AIRPDCAP_MAC_LEN*2;

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
        sha1_hmac(pmk, 32, R, 100, ptk + i * 20);
    }
}

static INT
AirPDcapRsnaPwd2PskStep(
    const guint8 *ppBytes,
    const guint ppLength,
    const CHAR *ssid,
    const size_t ssidLength,
    const INT iterations,
    const INT count,
    UCHAR *output)
{
    UCHAR digest[64], digest1[64];
    INT i, j;

    if (ssidLength+4 > 36)
        return AIRPDCAP_RET_UNSUCCESS;

    memset(digest, 0, 64);
    memset(digest1, 0, 64);

    /* U1 = PRF(P, S || INT(i)) */
    memcpy(digest, ssid, ssidLength);
    digest[ssidLength] = (UCHAR)((count>>24) & 0xff);
    digest[ssidLength+1] = (UCHAR)((count>>16) & 0xff);
    digest[ssidLength+2] = (UCHAR)((count>>8) & 0xff);
    digest[ssidLength+3] = (UCHAR)(count & 0xff);
    sha1_hmac(ppBytes, ppLength, digest, (guint32) ssidLength+4, digest1);

    /* output = U1 */
    memcpy(output, digest1, AIRPDCAP_SHA_DIGEST_LEN);
    for (i = 1; i < iterations; i++) {
        /* Un = PRF(P, Un-1) */
        sha1_hmac(ppBytes, ppLength, digest1, AIRPDCAP_SHA_DIGEST_LEN, digest);

        memcpy(digest1, digest, AIRPDCAP_SHA_DIGEST_LEN);
        /* output = output xor Un */
        for (j = 0; j < AIRPDCAP_SHA_DIGEST_LEN; j++) {
            output[j] ^= digest[j];
        }
    }

    return AIRPDCAP_RET_SUCCESS;
}

static INT
AirPDcapRsnaPwd2Psk(
    const CHAR *passphrase,
    const CHAR *ssid,
    const size_t ssidLength,
    UCHAR *output)
{
    UCHAR m_output[AIRPDCAP_WPA_PSK_LEN];
    GByteArray *pp_ba = g_byte_array_new();

    memset(m_output, 0, AIRPDCAP_WPA_PSK_LEN);

    if (!uri_str_to_bytes(passphrase, pp_ba)) {
        g_byte_array_free(pp_ba, TRUE);
        return 0;
    }

    AirPDcapRsnaPwd2PskStep(pp_ba->data, pp_ba->len, ssid, ssidLength, 4096, 1, m_output);
    AirPDcapRsnaPwd2PskStep(pp_ba->data, pp_ba->len, ssid, ssidLength, 4096, 2, &m_output[AIRPDCAP_SHA_DIGEST_LEN]);

    memcpy(output, m_output, AIRPDCAP_WPA_PSK_LEN);
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
    gchar *key;
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
    case AIRPDCAP_KEY_TYPE_WEP:
    case AIRPDCAP_KEY_TYPE_WEP_40:
    case AIRPDCAP_KEY_TYPE_WEP_104:

       key_ba = g_byte_array_new();
       res = hex_str_to_bytes(input_string, key_ba, FALSE);

       if (res && key_ba->len > 0) {
           /* Key is correct! It was probably an 'old style' WEP key */
           /* Create the decryption_key_t structure, fill it and return it*/
           dk = (decryption_key_t *)g_malloc(sizeof(decryption_key_t));

           dk->type = AIRPDCAP_KEY_TYPE_WEP;
           /* XXX - The current key handling code in the GUI requires
            * no separators and lower case */
           dk->key  = g_string_new(bytes_to_str(key_ba->data, key_ba->len));
           g_string_ascii_down(dk->key);
           dk->bits = key_ba->len * 8;
           dk->ssid = NULL;

           g_byte_array_free(key_ba, TRUE);
           return dk;
       }

       /* Key doesn't work */
       g_byte_array_free(key_ba, TRUE);
       return NULL;

    case AIRPDCAP_KEY_TYPE_WPA_PWD:

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

        dk->type = AIRPDCAP_KEY_TYPE_WPA_PWD;
        dk->key  = g_string_new(key);
        dk->bits = 256; /* This is the length of the array pf bytes that will be generated using key+ssid ...*/
        dk->ssid = byte_array_dup(ssid_ba); /* NULL if ssid_ba is NULL */

        g_string_free(key_string, TRUE);
        if (ssid_ba != NULL)
            g_byte_array_free(ssid_ba, TRUE);

        g_free(key);
        if(ssid != NULL)
            g_free(ssid);

        /* Free the array of strings */
        g_strfreev(tokens);
        return dk;

    case AIRPDCAP_KEY_TYPE_WPA_PSK:

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

        dk->type = AIRPDCAP_KEY_TYPE_WPA_PSK;
        dk->key  = g_string_new(input_string);
        dk->bits = (guint) dk->key->len * 4;
        dk->ssid = NULL;

        g_byte_array_free(key_ba, TRUE);
        return dk;
    }

    /* Type not supported */
    return NULL;
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
        case AIRPDCAP_KEY_TYPE_WEP:
            output_string = g_strdup_printf("%s:%s",STRING_KEY_TYPE_WEP,dk->key->str);
            break;
        case AIRPDCAP_KEY_TYPE_WPA_PWD:
            if(dk->ssid == NULL)
                output_string = g_strdup_printf("%s:%s",STRING_KEY_TYPE_WPA_PWD,dk->key->str);
            else
                output_string = g_strdup_printf("%s:%s:%s",
                    STRING_KEY_TYPE_WPA_PWD, dk->key->str,
                    format_uri(dk->ssid, ":"));
            break;
        case AIRPDCAP_KEY_TYPE_WPA_PMK:
            output_string = g_strdup_printf("%s:%s",STRING_KEY_TYPE_WPA_PSK,dk->key->str);
            break;
        default:
            return NULL;
    }

    return output_string;
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
