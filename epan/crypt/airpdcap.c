/****************************************************************************/
/*	File includes								*/

#include "airpdcap_system.h"
#include "airpdcap_int.h"

#include "airpdcap_wep.h"
#include "airpdcap_sha1.h"

#include "airpdcap_debug.h"

/****************************************************************************/

/****************************************************************************/
/*	Constant definitions							*/

#define	AIRPDCAP_SHA_DIGEST_LEN	20

/*	EAPOL definitions							*/
/**
 * Length of the EAPOL-Key key confirmation key (KCK) used to calculate
 * MIC over EAPOL frame and validate an EAPOL packet (128 bits)
 */
#define	AIRPDCAP_WPA_KCK_LEN	16
/**
 *Offset of the Key MIC in the EAPOL packet body
 */
#define	AIRPDCAP_WPA_MICKEY_OFFSET	77
/**
 * Maximum length of the EAPOL packet (it depends on the maximum MAC
 * frame size)
 */
#define	AIRPDCAP_WPA_MAX_EAPOL_LEN	4095
/**
 * EAPOL Key Descriptor Version 1, used for all EAPOL-Key frames to and
 * from a STA when neither the group nor pairwise ciphers are CCMP for
 * Key Descriptor 1.
 * @note
 * Defined in 802.11i-2004, page 78
 */
#define	AIRPDCAP_WPA_KEY_VER_CCMP	1
/**
 * EAPOL Key Descriptor Version 2, used for all EAPOL-Key frames to and
 * from a STA when either the pairwise or the group cipher is AES-CCMP
 * for Key Descriptor 2.
 * /note
 * Defined in 802.11i-2004, page 78
 */
#define	AIRPDCAP_WPA_KEY_VER_AES_CCMP	2

/****************************************************************************/

/****************************************************************************/
/*	Macro definitions							*/

extern const UINT32 crc32_table[256];
#define CRC(crc, ch)	 (crc = (crc >> 8) ^ crc32_table[(crc ^ (ch)) & 0xff])

#define	AIRPDCAP_GET_TK(ptk)	(ptk + 32)

/****************************************************************************/

/****************************************************************************/
/*	Type definitions							*/

/*	Internal function prototype declarations				*/

#ifdef	__cplusplus
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
INT AirPDcapRsnaPwd2PskStep(
        const CHAR *password,
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
INT AirPDcapRsnaPwd2Psk(
        const CHAR *password,
        const CHAR *ssid,
        const size_t ssidLength,
        UCHAR *output)
        ;

INT AirPDcapRsnaMng(
        UCHAR *decrypt_data,
        size_t *decrypt_len,
        PAIRPDCAP_KEY_ITEM key,
        AIRPDCAP_SEC_ASSOCIATION *sa,
        INT offset,
        UINT8 fcsPresent)
        ;

INT AirPDcapWepMng(
        PAIRPDCAP_CONTEXT ctx,
        UCHAR *decrypt_data,
        size_t *decrypt_len,
        PAIRPDCAP_KEY_ITEM key,
        AIRPDCAP_SEC_ASSOCIATION *sa,
        INT offset,
        UINT8 fcsPresent)
        ;

INT AirPDcapRsna4WHandshake(
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
INT AirPDcapValidateKey(
        PAIRPDCAP_KEY_ITEM key)
        ;

INT AirPDcapRsnaMicCheck(
        UCHAR *eapol,
        const USHORT eapol_len,
        const UCHAR KCK[AIRPDCAP_WPA_KCK_LEN],
        const USHORT key_ver)
        ;

/**
 * @param ctx [IN] pointer to the current context
 * @param id [IN] id of the association (composed by BSSID and MAC of
 * the station)
 * @return
 * - index of the Security Association structure if found
 * - -1, if the specified addresses pair BSSID-STA MAC has not been found
 */
INT AirPDcapGetSa(
        PAIRPDCAP_CONTEXT ctx,
        AIRPDCAP_SEC_ASSOCIATION_ID *id)
        ;

INT AirPDcapFreeSa(
        PAIRPDCAP_CONTEXT ctx,
        INT index)	/* index of the structure to free		*/
        ;

INT AirPDcapStoreSa(
        PAIRPDCAP_CONTEXT ctx,
        AIRPDCAP_SEC_ASSOCIATION_ID *id)
        ;

UCHAR * AirPDcapGetStaAddress(
        PAIRPDCAP_MAC_FRAME frame)
        ;

UCHAR * AirPDcapGetBssidAddress(
        PAIRPDCAP_MAC_FRAME frame)
        ;

void AirPDcapRsnaPrfX(
        AIRPDCAP_SEC_ASSOCIATION *sa,
        const UCHAR pmk[32],
        const UCHAR snonce[32],
        const INT x,	/*	for TKIP 512, for CCMP 384	*/
        UCHAR *ptk)
        ;

INT AirPDcapAlgCrc32(
        UCHAR *buf,
        size_t nr,
        ULONG *cval)
        ;

#ifdef	__cplusplus
}
#endif

/****************************************************************************/

/****************************************************************************/
/* Exported function definitions						*/

#ifdef	__cplusplus
extern "C" {
#endif

INT AirPDcapPacketProcess(
        PAIRPDCAP_CONTEXT ctx,
        const UCHAR *data,
        const size_t len,
        UCHAR *decrypt_data,
        size_t *decrypt_len,
        PAIRPDCAP_KEY_ITEM key,
        UINT8 fcsPresent,
        UINT8 radioTapPresent,
        UINT8 mngHandshake,
        UINT8 mngDecrypt)
{
        size_t mac_header_len;
        UCHAR *address;
        AIRPDCAP_SEC_ASSOCIATION_ID id;
        INT index;
        PAIRPDCAP_SEC_ASSOCIATION sa;
        INT offset;
        UINT16 bodyLength;

#ifdef _DEBUG
        CHAR msgbuf[255];
#endif

        AIRPDCAP_DEBUG_TRACE_START("AirPDcapPacketProcess");

        if (ctx==NULL) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "NULL context", AIRPDCAP_DEBUG_LEVEL_5);
                AIRPDCAP_DEBUG_TRACE_END("AirPDcapPacketProcess");
                return AIRPDCAP_RET_UNSUCCESS;
        }
        if (data==NULL || len==0) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "NULL data or length=0", AIRPDCAP_DEBUG_LEVEL_5);
                AIRPDCAP_DEBUG_TRACE_END("AirPDcapPacketProcess");
                return AIRPDCAP_RET_UNSUCCESS;
        }

        if (radioTapPresent)
                offset=AIRPDCAP_RADIOTAP_HEADER_LEN;
        else
                offset=0;

        /* check if the packet is of data type	*/
        /*	TODO consider packets send on an ad-hoc net (QoS)	*/
        if (AIRPDCAP_TYPE(data[offset])!=AIRPDCAP_TYPE_DATA) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "not data packet", AIRPDCAP_DEBUG_LEVEL_5);
                return AIRPDCAP_RET_NO_DATA;
        }

        /* check correct packet size, to avoid wrong elaboration of encryption algorithms	*/
        mac_header_len=AIRPDCAP_HEADER_LEN(data[offset+1]);
        if (len < (UINT)(mac_header_len+AIRPDCAP_CRYPTED_DATA_MINLEN)) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "minimum length violated", AIRPDCAP_DEBUG_LEVEL_5);
                return AIRPDCAP_RET_WRONG_DATA_SIZE;
        }

        /* get BSSID	*/
        if ( (address=AirPDcapGetBssidAddress((PAIRPDCAP_MAC_FRAME)(data+offset))) != NULL) {
                memcpy(id.bssid, address, AIRPDCAP_MAC_LEN);
#ifdef _DEBUG
                sprintf(msgbuf, "BSSID: %2X.%2X.%2X.%2X.%2X.%2X\t", id.bssid[0],id.bssid[1],id.bssid[2],id.bssid[3],id.bssid[4],id.bssid[5]);
#endif
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", msgbuf, AIRPDCAP_DEBUG_LEVEL_3);
        } else {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "BSSID not found", AIRPDCAP_DEBUG_LEVEL_5);
                return AIRPDCAP_RET_REQ_DATA;
        }

        /* get STA address	*/
        if ( (address=AirPDcapGetStaAddress((PAIRPDCAP_MAC_FRAME)(data+offset))) != NULL) {
                memcpy(id.sta, address, AIRPDCAP_MAC_LEN);
#ifdef _DEBUG
                sprintf(msgbuf, "ST_MAC: %2X.%2X.%2X.%2X.%2X.%2X\t", id.sta[0],id.sta[1],id.sta[2],id.sta[3],id.sta[4],id.sta[5]);
#endif
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", msgbuf, AIRPDCAP_DEBUG_LEVEL_3);
        } else {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "SA not found", AIRPDCAP_DEBUG_LEVEL_5);
                return AIRPDCAP_RET_REQ_DATA;
        }

        /* search for a cached Security Association for current BSSID and station MAC	*/
        if ((index=AirPDcapGetSa(ctx, &id))==-1) {
                /* create a new Security Association	*/
                if ((index=AirPDcapStoreSa(ctx, &id))==-1) {
                        return AIRPDCAP_RET_UNSUCCESS;
                }
        }

        /* get the Security Association structure	*/
        sa=&ctx->sa[index];

        /* cache offset in the packet data (to scan encryption data)	*/
        offset+=AIRPDCAP_HEADER_LEN(data[offset+1]);

        /*	check if data is encrypted (use the WEP bit in the Frame Control field)	*/
        if (AIRPDCAP_WEP(data[1])==0)
        {
                if (mngHandshake) {
                        /* data is sent in cleartext, check if is an authentication message or end the process	*/
                        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "Unencrypted data", AIRPDCAP_DEBUG_LEVEL_3);

                        /* check if the packet as an LLC header and the packet is 802.1X authentication (IEEE 802.1X-2004, pg. 24)	*/
                        if (data[offset]==0xAA &&	/* DSAP=SNAP								*/
                        data[offset+1]==0xAA &&	/*	SSAP=SNAP								*/
                        data[offset+2]==0x03 &&	/*	Control field=Unnumbered frame	*/
                        data[offset+3]==0x00 &&	/* Org. code=encaps. Ethernet			*/
                        data[offset+4]==0x00 &&
                        data[offset+5]==0x00 &&
                        data[offset+6]==0x88 &&	/*	Type: 802.1X authentication		*/
                        data[offset+7]==0x8E) {
                                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "Authentication: EAPOL packet", AIRPDCAP_DEBUG_LEVEL_3);

                                        /* skip LLC header	*/
                                        offset+=8;

                                        /* check the version of the EAPOL protocol used (IEEE 802.1X-2004, pg. 24)	*/
                                        /* TODO EAPOL protocol version to check?	*/
                                        /*if (data[offset]!=2) {
                                        AIRPDCAP_DEBUG_PRINT_LINE("EAPOL protocol version not recognized", AIRPDCAP_DEBUG_LEVEL_5);
                                        return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
                                        }*/

                                        /*	check if the packet is a EAPOL-Key (0x03) (IEEE 802.1X-2004, pg. 25)	*/
                                        if (data[offset+1]!=3) {
                                                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "Not EAPOL-Key", AIRPDCAP_DEBUG_LEVEL_5);
                                                return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
                                        }

                                        /* get and check the body length (IEEE 802.1X-2004, pg. 25)	*/
                                        bodyLength=ntohs(*(UINT16 *)(data+offset+2));
                                        if (((len-offset-4)!=bodyLength && !fcsPresent) || ((len-offset-8)!=bodyLength && fcsPresent)) {
                                                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "EAPOL body not valid (wrong length)", AIRPDCAP_DEBUG_LEVEL_5);
                                                return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
                                        }

                                        /* skip EAPOL MPDU and go to the first byte of the body	*/
                                        offset+=4;

                                        /* check if the key descriptor type is valid (IEEE 802.1X-2004, pg. 27)	*/
                                        if (/*data[offset]!=0x1 &&*/	/* RC4 Key Descriptor Type (deprecated)	*/
                                                data[offset]!=0x2 &&		/* IEEE 802.11 Key Descriptor Type			*/
                                                data[offset]!=0xFE)		/* TODO what's this value???					*/
                                        {
                                                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "Not valid key descriptor type", AIRPDCAP_DEBUG_LEVEL_5);
                                                return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
                                        }

                                        /* start with descriptor body	*/
                                        offset+=1;

                                        /*	manage the 4-way handshake to define the key	*/
                                        return AirPDcapRsna4WHandshake(ctx, data, sa, key, offset);
                        } else {
                                /* cleartext message, not authentication	*/
                                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "No authentication data", AIRPDCAP_DEBUG_LEVEL_5);
                                return AIRPDCAP_RET_NO_DATA_ENCRYPTED;
                        }
                }
        } else {
                if (mngDecrypt) {

                        if (decrypt_data==NULL)
                                return AIRPDCAP_RET_UNSUCCESS;

                        /*	create new header and data to modify	*/
                        *decrypt_len=len;
                        memcpy(decrypt_data, data, *decrypt_len);

                        /* encrypted data	*/
                        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "Encrypted data", AIRPDCAP_DEBUG_LEVEL_3);

                        if (fcsPresent)
                                /*	remove from next computation FCS	*/
                                *decrypt_len-=4;

                        /* check the Extension IV to distinguish between WEP encryption and WPA encryption	*/
                        /* refer to IEEE 802.11i-2004, 8.2.1.2, pag.35 for WEP,	*/
                        /*		IEEE 802.11i-2004, 8.3.2.2, pag. 45 for TKIP,		*/
                        /*		IEEE 802.11i-2004, 8.3.3.2, pag. 57 for CCMP			*/
                        if (AIRPDCAP_EXTIV(data[offset+3])==0) {
                                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "WEP encryption", AIRPDCAP_DEBUG_LEVEL_3);
                                return AirPDcapWepMng(ctx, decrypt_data, decrypt_len, key, sa, offset, fcsPresent);
                        } else {
                                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapPacketProcess", "TKIP or CCMP encryption", AIRPDCAP_DEBUG_LEVEL_3);
                                return AirPDcapRsnaMng(decrypt_data, decrypt_len, key, sa, offset, fcsPresent);
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

        /* clean keys collection before setting new ones	*/
        AirPDcapCleanKeys(ctx);

        /* check and insert keys	*/
        for (i=0, success=0; i<(INT)keys_nr; i++) {
                if (AirPDcapValidateKey(keys+i)==TRUE) {
                        if (keys[i].KeyType==AIRPDCAP_KEY_TYPE_WPA_PWD) {
                                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapSetKeys", "Set a WPA-PWD key", AIRPDCAP_DEBUG_LEVEL_4);
                                AirPDcapRsnaPwd2Psk(keys[i].KeyData.Wpa.UserPwd.Passphrase, keys[i].KeyData.Wpa.UserPwd.Ssid, keys[i].KeyData.Wpa.UserPwd.SsidLen, keys[i].KeyData.Wpa.Psk);
                        }
#ifdef	_DEBUG
                        else if (keys[i].KeyType==AIRPDCAP_KEY_TYPE_WPA_PMK) {
                                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapSetKeys", "Set a WPA-PMK key", AIRPDCAP_DEBUG_LEVEL_4);
                        } else if (keys[i].KeyType==AIRPDCAP_KEY_TYPE_WEP) {
                                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapSetKeys", "Set a WEP key", AIRPDCAP_DEBUG_LEVEL_4);
                        } else {
                                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapSetKeys", "Set a key", AIRPDCAP_DEBUG_LEVEL_4);
                        }
#endif

                        ctx->keys[success].KeyType=keys[i].KeyType;
                        memcpy(&ctx->keys[success].KeyData, &keys[i].KeyData, sizeof(keys[i].KeyData));

                        success++;
                }
        }

        ctx->keys_nr=success;

        AIRPDCAP_DEBUG_TRACE_END("AirPDcapSetKeys");
        return success;
}

INT AirPDcapCleanKeys(
        PAIRPDCAP_CONTEXT ctx)
{
        INT i;
        AIRPDCAP_DEBUG_TRACE_START("AirPDcapCleanKeys");

        if (ctx==NULL) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapCleanKeys", "NULL context", AIRPDCAP_DEBUG_LEVEL_5);
                AIRPDCAP_DEBUG_TRACE_END("AirPDcapCleanKeys");
                return 0;
        }

        for (i=0; i<AIRPDCAP_MAX_KEYS_NR; i++) {
                memset(&ctx->keys[i], 0, sizeof(AIRPDCAP_KEY_ITEM));
        }

        ctx->keys_nr=0;

        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapCleanKeys", "Keys collection cleaned!", AIRPDCAP_DEBUG_LEVEL_5);
        AIRPDCAP_DEBUG_TRACE_END("AirPDcapCleanKeys");

        return i;
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
                        keys[j].KeyType=ctx->keys[i].KeyType;
                        memcpy(&keys[j].KeyData, &ctx->keys[i].KeyData, sizeof(keys[j].KeyData));
                        j++;
                        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapGetKeys", "Got a key", AIRPDCAP_DEBUG_LEVEL_5);
                }

                AIRPDCAP_DEBUG_TRACE_END("AirPDcapGetKeys");
                return j;
        }
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
        ctx->last_stored_index=-1;

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
        ctx->last_stored_index=-1;

        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapDestroyContext", "Context destroyed!", AIRPDCAP_DEBUG_LEVEL_5);
        AIRPDCAP_DEBUG_TRACE_END("AirPDcapDestroyContext");
        return AIRPDCAP_RET_SUCCESS;
}

#ifdef	__cplusplus
}
#endif

/****************************************************************************/

/****************************************************************************/
/* Internal function definitions						*/

#ifdef	__cplusplus
extern "C" {
#endif

INT AirPDcapRsnaMng(
        UCHAR *decrypt_data,
        size_t *decrypt_len,
        PAIRPDCAP_KEY_ITEM key,
        AIRPDCAP_SEC_ASSOCIATION *sa,
        INT offset,
        UINT8 fcsPresent)
{
        INT ret_value;
        ULONG crc;

        if (sa->key==NULL) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsnaMng", "No key associated", AIRPDCAP_DEBUG_LEVEL_3);
                return AIRPDCAP_RET_REQ_DATA;
        }
        if (sa->validKey==FALSE) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsnaMng", "Key not yet valid", AIRPDCAP_DEBUG_LEVEL_3);
                return AIRPDCAP_RET_UNSUCCESS;
        }
        if (sa->wpa.key_ver==1) {
                /*	CCMP -> HMAC-MD5 is the EAPOL-Key MIC, RC4 is the EAPOL-Key encryption algorithm	*/
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsnaMng", "TKIP", AIRPDCAP_DEBUG_LEVEL_3);

                ret_value=AirPDcapTkipDecrypt(decrypt_data+offset, *decrypt_len-offset, decrypt_data+AIRPDCAP_TA_OFFSET, AIRPDCAP_GET_TK(sa->wpa.ptk));
                if (ret_value)
                        return ret_value;

                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsnaMng", "TKIP DECRYPTED!!!", AIRPDCAP_DEBUG_LEVEL_3);
                /* remove MIC (8bytes) and ICV (4bytes) from the end of packet	*/
                *decrypt_len-=12;
        } else {
                /*	AES-CCMP -> HMAC-SHA1-128 is the EAPOL-Key MIC, AES wep_key wrap is the EAPOL-Key encryption algorithm	*/
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsnaMng", "CCMP", AIRPDCAP_DEBUG_LEVEL_3);

                ret_value=AirPDcapCcmpDecrypt(decrypt_data, (INT)*decrypt_len, AIRPDCAP_GET_TK(sa->wpa.ptk));
                if (ret_value)
                        return ret_value;

                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsnaMng", "CCMP DECRYPTED!!!", AIRPDCAP_DEBUG_LEVEL_3);
                /* remove MIC (8bytes) from the end of packet	*/
                *decrypt_len-=8;
        }

        /* remove protection bit	*/
        decrypt_data[1]&=0xBF;

        /* remove TKIP/CCMP header	*/
        offset=AIRPDCAP_HEADER_LEN(decrypt_data[1]);
        *decrypt_len-=8;
        memcpy(decrypt_data+offset, decrypt_data+offset+8, *decrypt_len-offset);

        if (fcsPresent) {
                /* calculate FCS	*/
                AirPDcapAlgCrc32(decrypt_data, *decrypt_len, &crc);
                *(unsigned long*)(decrypt_data+*decrypt_len)=crc;

                /* add FCS in packet	*/
                *decrypt_len+=4;
        }

        if (key!=NULL) {
                memcpy(key, sa->key, sizeof(AIRPDCAP_KEY_ITEM));

                if (sa->wpa.key_ver==AIRPDCAP_WPA_KEY_VER_CCMP)
                        key->KeyType=AIRPDCAP_KEY_TYPE_TKIP;
                else if (sa->wpa.key_ver==AIRPDCAP_WPA_KEY_VER_AES_CCMP)
                        key->KeyType=AIRPDCAP_KEY_TYPE_CCMP;
        }

        return AIRPDCAP_RET_SUCCESS;
}

INT AirPDcapWepMng(
        PAIRPDCAP_CONTEXT ctx,
        UCHAR *decrypt_data,
        size_t *decrypt_len,
        PAIRPDCAP_KEY_ITEM key,
        AIRPDCAP_SEC_ASSOCIATION *sa,
        INT offset,
        UINT8 fcsPresent)
{
        UCHAR wep_key[AIRPDCAP_WEP_KEY_MAXLEN+AIRPDCAP_WEP_IVLEN];
        size_t keylen;
        INT ret_value=1;
        ULONG crc;
        INT key_index;
        AIRPDCAP_KEY_ITEM *tmp_key;
        UINT8 useCache=FALSE;

        if (sa->key!=NULL)
                useCache=TRUE;

        for (key_index=0; key_index<(INT)ctx->keys_nr; key_index++) {
                /* use the cached one, or try all keys	*/
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

                /* obviously, try only WEP keys...	*/
                if (tmp_key->KeyType==AIRPDCAP_KEY_TYPE_WEP)
                {
                        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapWepMng", "Try WEP key...", AIRPDCAP_DEBUG_LEVEL_3);

                        memset(wep_key, 0, sizeof(wep_key));

                        /* Costruct the WEP seed: copy the IV in first 3 bytes and then the WEP key (refer to 802-11i-2004, 8.2.1.4.3, pag. 36)	*/
                        memcpy(wep_key, decrypt_data+AIRPDCAP_HEADER_LEN(decrypt_data[1]), AIRPDCAP_WEP_IVLEN);
                        keylen=tmp_key->KeyData.Wep.WepKeyLen;
                        memcpy(wep_key+AIRPDCAP_WEP_IVLEN, tmp_key->KeyData.Wep.WepKey, keylen);

                        ret_value=AirPDcapWepDecrypt(wep_key,
                                keylen+AIRPDCAP_WEP_IVLEN,
                                decrypt_data + (AIRPDCAP_HEADER_LEN(decrypt_data[1])+AIRPDCAP_WEP_IVLEN+AIRPDCAP_WEP_KIDLEN),
                                *decrypt_len-(AIRPDCAP_HEADER_LEN(decrypt_data[1])+AIRPDCAP_WEP_IVLEN+AIRPDCAP_WEP_KIDLEN+AIRPDCAP_CRC_LEN));

                }

                if (!ret_value && tmp_key->KeyType==AIRPDCAP_KEY_TYPE_WEP) {
                        /* the tried key is the correct one, cached in the Security Association	*/

                        sa->key=tmp_key;

                        if (key!=NULL) {
                                memcpy(key, &sa->key, sizeof(AIRPDCAP_KEY_ITEM));
                                key->KeyType=AIRPDCAP_KEY_TYPE_WEP;
                        }

                        break;
                } else {
                        /* the cached key was not valid, try other keys	*/

                        if (useCache==TRUE) {
                                useCache=FALSE;
                                key_index--;
                        }
                }
        }

        if (ret_value)
                return ret_value;

        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapWepMng", "WEP DECRYPTED!!!", AIRPDCAP_DEBUG_LEVEL_3);

        /* remove ICV (4bytes) from the end of packet	*/
        *decrypt_len-=4;

        /* remove protection bit	*/
        decrypt_data[1]&=0xBF;

        /* remove IC header	*/
        offset=AIRPDCAP_HEADER_LEN(decrypt_data[1]);
        *decrypt_len-=4;
        memcpy(decrypt_data+offset, decrypt_data+offset+AIRPDCAP_WEP_IVLEN+AIRPDCAP_WEP_KIDLEN, *decrypt_len-offset);

        if (fcsPresent) {
                /* calculate FCS and append it at the end of the decrypted packet	*/
                AirPDcapAlgCrc32(decrypt_data, *decrypt_len, &crc);
                *(unsigned long*)(decrypt_data+*decrypt_len)=crc;

                /* add FCS in packet	*/
                *decrypt_len += 4;
        }

        return AIRPDCAP_RET_SUCCESS;
}

/* Refer to IEEE 802.11i-2004, 8.5.3, pag. 85	*/
INT AirPDcapRsna4WHandshake(
        PAIRPDCAP_CONTEXT ctx,
        const UCHAR *data,
        AIRPDCAP_SEC_ASSOCIATION *sa,
        PAIRPDCAP_KEY_ITEM key,
        INT offset)
{
        AIRPDCAP_KEY_ITEM *tmp_key;
        INT key_index;
        INT ret_value=1;
        UCHAR useCache=FALSE;
        UCHAR eapol[AIRPDCAP_EAPOL_MAX_LEN];
        USHORT eapol_len;

        if (sa->key!=NULL)
                useCache=TRUE;

        /* a 4-way handshake packet use a Pairwise key type (IEEE 802.11i-2004, pg. 79)	*/
        if (AIRPDCAP_EAP_KEY(data[offset+1])!=1) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "Group/STAKey message (not used)", AIRPDCAP_DEBUG_LEVEL_5);
                return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
        }

        /* TODO timeouts? reauthentication?	*/

        /* TODO consider key-index	*/

        /* TODO considera Deauthentications	*/

        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "4-way handshake...", AIRPDCAP_DEBUG_LEVEL_5);

        /* manage 4-way handshake packets; this step completes the 802.1X authentication process (IEEE 802.11i-2004, pag. 85)	*/

        /* message 1: Authenticator->Supplicant (Sec=0, Mic=0, Ack=1, Inst=0, Key=1(pairwise), KeyRSC=0, Nonce=ANonce, MIC=0)	*/
        if (AIRPDCAP_EAP_INST(data[offset+1])==0 &&
                AIRPDCAP_EAP_ACK(data[offset+1])==1 &&
                AIRPDCAP_EAP_MIC(data[offset])==0)
        {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "4-way handshake message 1", AIRPDCAP_DEBUG_LEVEL_3);

                /* On reception of Message 1, the Supplicant determines whether the Key Replay Counter field value has been			*/
                /* used before with the current PMKSA. If the Key Replay Counter field value is less than or equal to the current	*/
                /* local value, the Supplicant discards the message.																					*/
                /* -> not checked, the Authenticator will be send another Message 1 (hopefully!)												*/

                /* save ANonce (from authenticator)	to derive the PTK with the SNonce (from the 2 message)	*/
                memcpy(sa->wpa.nonce, data+offset+12, 32);

                /* get the Key Descriptor Version (to select algorithm used in decryption -CCMP or TKIP-)	*/
                sa->wpa.key_ver=AIRPDCAP_EAP_KEY_DESCR_VER(data[offset+1]);

                sa->handshake=1;

                return AIRPDCAP_RET_SUCCESS_HANDSHAKE;
        }

        /* message 2|4: Supplicant->Authenticator (Sec=0|1, Mic=1, Ack=0, Inst=0, Key=1(pairwise), KeyRSC=0, Nonce=SNonce|0, MIC=MIC(KCK,EAPOL))	*/
        if (AIRPDCAP_EAP_INST(data[offset+1])==0 &&
                AIRPDCAP_EAP_ACK(data[offset+1])==0 &&
                AIRPDCAP_EAP_MIC(data[offset])==1)
        {
                if (AIRPDCAP_EAP_SEC(data[offset])==0) {

                        /* PATCH:	some implementations set secure bit to 0 also in the 4th message		*/
                        /*				to recognize which message is this check if wep_key data lenght is 0	*/
                        /*				in the 4th message																	*/
                        if (*(UINT16 *)(data+offset+92)!=0) {
                                /* message 2	*/
                                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "4-way handshake message 2", AIRPDCAP_DEBUG_LEVEL_3);

                                /* On reception of Message 2, the Authenticator checks that the key replay counter corresponds to the	*/
                                /* outstanding Message 1. If not, it silently discards the message.												*/
                                /* If the calculated MIC does not match the MIC that the Supplicant included in the EAPOL-Key frame,	*/
                                /* the Authenticator silently discards Message 2.																		*/
                                /* -> not checked; the Supplicant will send another message 2 (hopefully!)										*/

                                /* now you can derive the PTK	*/
                                for (key_index=0; key_index<(INT)ctx->keys_nr || sa->key!=NULL; key_index++) {
                                        /* use the cached one, or try all keys	*/
                                        if (!useCache) {
                                                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "Try WPA key...", AIRPDCAP_DEBUG_LEVEL_3);
                                                tmp_key=&ctx->keys[key_index];
                                        } else {
                                                /* there is a cached key in the security association, if it's a WPA key try it...	*/
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

                                        /* obviously, try only WPA keys...	*/
                                        if (tmp_key->KeyType==AIRPDCAP_KEY_TYPE_WPA_PWD ||
                                                tmp_key->KeyType==AIRPDCAP_KEY_TYPE_WPA_PSK ||
                                                tmp_key->KeyType==AIRPDCAP_KEY_TYPE_WPA_PMK)
                                        {
                                                /* derive the PTK from the BSSID, STA MAC, PMK, SNonce, ANonce	*/
                                                AirPDcapRsnaPrfX(sa,					/* authenticator nonce, bssid, station mac	*/
                                                        tmp_key->KeyData.Wpa.Pmk,	/* PMK	*/
                                                        data+offset+12,				/*	supplicant nonce	*/
                                                        512,
                                                        sa->wpa.ptk);

                                                /* verify the MIC (compare the MIC in the packet included in this message with a MIC calculated with the PTK)	*/
                                                eapol_len=(USHORT)(ntohs(*(UINT16 *)(data+offset-3))+4);
                                                memcpy(eapol, &data[offset-5], (eapol_len<AIRPDCAP_EAPOL_MAX_LEN?eapol_len:AIRPDCAP_EAPOL_MAX_LEN));
                                                ret_value=AirPDcapRsnaMicCheck(eapol,						/*	eapol frame (header also)		*/
                                                        eapol_len,													/*	eapol frame length				*/
                                                        sa->wpa.ptk,												/*	Key Confirmation Key				*/
                                                        AIRPDCAP_EAP_KEY_DESCR_VER(data[offset+1]));		/*	EAPOL-Key description version	*/

                                                /* If the MIC is valid, the Authenticator checks that the RSN information element bit-wise matches		*/
                                                /* that from the (Re)Association Request message.																		*/
                                                /*		i) TODO If these are not exactly the same, the Authenticator uses MLME-DEAUTHENTICATE.request	*/
                                                /* primitive to terminate the association.																				*/
                                                /*		ii) If they do match bit-wise, the Authenticator constructs Message 3.									*/
                                        }

                                        if (!ret_value &&
                                                (tmp_key->KeyType==AIRPDCAP_KEY_TYPE_WPA_PWD ||
                                                tmp_key->KeyType==AIRPDCAP_KEY_TYPE_WPA_PSK ||
                                                tmp_key->KeyType==AIRPDCAP_KEY_TYPE_WPA_PMK))
                                        {
                                                /* the temporary key is the correct one, cached in the Security Association	*/

                                                sa->key=tmp_key;

                                                if (key!=NULL) {
                                                        memcpy(key, &tmp_key, sizeof(AIRPDCAP_KEY_ITEM));
                                                        if (AIRPDCAP_EAP_KEY_DESCR_VER(data[offset+1])==AIRPDCAP_WPA_KEY_VER_CCMP)
                                                                key->KeyType=AIRPDCAP_KEY_TYPE_TKIP;
                                                        else if (AIRPDCAP_EAP_KEY_DESCR_VER(data[offset+1])==AIRPDCAP_WPA_KEY_VER_AES_CCMP)
                                                                key->KeyType=AIRPDCAP_KEY_TYPE_CCMP;
                                                }

                                                break;
                                        } else {
                                                /* the cached key was not valid, try other keys	*/

                                                if (useCache==TRUE) {
                                                        useCache=FALSE;
                                                        key_index--;
                                                }
                                        }
                                }

                                if (ret_value) {
                                        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "handshake step failed", AIRPDCAP_DEBUG_LEVEL_3);
                                        return ret_value;
                                }

                                sa->handshake=2;

                                return AIRPDCAP_RET_SUCCESS_HANDSHAKE;
                        } else {
                                /* message 4	*/

                                /* TODO "Note that when the 4-Way Handshake is first used Message 4 is sent in the clear."	*/

                                /* TODO check MIC and Replay Counter																							*/
                                /* On reception of Message 4, the Authenticator verifies that the Key Replay Counter field value is one	*/
                                /* that it used on this 4-Way Handshake; if it is not, it silently discards the message.						*/
                                /* If the calculated MIC does not match the MIC that the Supplicant included in the EAPOL-Key frame, the	*/
                                /* Authenticator silently discards Message 4.																				*/

                                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "4-way handshake message 4 (patched)", AIRPDCAP_DEBUG_LEVEL_3);

                                sa->handshake=4;

                                sa->validKey=TRUE;

                                return AIRPDCAP_RET_SUCCESS_HANDSHAKE;
                        }
                        /* END OF PATCH																					*/
                        /*																										*/
                } else {
                        /* message 4	*/

                        /* TODO "Note that when the 4-Way Handshake is first used Message 4 is sent in the clear."	*/

                        /* TODO check MIC and Replay Counter																							*/
                        /* On reception of Message 4, the Authenticator verifies that the Key Replay Counter field value is one	*/
                        /* that it used on this 4-Way Handshake; if it is not, it silently discards the message.						*/
                        /* If the calculated MIC does not match the MIC that the Supplicant included in the EAPOL-Key frame, the	*/
                        /* Authenticator silently discards Message 4.																				*/

                        AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "4-way handshake message 4", AIRPDCAP_DEBUG_LEVEL_3);

                        sa->handshake=4;

                        sa->validKey=TRUE;

                        return AIRPDCAP_RET_SUCCESS_HANDSHAKE;
                }
        }

        /* message 3: Authenticator->Supplicant (Sec=1, Mic=1, Ack=1, Inst=0/1, Key=1(pairwise), KeyRSC=???, Nonce=ANonce, MIC=1)	*/
        if (AIRPDCAP_EAP_ACK(data[offset+1])==1 &&
                AIRPDCAP_EAP_MIC(data[offset])==1)
        {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapRsna4WHandshake", "4-way handshake message 3", AIRPDCAP_DEBUG_LEVEL_3);

                /* On reception of Message 3, the Supplicant silently discards the message if the Key Replay Counter field		*/
                /* value has already been used or if the ANonce value in Message 3 differs from the ANonce value in Message 1.	*/
                /* -> not checked, the Authenticator will send another message 3 (hopefully!)												*/

                /*	TODO check page 88 (RNS)	*/

                return AIRPDCAP_RET_SUCCESS_HANDSHAKE;
        }

        return AIRPDCAP_RET_UNSUCCESS;
}

INT AirPDcapRsnaMicCheck(
        UCHAR *eapol,
        const USHORT eapol_len,
        const UCHAR KCK[AIRPDCAP_WPA_KCK_LEN],
        const USHORT key_ver)
{
        UCHAR mic[AIRPDCAP_WPA_MICKEY_LEN];
        UCHAR c_mic[20];	/* MIC 16 byte, the HMAC-SHA1 use a buffer of 20 bytes	*/

        /* copy the MIC from the EAPOL packet	*/
        memcpy(mic, eapol+AIRPDCAP_WPA_MICKEY_OFFSET+4, AIRPDCAP_WPA_MICKEY_LEN);

        /*	set to 0 the MIC in the EAPOL packet (to calculate the MIC)	*/
        memset(eapol+AIRPDCAP_WPA_MICKEY_OFFSET+4, 0, AIRPDCAP_WPA_MICKEY_LEN);

        if (key_ver==AIRPDCAP_WPA_KEY_VER_CCMP) {
                /*	use HMAC-MD5 for the EAPOL-Key MIC	*/
                AirPDcapAlgHmacMd5((UCHAR *)KCK, AIRPDCAP_WPA_KCK_LEN, eapol, eapol_len, c_mic);
        } else if (key_ver==AIRPDCAP_WPA_KEY_VER_AES_CCMP) {
                /*	use HMAC-SHA1-128 for the EAPOL-Key MIC	*/
                AirPDcapAlgHmacSha1(KCK, AIRPDCAP_WPA_KCK_LEN, eapol, eapol_len, c_mic);
        } else
                /*	key descriptor version not recognized	*/
                return AIRPDCAP_RET_UNSUCCESS;

        /* compare calculated MIC with the Key MIC and return result (0 means success)	*/
        return memcmp(mic, c_mic, AIRPDCAP_WPA_MICKEY_LEN);
}

INT AirPDcapValidateKey(
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
        /* check key size limits	*/
        len=key->KeyData.Wep.WepKeyLen;
        if (len<AIRPDCAP_WEP_KEY_MINLEN || len>AIRPDCAP_WEP_KEY_MAXLEN) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapValidateKey", "WEP key: key length not accepted", AIRPDCAP_DEBUG_LEVEL_5);
                ret=FALSE;
        }
        break;

case AIRPDCAP_KEY_TYPE_WEP_40:
        /* set the standard length	and use a generic WEP key type	*/
        key->KeyData.Wep.WepKeyLen=AIRPDCAP_WEP_40_KEY_LEN;
        key->KeyType=AIRPDCAP_KEY_TYPE_WEP;
        break;

case AIRPDCAP_KEY_TYPE_WEP_104:
        /* set the standard length	and use a generic WEP key type	*/
        key->KeyData.Wep.WepKeyLen=AIRPDCAP_WEP_104_KEY_LEN;
        key->KeyType=AIRPDCAP_KEY_TYPE_WEP;
        break;

case AIRPDCAP_KEY_TYPE_WPA_PWD:
        /* check passphrase and SSID size limits	*/
        len=strlen(key->KeyData.Wpa.UserPwd.Passphrase);
        if (len<AIRPDCAP_WPA_PASSPHRASE_MIN_LEN || len>AIRPDCAP_WPA_PASSPHRASE_MAX_LEN) {
                AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapValidateKey", "WPA-PWD key: passphrase length not accepted", AIRPDCAP_DEBUG_LEVEL_5);
                ret=FALSE;
        }

        len=key->KeyData.Wpa.UserPwd.SsidLen;
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

INT AirPDcapGetSa(
        PAIRPDCAP_CONTEXT ctx,
        AIRPDCAP_SEC_ASSOCIATION_ID *id)
{
        INT index;

        if (ctx->last_stored_index!=-1) {
                /* at least one association was stored														*/
                /* search for the association from last_stored_index to 0 (most recent added)	*/
                for (index=ctx->last_stored_index; index>=0; index--) {
                        if (ctx->sa[index].used) {
                                if (memcmp(id, &(ctx->sa[index].saId), sizeof(AIRPDCAP_SEC_ASSOCIATION_ID))==0) {
                                        ctx->index=index;
                                        return index;
                                }
                        }
                }
        }

        return -1;
}

INT AirPDcapFreeSa(
        PAIRPDCAP_CONTEXT ctx,
        INT index)								/* index of the structure to free		*/
{
        /* set the structure as free (the reset will be done in AIRPDCAP_store_sta_info)	*/
        ctx->sa[index].used=0;

        /* set the first_free_index to avoid free blocks in the middle	*/
        if (index<ctx->first_free_index)
                ctx->first_free_index=index;

        /* decrement the last_stored_index if this was the last stored block	*/
        if (index==ctx->last_stored_index)
                ctx->last_stored_index--;

        /* if the list is empty, set the index	*/
        if (ctx->last_stored_index==-1)
                ctx->index=-1;

        return ctx->index;
}

INT AirPDcapStoreSa(
        PAIRPDCAP_CONTEXT ctx,
        AIRPDCAP_SEC_ASSOCIATION_ID *id)
{
        INT last_free;

        if (ctx->sa[ctx->first_free_index].used) {
                /* last addition was in the middle of the array (and the first_free_index was just incremented by 1)	*/
                /* search for a free space from the first_free_index to AIRPDCAP_STA_INFOS_NR (to avoid free blocks in	*/
                /*		the middle)																													*/
                for (last_free=ctx->first_free_index; last_free<AIRPDCAP_MAX_SEC_ASSOCIATIONS_NR; last_free++)
                        if (!ctx->sa[last_free].used)
                                break;

                if (last_free>=AIRPDCAP_MAX_SEC_ASSOCIATIONS_NR) {
                        /* there is no empty space available. FAILURE	*/
                        return -1;
                }

                /* store first free space index	*/
                ctx->first_free_index=last_free;
        }

        /* use this info	*/
        ctx->index=ctx->first_free_index;

        /* reset the info structure	*/
        memset(ctx->sa+ctx->index, 0, sizeof(AIRPDCAP_SEC_ASSOCIATION));

        ctx->sa[ctx->index].used=1;

        /* set the info structure	*/
        memcpy(&(ctx->sa[ctx->index].saId), id, sizeof(AIRPDCAP_SEC_ASSOCIATION_ID));

        /* increment by 1 the first_free_index (heuristic)	*/
        ctx->first_free_index++;

        /* set the last_stored_index if the added index is greater the the last_stored_index	*/
        if (ctx->index > ctx->last_stored_index)
                ctx->last_stored_index=ctx->index;

        return ctx->index;
}

UCHAR * AirPDcapGetStaAddress(
        PAIRPDCAP_MAC_FRAME frame)
{
        if (AIRPDCAP_TO_DS(frame->fc[1])==0) {
                if (AIRPDCAP_FROM_DS(frame->fc[1])==0)
                        return NULL;
                else
                        return frame->addr1;
        } else {
                if (AIRPDCAP_FROM_DS(frame->fc[1])==0)
                        return frame->addr2;
                else
                        return NULL;
        }
}

UCHAR * AirPDcapGetBssidAddress(
        PAIRPDCAP_MAC_FRAME frame)
{
        if (AIRPDCAP_TO_DS(frame->fc[1])==0) {
                if (AIRPDCAP_FROM_DS(frame->fc[1])==0)
                        return frame->addr3;
                else
                        return frame->addr2;
        } else {
                if (AIRPDCAP_FROM_DS(frame->fc[1])==0)
                        return frame->addr1;
                else
                        return NULL;
        }
}

/* Function used to derive the PTK. Refer to IEEE 802.11I-2004, pag. 74	*/
void AirPDcapRsnaPrfX(
        AIRPDCAP_SEC_ASSOCIATION *sa,
        const UCHAR pmk[32],
        const UCHAR snonce[32],
        const INT x,	/*	for TKIP 512, for CCMP 384	*/
        UCHAR *ptk)
{
        UINT8 i;
        UCHAR R[100];
        INT offset=sizeof("Pairwise key expansion");

        memset(R, 0, 100);

        memcpy(R, "Pairwise key expansion", offset);

        /*	Min(AA, SPA) || Max(AA, SPA)	*/
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

        /*	Min(ANonce,SNonce) || Max(ANonce,SNonce)	*/
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
                AirPDcapAlgHmacSha1(pmk, 32, R, 100, ptk + i * 20);
        }
}

INT AirPDcapRsnaPwd2PskStep(
        const CHAR *password,
        const CHAR *ssid,
        const size_t ssidLength,
        const INT iterations,
        const INT count,
        UCHAR *output)
{
        UCHAR digest[36], digest1[AIRPDCAP_SHA_DIGEST_LEN];
        INT i, j;

        /* U1 = PRF(P, S || INT(i)) */
        memcpy(digest, ssid, ssidLength);
        digest[ssidLength] = (UCHAR)((count>>24) & 0xff);
        digest[ssidLength+1] = (UCHAR)((count>>16) & 0xff);
        digest[ssidLength+2] = (UCHAR)((count>>8) & 0xff);
        digest[ssidLength+3] = (UCHAR)(count & 0xff);
        AirPDcapAlgHmacSha1((UCHAR *)password, strlen(password), digest, ssidLength+4, digest1);

        /* output = U1 */
        memcpy(output, digest1, AIRPDCAP_SHA_DIGEST_LEN);
        for (i = 1; i < iterations; i++) {
                /* Un = PRF(P, Un-1) */
                AirPDcapAlgHmacSha1((UCHAR *)password, strlen(password), digest1, AIRPDCAP_SHA_DIGEST_LEN, digest);

                memcpy(digest1, digest, AIRPDCAP_SHA_DIGEST_LEN);
                /* output = output xor Un */
                for (j = 0; j < AIRPDCAP_SHA_DIGEST_LEN; j++) {
                        output[j] ^= digest[j];
                }
        }

        return AIRPDCAP_RET_SUCCESS;
}

INT AirPDcapRsnaPwd2Psk(
        const CHAR *password,
        const CHAR *ssid,
        const size_t ssidLength,
        UCHAR *output)
{
        UCHAR m_output[AIRPDCAP_WPA_PSK_LEN];

        memset(m_output, 0, AIRPDCAP_WPA_PSK_LEN);

        memset(m_output, 0, 40);

        AirPDcapRsnaPwd2PskStep(password, ssid, ssidLength, 4096, 1, m_output);
        AirPDcapRsnaPwd2PskStep(password, ssid, ssidLength, 4096, 2, &m_output[AIRPDCAP_SHA_DIGEST_LEN]);

        memcpy(output, m_output, AIRPDCAP_WPA_PSK_LEN);

        return 0;
}

/*
 * The following code come from freeBSD and implements the AUTODIN II
 * polynomial used by 802.11.
 * It can be used to calculate multicast address hash indices.
 * It assumes that the low order bits will be transmitted first,
 * and consequently the low byte should be sent first when
 * the crc computation is finished.  The crc should be complemented
 * before transmission.
 * The variable corresponding to the macro argument "crc" should
 * be an unsigned long and should be preset to all ones for Ethernet
 * use.  An error-free packet will leave 0xDEBB20E3 in the crc.
 */
INT AirPDcapAlgCrc32(
        UCHAR *buf,
        size_t nr,
        ULONG *cval)
{
        ULONG crc32_total = 0 ;
        ULONG crc = ~(ULONG)0;
        UCHAR *p ;
        size_t len;

        len = 0 ;
        crc32_total = ~crc32_total ;

        for(len += nr, p = buf; nr--; ++p)
        {
                CRC(crc, *p) ;
                CRC(crc32_total, *p) ;
        }

        *cval = ~crc ;
        crc32_total = ~crc32_total ;

        return 0;
}

#ifdef	__cplusplus
}
#endif

/****************************************************************************/
