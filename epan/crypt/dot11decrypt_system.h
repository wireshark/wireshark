/* dot11decrypt_system.h
 *
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
 */

#ifndef	_DOT11DECRYPT_SYSTEM_H
#define	_DOT11DECRYPT_SYSTEM_H

/************************************************************************/
/*	Constant definitions						*/

/*	General definitions						*/
#ifndef	TRUE
#define	TRUE	1
#endif
#ifndef	FALSE
#define	FALSE	0
#endif

#define	DOT11DECRYPT_RET_SUCCESS                      0
#define	DOT11DECRYPT_RET_UNSUCCESS                    1

#define	DOT11DECRYPT_RET_NO_DATA		          1
#define	DOT11DECRYPT_RET_WRONG_DATA_SIZE	          2
#define	DOT11DECRYPT_RET_REQ_DATA		          3
#define	DOT11DECRYPT_RET_NO_VALID_HANDSHAKE	          4
#define	DOT11DECRYPT_RET_NO_DATA_ENCRYPTED	          5

#define	DOT11DECRYPT_RET_SUCCESS_HANDSHAKE  	 -1

#define	DOT11DECRYPT_MAX_KEYS_NR	        	 64
#define	DOT11DECRYPT_MAX_SEC_ASSOCIATIONS_NR	256

/*	Decryption algorithms fields size definition (bytes)		*/
#define	DOT11DECRYPT_WPA_NONCE_LEN		         32
#define	DOT11DECRYPT_WPA_PTK_LEN			 64	/* TKIP uses 48 bytes, CCMP uses 64 bytes	*/
#define	DOT11DECRYPT_WPA_MICKEY_LEN		         16

#define	DOT11DECRYPT_WEP_128_KEY_LEN	         16	/* 128 bits	*/

/* General 802.11 constants						*/
#define	DOT11DECRYPT_MAC_LEN			   6
#define	DOT11DECRYPT_RADIOTAP_HEADER_LEN	          24

#define	DOT11DECRYPT_EAPOL_MAX_LEN			1024U

#define DOT11DECRYPT_TK_LEN                           16

/* Max length of capture data						*/
#define	DOT11DECRYPT_MAX_CAPLEN			8192

#define	DOT11DECRYPT_WEP_IVLEN	3       /* 24bit */
#define	DOT11DECRYPT_WEP_KIDLEN	1       /* 1 octet */
#define	DOT11DECRYPT_WEP_ICV	4
#define	DOT11DECRYPT_WEP_HEADER	DOT11DECRYPT_WEP_IVLEN + DOT11DECRYPT_WEP_KIDLEN
#define	DOT11DECRYPT_WEP_TRAILER	DOT11DECRYPT_WEP_ICV

/*
 * 802.11i defines an extended IV for use with non-WEP ciphers.
 * When the EXTIV bit is set in the key id byte an additional
 * 4 bytes immediately follow the IV for TKIP.  For CCMP the
 * EXTIV bit is likewise set but the 8 bytes represent the
 * CCMP header rather than IV+extended-IV.
 */
#define	DOT11DECRYPT_RSNA_EXTIV	0x20
#define	DOT11DECRYPT_RSNA_EXTIVLEN	4       /* extended IV length */
#define	DOT11DECRYPT_RSNA_MICLEN	8       /* trailing MIC */

#define	DOT11DECRYPT_RSNA_HEADER	DOT11DECRYPT_WEP_HEADER + DOT11DECRYPT_RSNA_EXTIVLEN

#define	DOT11DECRYPT_CCMP_HEADER	DOT11DECRYPT_RSNA_HEADER
#define	DOT11DECRYPT_CCMP_TRAILER	DOT11DECRYPT_RSNA_MICLEN

#define	DOT11DECRYPT_TKIP_HEADER	DOT11DECRYPT_RSNA_HEADER
#define	DOT11DECRYPT_TKIP_TRAILER	DOT11DECRYPT_RSNA_MICLEN + DOT11DECRYPT_WEP_ICV

#define	DOT11DECRYPT_CRC_LEN	4

/************************************************************************/
/*      File includes                                                   */

#include "dot11decrypt_interop.h"
#include "dot11decrypt_user.h"
#include "ws_symbol_export.h"

/************************************************************************/
/*	Macro definitions						*/

/************************************************************************/
/*	Type definitions						*/

typedef struct _DOT11DECRYPT_SEC_ASSOCIATION_ID {
	UCHAR bssid[DOT11DECRYPT_MAC_LEN];
	UCHAR sta[DOT11DECRYPT_MAC_LEN];
} DOT11DECRYPT_SEC_ASSOCIATION_ID, *PDOT11DECRYPT_SEC_ASSOCIATION_ID;

typedef struct _DOT11DECRYPT_SEC_ASSOCIATION {
    /* This is for reassociations. A linked list of old security
     * associations is kept.  GCS
     */
    struct _DOT11DECRYPT_SEC_ASSOCIATION* next;

	/**
	 * This flag define whether this item is used or not. Accepted
     * values are TRUE and FALSE
	 */
	UINT8 used;
	DOT11DECRYPT_SEC_ASSOCIATION_ID saId;
	DOT11DECRYPT_KEY_ITEM *key;
	UINT8 handshake;
	UINT8 validKey;

	struct {
		UINT8 key_ver;		/* Key descriptor version	*/
		UINT64 pn;		/* only used with CCMP AES -if needed replay check- */
		UCHAR nonce[DOT11DECRYPT_WPA_NONCE_LEN];
		/* used to derive PTK, ANonce stored, SNonce taken	*/
		/* the 2nd packet of the 4W handshake			*/

		UCHAR ptk[DOT11DECRYPT_WPA_PTK_LEN];		/* session key used in decryption algorithm	*/
	} wpa;


} DOT11DECRYPT_SEC_ASSOCIATION, *PDOT11DECRYPT_SEC_ASSOCIATION;

typedef struct _DOT11DECRYPT_CONTEXT {
	DOT11DECRYPT_SEC_ASSOCIATION sa[DOT11DECRYPT_MAX_SEC_ASSOCIATIONS_NR];
	INT sa_index;
	DOT11DECRYPT_KEY_ITEM keys[DOT11DECRYPT_MAX_KEYS_NR];
	size_t keys_nr;

        CHAR pkt_ssid[DOT11DECRYPT_WPA_SSID_MAX_LEN];
        size_t pkt_ssid_len;

	INT index;
	INT first_free_index;
} DOT11DECRYPT_CONTEXT, *PDOT11DECRYPT_CONTEXT;

/************************************************************************/
/*	Function prototype declarations					*/

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * This will try to decrypt a 802.11 frame. If scanHandshake is
 * true it will also check if it's a cleartext or encrypted eapol key
 * frame which can be used to setup TK or GTK decryption keys.
 * @param ctx [IN] Pointer to the current context
 * @param data [IN] Pointer to a buffer with an 802.11 frame, including MAC
 *   header and payload
 * @param data_off [IN] Payload offset (aka the MAC header length)
 * @param data_len [IN] Total length of the MAC header and the payload
 * @param decrypt_data [OUT] Pointer to a buffer that will contain
 *   decrypted data. Must have room for at least DOT11DECRYPT_MAX_CAPLEN bytes.
 * @param decrypt_len [OUT] Length of decrypted data.
 * @param key [OUT] Pointer to a preallocated key structure containing
 *   the key used during the decryption process (if done). If this parameter
 *   is set to NULL, the key will be not returned.
 * @param scanHandshake [IN] If TRUE this function will additional check if
 *   the 802.11 frame data is pointing to has key information and if so use
 *   it to setup potential decryption keys. Enables handshake return codes.
 * @return
 * - DOT11DECRYPT_RET_SUCCESS: Decryption has been done (decrypt_data and
 *   decrypt_length will contain the packet data decrypted and the length of
 *   the new packet)
 * - DOT11DECRYPT_RET_NO_DATA: The packet is not a data packet
 * - DOT11DECRYPT_RET_WRONG_DATA_SIZE: The size of the packet is below the
 *   accepted minimum
 * - DOT11DECRYPT_RET_REQ_DATA: Required data is not available and the
 *   processing must be interrupted (can also occur after decryption when
 *   scanHandshake is TRUE)
 * - DOT11DECRYPT_RET_NO_DATA_ENCRYPTED: Not encrypted and no attempt to
 *   extract key information
 * - DOT11DECRYPT_RET_UNSUCCESS: Generic unspecified error (decrypt_data
 *   and decrypt_length will be not modified).
 * - DOT11DECRYPT_RET_SUCCESS_HANDSHAKE: An eapol handshake packet was successfuly parsed
 *   and key information extracted. The decrypted eapol keydata is copied to
 *   decrypt_data with keydata len in decrypt_len. key param will contain ptk
 *   used to decrypt eapol keydata.
 * - DOT11DECRYPT_RET_NO_VALID_HANDSHAKE: The handshake is invalid or was not used
 *   for some reason. For encrypted packets decryption was still successful.
 * @note
 * The decrypted buffer should be allocated for a size equal or greater
 * than the packet data buffer size. Before decryption process original
 * data is copied in the buffer pointed by decrypt_data not to modify the
 * original packet.
 * @note
 * The length of decrypted data will consider the entire 802.11 frame
 * (thus the MAC header, the frame body and the recalculated FCS -if
 * initially present-)
 * @note
 * This function is not thread-safe when used in parallel with context
 *  management functions on the same context.
 */
extern INT Dot11DecryptPacketProcess(
	PDOT11DECRYPT_CONTEXT ctx,
	const guint8 *data,
	const guint data_off,
	const guint data_len,
	UCHAR *decrypt_data,
	guint32 *decrypt_len,
	PDOT11DECRYPT_KEY_ITEM key,
	gboolean scanHandshake)
	;

/**
 * It sets a new keys collection to use during packet processing.
 * Any key should be well-formed, thus: it should have a defined key
 * type and the specified length should be conforming WEP or WPA/WPA2
 * standards. A general WEP keys could be of any length (in the range
 * defined in DOT11DECRYPT_KEY_ITEM), if a specific WEP key is used, the
 * length of the key will be the one specified in 802.11i-2004 (40 bits or
 * 104 bits).
 * For WPA/WPA2 the password (passphrase and SSID), the PSK and the PMK
 * are in alternative, as explain in the DOT11DECRYPT_KEY_ITEM structure
 * description.
 * @param ctx [IN] pointer to the current context
 * @param keys [IN] an array of keys to set.
 * @param keys_nr [IN] the size of the keys array
 * @return The number of keys correctly inserted in the current database.
 * @note Before inserting new keys, the current database will be cleaned.
 * @note
 * This function is not thread-safe when used in parallel with context
 * management functions and the packet process function on the same
 * context.
 */
extern INT Dot11DecryptSetKeys(
	PDOT11DECRYPT_CONTEXT ctx,
	DOT11DECRYPT_KEY_ITEM keys[],
	const size_t keys_nr)
	;

/**
 * It gets the keys collection fom the specified context.
 * @param ctx [IN] pointer to the current context
 * @param keys [IN] a preallocated array of keys to be returned
 * @param keys_nr [IN] the number of keys to return (the key array must
 * be able to contain at least keys_nr keys)
 * @return The number of keys returned
 * @note
 * Any key could be modified, as stated in the DOT11DECRYPT_KEY_ITEM description.
 * @note
 * This function is not thread-safe when used in parallel with context
 * management functions and the packet process function on the same
 * context.
 */
INT Dot11DecryptGetKeys(
	const PDOT11DECRYPT_CONTEXT ctx,
	DOT11DECRYPT_KEY_ITEM keys[],
	const size_t keys_nr)
	;

/**
 * Sets the "last seen" SSID.  This allows us to pick up previous
 * SSIDs and use them when "wildcard" passphrases are specified
 * in the preferences.
 * @param ctx [IN|OUT] pointer to a preallocated context structure
 * @param pkt_ssid [IN] pointer to the packet's SSID
 * @param pkt_ssid_len [IN] length of the packet's SSID
 * @return
 *   DOT11DECRYPT_RET_SUCCESS: The key has been set.
 *   DOT11DECRYPT_RET_UNSUCCESS: The has not been set, e.g. the length was
 *   too long.
 */
INT Dot11DecryptSetLastSSID(
        PDOT11DECRYPT_CONTEXT ctx,
        CHAR *pkt_ssid,
        size_t pkt_ssid_len)
	;

/**
 * Initialize a context used to manage decryption and keys collection.
 * @param ctx [IN|OUT] pointer to a preallocated context structure
 * @return
 *   DOT11DECRYPT_RET_SUCCESS: the context has been successfully initialized
 *   DOT11DECRYPT_RET_UNSUCCESS: the context has not been initialized
 * @note
 * Only a correctly initialized context can be used to manage decryption
 * processes and keys.
 * @note
 * This function is not thread-safe when used in parallel with context
 * management functions and the packet process function on the same context.
 */
WS_DLL_PUBLIC
INT Dot11DecryptInitContext(
        PDOT11DECRYPT_CONTEXT ctx)
	;

/**
 * Clean up the specified context. After the cleanup the pointer should
 * not be used anymore.
 * @param ctx [IN|OUT] pointer to the current context structure
 * @return
 *  DOT11DECRYPT_RET_SUCCESS: the context has been successfully initialized
 *  DOT11DECRYPT_RET_UNSUCCESS: the context has not been initialized
 * @note
 * This function is not thread-safe when used in parallel with context
 * management functions and the packet process function on the same
 * context.
 */
WS_DLL_PUBLIC
INT Dot11DecryptDestroyContext(
	PDOT11DECRYPT_CONTEXT ctx)
	;

extern INT Dot11DecryptCcmpDecrypt(
	UINT8 *m,
        gint mac_header_len,
	INT len,
	UCHAR TK1[16])
	;
extern INT Dot11DecryptTkipDecrypt(
	UCHAR *tkip_mpdu,
	size_t mpdu_len,
	UCHAR TA[DOT11DECRYPT_MAC_LEN],
	UCHAR TK[DOT11DECRYPT_TK_LEN])
	;

#ifdef	__cplusplus
}
#endif

#endif /* _DOT11DECRYPT_SYSTEM_H */
