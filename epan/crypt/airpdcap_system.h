/* airpdcap_system.h
 *
 * $Id$
 *
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

#ifndef	_AIRPDCAP_SYSTEM_H
#define	_AIRPDCAP_SYSTEM_H

/************************************************************************/
/*	File includes							*/

#include "airpdcap_interop.h"
#include "airpdcap_user.h"

/************************************************************************/
/*	Constant definitions						*/

/*	General definitions						*/
#ifndef	TRUE
#define	TRUE	1
#endif
#ifndef	FALSE
#define	FALSE	0
#endif

#define	AIRPDCAP_RET_SUCCESS                      0
#define	AIRPDCAP_RET_UNSUCCESS                    1

#define	AIRPDCAP_RET_NO_DATA		          1
#define	AIRPDCAP_RET_WRONG_DATA_SIZE	          2
#define	AIRPDCAP_RET_REQ_DATA		          3
#define	AIRPDCAP_RET_NO_VALID_HANDSHAKE	          4
#define	AIRPDCAP_RET_NO_DATA_ENCRYPTED	          5

#define	AIRPDCAP_RET_SUCCESS_HANDSHAKE  	 -1

#define	AIRPDCAP_MAX_KEYS_NR	        	 64
#define	AIRPDCAP_MAX_SEC_ASSOCIATIONS_NR	256

/*	Decryption algorithms fields size definition (bytes)		*/
#define	AIRPDCAP_WPA_NONCE_LEN		         32
#define	AIRPDCAP_WPA_PTK_LEN			 64	/* TKIP uses 48 bytes, CCMP uses 64 bytes	*/
#define	AIRPDCAP_WPA_MICKEY_LEN		         16

#define	AIRPDCAP_WEP_128_KEY_LEN	         16	/* 128 bits	*/

/* General 802.11 constants						*/
#define	AIRPDCAP_MAC_LEN			   6
#define	AIRPDCAP_RADIOTAP_HEADER_LEN	          24

#define	AIRPDCAP_EAPOL_MAX_LEN			1024

#define AIRPDCAP_TK_LEN                           16

/* Max length of capture data						*/
#define	AIRPDCAP_MAX_CAPLEN			8192

#define	AIRPDCAP_WEP_IVLEN	3       /* 24bit */
#define	AIRPDCAP_WEP_KIDLEN	1       /* 1 octet */
#define	AIRPDCAP_WEP_ICV	4
#define	AIRPDCAP_WEP_HEADER	AIRPDCAP_WEP_IVLEN + AIRPDCAP_WEP_KIDLEN
#define	AIRPDCAP_WEP_TRAILER	AIRPDCAP_WEP_ICV

/*
 * 802.11i defines an extended IV for use with non-WEP ciphers.
 * When the EXTIV bit is set in the key id byte an additional
 * 4 bytes immediately follow the IV for TKIP.  For CCMP the
 * EXTIV bit is likewise set but the 8 bytes represent the
 * CCMP header rather than IV+extended-IV.
 */
#define	AIRPDCAP_RSNA_EXTIV	0x20
#define	AIRPDCAP_RSNA_EXTIVLEN	4       /* extended IV length */
#define	AIRPDCAP_RSNA_MICLEN	8       /* trailing MIC */

#define	AIRPDCAP_RSNA_HEADER	AIRPDCAP_WEP_HEADER + AIRPDCAP_RSNA_EXTIVLEN

#define	AIRPDCAP_CCMP_HEADER	AIRPDCAP_RSNA_HEADER
#define	AIRPDCAP_CCMP_TRAILER	AIRPDCAP_RSNA_MICLEN

#define	AIRPDCAP_TKIP_HEADER	AIRPDCAP_RSNA_HEADER
#define	AIRPDCAP_TKIP_TRAILER	AIRPDCAP_RSNA_MICLEN + AIRPDCAP_WEP_ICV

#define	AIRPDCAP_CRC_LEN	4

/************************************************************************/
/*	Macro definitions						*/

/************************************************************************/
/*	Type definitions						*/

typedef struct _AIRPDCAP_SEC_ASSOCIATION_ID {
	UCHAR bssid[AIRPDCAP_MAC_LEN];
	UCHAR sta[AIRPDCAP_MAC_LEN];
} AIRPDCAP_SEC_ASSOCIATION_ID, *PAIRPDCAP_SEC_ASSOCIATION_ID;

typedef struct _AIRPDCAP_SEC_ASSOCIATION {
    /* This is for reassociations. A linked list of old security 
     * associations is kept.  GCS
     */
    struct _AIRPDCAP_SEC_ASSOCIATION* next;

	/**
	 * This flag define whether this item is used or not. Accepted
     * values are TRUE and FALSE
	 */
	UINT8 used;
	AIRPDCAP_SEC_ASSOCIATION_ID saId;
	AIRPDCAP_KEY_ITEM *key;
	UINT8 handshake;
	UINT8 validKey;

	struct {
		UINT8 key_ver;		/* Key descriptor version	*/
		UINT64 pn;		/* only used with CCMP AES -if needed replay check- */
		UCHAR nonce[AIRPDCAP_WPA_NONCE_LEN];
		/* used to derive PTK, ANonce stored, SNonce taken	*/
		/* the 2nd packet of the 4W handshake			*/

		UCHAR ptk[AIRPDCAP_WPA_PTK_LEN];		/* session key used in decryption algorithm	*/
	} wpa;


} AIRPDCAP_SEC_ASSOCIATION, *PAIRPDCAP_SEC_ASSOCIATION;

typedef struct _AIRPDCAP_CONTEXT {
	AIRPDCAP_SEC_ASSOCIATION sa[AIRPDCAP_MAX_SEC_ASSOCIATIONS_NR];
	INT sa_index;
	AIRPDCAP_KEY_ITEM keys[AIRPDCAP_MAX_KEYS_NR];
	size_t keys_nr;

        CHAR pkt_ssid[AIRPDCAP_WPA_SSID_MAX_LEN];
        size_t pkt_ssid_len;

	INT index;
	INT first_free_index;
} AIRPDCAP_CONTEXT, *PAIRPDCAP_CONTEXT;

/************************************************************************/
/*	Function prototype declarations					*/

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * Given an 802.11 packet, either extract its key data (in the case of
 * WPA handshaking) or try to decrypt it.
 * @param ctx [IN] Pointer to the current context
 * @param data [IN] Pointer to a buffer with an 802.11 frame, including MAC
 *   header and payload
 * @param data_off [IN] Payload offset (aka the MAC header length)
 * @param data_len [IN] Total length of the MAC header and the payload
 * @param decrypt_data [OUT] Pointer to a buffer that will contain
 *   decrypted data
 * @param decrypt_len [OUT] Length of decrypted data
 * @param key [OUT] Pointer to a preallocated key structure containing
 *   the key used during the decryption process (if done). If this parameter
 *   is set to NULL, the key will be not returned.
 * @param mngHandshake [IN] If TRUE this function will manage the 4-way
 *   handshake for WPA/WPA2
 * @param mngDecrypt [IN] If TRUE this function will manage the WEP or
 * WPA/WPA2 decryption
 * @return
 * - AIRPDCAP_RET_SUCCESS: Decryption has been done (decrypt_data and
 *   decrypt_length will contain the packet data decrypted and the length of
 *   the new packet)
 * - AIRPDCAP_RET_SUCCESS_HANDSHAKE: A step of the 4-way handshake for
 *   WPA key has been successfully done
 * - AIRPDCAP_RET_NO_DATA: The packet is not a data packet
 * - AIRPDCAP_RET_WRONG_DATA_SIZE: The size of the packet is below the
 *   accepted minimum
 * - AIRPDCAP_RET_REQ_DATA: Required data is not available and the
 *   processing must be interrupted
 * - AIRPDCAP_RET_NO_VALID_HANDSHAKE: The authentication is not for WPA or RSNA
 * - AIRPDCAP_RET_NO_DATA_ENCRYPTED: No encrypted data
 * - AIRPDCAP_RET_UNSUCCESS: No decryption has been done (decrypt_data
 *   and decrypt_length will be not modified).
 * Some other errors could be:
 *   data not correct
 *   data not encrypted
 *   key handshake, not encryption
 *   decryption not successful
 *   key handshake not correct
 *   replay check not successful
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
extern INT AirPDcapPacketProcess(
	PAIRPDCAP_CONTEXT ctx,
	const guint8 *data,
	const guint data_off,
	const guint data_len,
	UCHAR *decrypt_data,
	guint32 *decrypt_len,
	PAIRPDCAP_KEY_ITEM key,
	gboolean mngHandshake,
	gboolean mngDecrypt)
	;

/**
 * It sets a new keys collection to use during packet processing.
 * Any key should be well-formed, thus: it should have a defined key
 * type and the specified length should be conforming WEP or WPA/WPA2
 * standards. A general WEP keys could be of any length (in the range
 * defined in AIRPDCAP_KEY_ITEM), if a specific WEP key is used, the
 * length of the key will be the one specified in 802.11i-2004 (40 bits or
 * 104 bits).
 * For WPA/WPA2 the password (passphrase and SSID), the PSK and the PMK
 * are in alternative, as explain in the AIRPDCAP_KEY_ITEM structure
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
extern INT AirPDcapSetKeys(
	PAIRPDCAP_CONTEXT ctx,
	AIRPDCAP_KEY_ITEM keys[],
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
 * Any key could be modified, as stated in the AIRPDCAP_KEY_ITEM description.
 * @note
 * This function is not thread-safe when used in parallel with context
 * management functions and the packet process function on the same
 * context.
 */
INT AirPDcapGetKeys(
	const PAIRPDCAP_CONTEXT ctx,
	AIRPDCAP_KEY_ITEM keys[],
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
 *   AIRPDCAP_RET_SUCCESS: The key has been set.
 *   AIRPDCAP_RET_UNSUCCESS: The has not been set, e.g. the length was
 *   too long.
 */
INT AirPDcapSetLastSSID(
        PAIRPDCAP_CONTEXT ctx,
        CHAR *pkt_ssid,
        size_t pkt_ssid_len)
	;

/**
 * Initialize a context used to manage decryption and keys collection.
 * @param ctx [IN|OUT] pointer to a preallocated context structure
 * @return
 *   AIRPDCAP_RET_SUCCESS: the context has been successfully initialized
 *   AIRPDCAP_RET_UNSUCCESS: the context has not been initialized
 * @note
 * Only a correctly initialized context can be used to manage decryption
 * processes and keys.
 * @note
 * This function is not thread-safe when used in parallel with context
 * management functions and the packet process function on the same context.
 */
INT AirPDcapInitContext(
        PAIRPDCAP_CONTEXT ctx)
	;

/**
 * Clean up the specified context. After the cleanup the pointer should
 * not be used anymore.
 * @param ctx [IN|OUT] pointer to the current context structure
 * @return
 *  AIRPDCAP_RET_SUCCESS: the context has been successfully initialized
 *  AIRPDCAP_RET_UNSUCCESS: the context has not been initialized
 * @note
 * This function is not thread-safe when used in parallel with context
 * management functions and the packet process function on the same
 * context.
 */
INT AirPDcapDestroyContext(
	PAIRPDCAP_CONTEXT ctx)
	;

extern INT AirPDcapCcmpDecrypt(
	UINT8 *m,
        gint mac_header_len,
	INT len,
	UCHAR TK1[16])
	;
extern INT AirPDcapTkipDecrypt(
	UCHAR *tkip_mpdu,
	size_t mpdu_len,
	UCHAR TA[AIRPDCAP_MAC_LEN],
	UCHAR TK[AIRPDCAP_TK_LEN])
	;

#ifdef	__cplusplus
}
#endif

#endif /* _AIRPDCAP_SYSTEM_H */
