/** @file
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
#define	DOT11DECRYPT_RET_SUCCESS                      0
#define	DOT11DECRYPT_RET_UNSUCCESS                    1

#define	DOT11DECRYPT_RET_NO_DATA		          1
#define	DOT11DECRYPT_RET_WRONG_DATA_SIZE	          2
#define	DOT11DECRYPT_RET_REQ_DATA		          3
#define	DOT11DECRYPT_RET_NO_VALID_HANDSHAKE	          4
#define	DOT11DECRYPT_RET_NO_DATA_ENCRYPTED	          5

#define	DOT11DECRYPT_RET_SUCCESS_HANDSHAKE  	 -1

#define	DOT11DECRYPT_MAX_KEYS_NR	        	 64

/*	Decryption algorithms fields size definition (bytes)		*/
#define	DOT11DECRYPT_WPA_NONCE_LEN		         32
#define	DOT11DECRYPT_WPA_PTK_MAX_LEN			 88	/* TKIP 48, CCMP 64, GCMP-256 88 bytes */
#define	DOT11DECRYPT_WPA_MICKEY_MAX_LEN			 24

#define	DOT11DECRYPT_WEP_128_KEY_LEN	         16	/* 128 bits	*/

/* General 802.11 constants						*/
#define	DOT11DECRYPT_MAC_LEN			   6
#define	DOT11DECRYPT_RADIOTAP_HEADER_LEN	          24

#define	DOT11DECRYPT_EAPOL_MAX_LEN			1024U

#define DOT11DECRYPT_TK_LEN                           16

/* Max length of capture data						*/
#define	DOT11DECRYPT_MAX_CAPLEN			(12 * 1024)

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
#define	DOT11DECRYPT_TKIP_MICLEN	8       /* trailing MIC */

#define	DOT11DECRYPT_RSNA_HEADER	DOT11DECRYPT_WEP_HEADER + DOT11DECRYPT_RSNA_EXTIVLEN

#define	DOT11DECRYPT_CCMP_HEADER		DOT11DECRYPT_RSNA_HEADER
#define	DOT11DECRYPT_CCMP_TRAILER		8   /* IEEE 802.11-2016 12.5.3.2 CCMP MPDU format */
#define	DOT11DECRYPT_CCMP_256_TRAILER	16  /* IEEE 802.11-2016 12.5.3.2 CCMP MPDU format */

#define	DOT11DECRYPT_GCMP_HEADER		8   /* IEEE 802.11-206 12.5.5.2 GCMP MPDU format */
#define	DOT11DECRYPT_GCMP_TRAILER		16

#define	DOT11DECRYPT_TKIP_HEADER	DOT11DECRYPT_RSNA_HEADER
#define	DOT11DECRYPT_TKIP_TRAILER	DOT11DECRYPT_TKIP_MICLEN + DOT11DECRYPT_WEP_ICV

#define DOT11DECRYPT_RSNA_MIN_TRAILER 8

#define	DOT11DECRYPT_CRC_LEN	4

/************************************************************************/
/*      File includes                                                   */

#include <stdint.h>
#include <stdbool.h>

#include "dot11decrypt_user.h"
#include "ws_symbol_export.h"

/************************************************************************/
/*	Macro definitions						*/

/************************************************************************/
/*	Type definitions						*/

typedef struct _DOT11DECRYPT_SEC_ASSOCIATION_ID {
	unsigned char bssid[DOT11DECRYPT_MAC_LEN];
	unsigned char sta[DOT11DECRYPT_MAC_LEN];
} DOT11DECRYPT_SEC_ASSOCIATION_ID, *PDOT11DECRYPT_SEC_ASSOCIATION_ID;

typedef struct _DOT11DECRYPT_SEC_ASSOCIATION {
    /* This is for reassociations. A linked list of old security
     * associations is kept.  GCS
     */
    struct _DOT11DECRYPT_SEC_ASSOCIATION* next;

	DOT11DECRYPT_SEC_ASSOCIATION_ID saId;
	DOT11DECRYPT_KEY_ITEM *key;
	uint8_t handshake;
	uint8_t validKey;

	struct {
		uint8_t key_ver;		/* Key descriptor version	*/
		unsigned char nonce[DOT11DECRYPT_WPA_NONCE_LEN];
		/* used to derive PTK, ANonce stored, SNonce taken	*/
		/* the 2nd packet of the 4W handshake			*/
		int akm;
		int cipher;
		int tmp_group_cipher; /* Keep between HS msg 2 and 3 */
		unsigned char ptk[DOT11DECRYPT_WPA_PTK_MAX_LEN]; /* session key used in decryption algorithm */
		int ptk_len;
		int dh_group;
	} wpa;


} DOT11DECRYPT_SEC_ASSOCIATION, *PDOT11DECRYPT_SEC_ASSOCIATION;

typedef struct _DOT11DECRYPT_CONTEXT {
	GHashTable *sa_hash;
	DOT11DECRYPT_KEY_ITEM keys[DOT11DECRYPT_MAX_KEYS_NR];
	size_t keys_nr;
	char pkt_ssid[DOT11DECRYPT_WPA_SSID_MAX_LEN];
	size_t pkt_ssid_len;
} DOT11DECRYPT_CONTEXT, *PDOT11DECRYPT_CONTEXT;

typedef enum _DOT11DECRYPT_HS_MSG_TYPE {
	DOT11DECRYPT_HS_MSG_TYPE_INVALID = 0,
	DOT11DECRYPT_HS_MSG_TYPE_4WHS_1,
	DOT11DECRYPT_HS_MSG_TYPE_4WHS_2,
	DOT11DECRYPT_HS_MSG_TYPE_4WHS_3,
	DOT11DECRYPT_HS_MSG_TYPE_4WHS_4,
	DOT11DECRYPT_HS_MSG_TYPE_GHS_1,
	DOT11DECRYPT_HS_MSG_TYPE_GHS_2
} DOT11DECRYPT_HS_MSG_TYPE;

typedef struct _DOT11DECRYPT_FTE {
	uint8_t *mic;
	uint8_t mic_len;
	uint8_t *anonce;
	uint8_t *snonce;
	uint8_t *r0kh_id;
	uint8_t r0kh_id_len;
	uint8_t *r1kh_id;
	uint8_t r1kh_id_len;
} DOT11DECRYPT_FTE, *PDOT11DECRYPT_FTE;

typedef struct _DOT11DECRYPT_EAPOL_PARSED {
	DOT11DECRYPT_HS_MSG_TYPE msg_type;
	uint16_t len;
	uint8_t key_type;
	uint8_t key_version;
	uint16_t key_len;
	uint8_t *key_iv;
	uint8_t *key_data;
	uint16_t key_data_len;
	uint8_t group_cipher;
	uint8_t cipher;
	uint8_t akm;
	uint8_t *nonce;
	uint8_t *mic;
	uint16_t mic_len;
	uint8_t *gtk;
	uint16_t gtk_len;
	uint16_t dh_group;

	/* For fast bss transition akms */
	uint8_t *mdid;
	DOT11DECRYPT_FTE fte;
} DOT11DECRYPT_EAPOL_PARSED, *PDOT11DECRYPT_EAPOL_PARSED;

typedef struct _DOT11DECRYPT_ASSOC_PARSED
{
	uint8_t frame_subtype;
	uint8_t group_cipher;
	uint8_t cipher;
	uint8_t akm;
	uint8_t *mdid;
	DOT11DECRYPT_FTE fte;
	uint8_t* rsne_tag;
	uint8_t* rsnxe_tag;
	uint8_t* mde_tag;
	uint8_t* fte_tag;
	uint8_t* rde_tag;
	uint8_t *gtk;
	uint16_t gtk_len;
	uint16_t gtk_subelem_key_len;
	uint8_t bssid[DOT11DECRYPT_MAC_LEN];
	uint8_t sa[DOT11DECRYPT_MAC_LEN];
	uint8_t da[DOT11DECRYPT_MAC_LEN];
} DOT11DECRYPT_ASSOC_PARSED, *PDOT11DECRYPT_ASSOC_PARSED;

/************************************************************************/
/*	Function prototype declarations					*/

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * This will try to decrypt a 802.11 frame.
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
 * @return
 * - DOT11DECRYPT_RET_SUCCESS: Decryption has been done (decrypt_data and
 *   decrypt_length will contain the packet data decrypted and the length of
 *   the new packet)
 * - DOT11DECRYPT_RET_NO_DATA: The packet is not a data packet
 * - DOT11DECRYPT_RET_WRONG_DATA_SIZE: The size of the packet is below the
 *   accepted minimum
 * - DOT11DECRYPT_RET_REQ_DATA: Required data is not available and the
 *   processing must be interrupted
 * - DOT11DECRYPT_RET_NO_DATA_ENCRYPTED: Not encrypted
 * - DOT11DECRYPT_RET_UNSUCCESS: Generic unspecified error (decrypt_data
 *   and decrypt_length will be not modified).
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

extern int Dot11DecryptDecryptPacket(
	PDOT11DECRYPT_CONTEXT ctx,
	const uint8_t *data,
	const unsigned data_off,
	const unsigned data_len,
	unsigned char *decrypt_data,
	uint32_t *decrypt_len,
	PDOT11DECRYPT_KEY_ITEM key)
	;

/**
 * This will try to decrypt the encrypted keydata field of an EAPOL KEY frame.
 * @param ctx [IN] Pointer to the current context
 * @param eapol_parsed [IN] Extracted/Parsed pieces of eapol frame
 * @param bssid [IN] bssid of AP
 * @param sta [IN] sta MAC address
 * @param decrypted_data [OUT] Pointer to a buffer that will contain
 *   decrypted data. Must have room for at least DOT11DECRYPT_EAPOL_MAX_LEN bytes.
 * @param decrypted_len [OUT] Length of decrypted data.
 * @param key [OUT] Pointer to a preallocated key structure containing
 *   the key used during the decryption process (if done). If this parameter
 *   is set to NULL, the key will be not returned.
 * @return
 * - DOT11DECRYPT_RET_SUCCESS: Decryption has been done (decrypt_data and
 *   decrypt_length will contain the packet data decrypted and the length of
 *   the new packet)
 * - DOT11DECRYPT_RET_UNSUCCESS: Generic unspecified error (decrypt_data
 *   and decrypt_length will be not modified).
 */
extern int
Dot11DecryptDecryptKeyData(PDOT11DECRYPT_CONTEXT ctx,
                           PDOT11DECRYPT_EAPOL_PARSED eapol_parsed,
                           const unsigned char bssid[DOT11DECRYPT_MAC_LEN],
                           const unsigned char sta[DOT11DECRYPT_MAC_LEN],
                           unsigned char *decrypted_data, unsigned *decrypted_len,
                           PDOT11DECRYPT_KEY_ITEM key)
	;

/**
 * This will try to extract keys from an EAPOL frame and add corresponding
 * SAs to current context. eapol_parsed must contain the already parsed EAPOL
 * key frame and for frames that contain encrypted EAPOL keydata the keydata
 * must first be decrypted with Dot11DecryptDecryptKeyData before calling this
 * function.
 * @param ctx [IN] Pointer to the current context
 * @param eapol_parsed [IN] Extracted/Parsed pieces of eapol frame
 * @param eapol_raw [IN] Pointer to a buffer with an EAPOL frame
 * @param tot_len [IN] Total length of the EAPOL frame
 * @param bssid [IN] bssid of AP
 * @param sta [IN] sta MAC address
 * @return
 * - DOT11DECRYPT_RET_REQ_DATA: Required data is not available and the
 *   processing must be interrupted
 * - DOT11DECRYPT_RET_UNSUCCESS: Generic unspecified error (decrypt_data
 *   and decrypt_length will be not modified).
 * - DOT11DECRYPT_RET_SUCCESS_HANDSHAKE: An eapol handshake packet was successfuly parsed
 *   and key information extracted.
 * - DOT11DECRYPT_RET_NO_VALID_HANDSHAKE: The handshake is invalid or was not used
 *   for some reason. For encrypted packets decryption was still successful.
 * @note
 * This function is not thread-safe when used in parallel with context
 *  management functions on the same context.
 */
extern int Dot11DecryptScanEapolForKeys(
    PDOT11DECRYPT_CONTEXT ctx,
    PDOT11DECRYPT_EAPOL_PARSED eapol_parsed,
    const uint8_t *eapol_raw,
    const unsigned tot_len,
    const unsigned char bssid[DOT11DECRYPT_MAC_LEN],
    const unsigned char sta[DOT11DECRYPT_MAC_LEN])
	;

/**
 * This will try to extract keys from an FT (re)association frame and add
 * corresponding SAs to current context. assoc_parsed must contain the already
 * parsed association frame content. If the FT BSS Transition IE contains an
 * encrypted GTK subelem and decryption is successful the decrypted GTK will
 * be returned in decrypted_gtk.
 * @param ctx [IN] Pointer to the current context
 * @param assoc_parsed [IN] Extracted/Parsed pieces of association frame
 * @param decrypted_gtk [OUT] Buffer for decrypted GTK subelem
 * @param decrypted_len [OUT] Decrypted GTK subelem key length
 * @param used_key [OUT] Buffer to hold the key used during the decryption process.
 * @return
 * - DOT11DECRYPT_RET_UNSUCCESS: Generic unspecified error (decrypted_gtk
 *   and decrypted_len will be not modified).
 * - DOT11DECRYPT_RET_SUCCESS_HANDSHAKE: An association frame was successfuly parsed
 *   and key information extracted.
 * - DOT11DECRYPT_RET_NO_VALID_HANDSHAKE: The association is invalid or no matching
 *   key for decryption was found.
 */
int
Dot11DecryptScanFtAssocForKeys(
    const PDOT11DECRYPT_CONTEXT ctx,
    const PDOT11DECRYPT_ASSOC_PARSED assoc_parsed,
    uint8_t *decrypted_gtk, size_t *decrypted_len,
    DOT11DECRYPT_KEY_ITEM* used_key);

/**
 * This will try to extract keys from a TDLS action frame (without MAC headers)
 * and add corresponding SAs to current context.
 * @param ctx [IN] Pointer to the current context
 * @param data [IN] Pointer to a buffer with a TDLS action frame
 * @param tot_len [IN] Total length of the TDLS action frame
 * @return
 * - DOT11DECRYPT_RET_REQ_DATA: Required data is not available and the
 *   processing must be interrupted
 * - DOT11DECRYPT_RET_SUCCESS_HANDSHAKE: The TDLS action frame was successfuly parsed
 *   and key information extracted.
 * - DOT11DECRYPT_RET_NO_VALID_HANDSHAKE: No keys extracted
 */
extern int Dot11DecryptScanTdlsForKeys(
    PDOT11DECRYPT_CONTEXT ctx,
    const uint8_t *data,
    const unsigned tot_len)
	;

/**
 * These are helper functions to retrieve KCK, KEK, TK portion of PTK
 * for a certain "key"
 * @param key [IN] Pointer to a key structure containing the key retrieved
 * from functions Dot11DecryptDecryptPacket, Dot11DecryptKeydata
 * @param kck [OUT] Pointer to the KCK/KEK/TK portion of PTK.
 * @return length in bytes of KCK/KEK/TK
 */
int
Dot11DecryptGetKCK(const PDOT11DECRYPT_KEY_ITEM key, const uint8_t **kck);

int
Dot11DecryptGetKEK(const PDOT11DECRYPT_KEY_ITEM key, const uint8_t **kek);

int
Dot11DecryptGetTK(const PDOT11DECRYPT_KEY_ITEM key, const uint8_t **tk);

int
Dot11DecryptGetGTK(const PDOT11DECRYPT_KEY_ITEM key, const uint8_t **gtk);

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
extern int Dot11DecryptSetKeys(
	PDOT11DECRYPT_CONTEXT ctx,
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
int Dot11DecryptSetLastSSID(
        PDOT11DECRYPT_CONTEXT ctx,
        char *pkt_ssid,
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
int Dot11DecryptInitContext(
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
int Dot11DecryptDestroyContext(
	PDOT11DECRYPT_CONTEXT ctx)
	;

#ifdef	__cplusplus
}
#endif

#endif /* _DOT11DECRYPT_SYSTEM_H */
