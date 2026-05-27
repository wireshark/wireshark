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
#define	DOT11DECRYPT_WPA_PTK_MAX_LEN			 96	/* TKIP 48, AKM 18/24/25 96 */
#define	DOT11DECRYPT_WPA_MICKEY_MAX_LEN			 32

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

#define DOT11DECRYPT_MAX_MLO_LINKS 3 // Is there actually any device supporting this many links?

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

/**
 * @brief Uniquely identifies a security association by the BSSID and station MAC address pair.
 */
typedef struct _DOT11DECRYPT_SEC_ASSOCIATION_ID {
    unsigned char bssid[DOT11DECRYPT_MAC_LEN]; /**< MAC address of the access point (BSSID) */
    unsigned char sta[DOT11DECRYPT_MAC_LEN];   /**< MAC address of the associated station (STA) */
} DOT11DECRYPT_SEC_ASSOCIATION_ID, *PDOT11DECRYPT_SEC_ASSOCIATION_ID;

/**
 * @brief Holds the full cryptographic state of a security association between a STA and an AP.
 */
typedef struct _DOT11DECRYPT_SEC_ASSOCIATION {
    struct _DOT11DECRYPT_SEC_ASSOCIATION *next; /**< Pointer to the previous security association in the reassociation linked list; NULL if none */

    DOT11DECRYPT_SEC_ASSOCIATION_ID saId;       /**< Identity of this security association (BSSID + STA MAC) */
    DOT11DECRYPT_KEY_ITEM          *key;        /**< Pointer to the key material used to derive session keys */
    uint8_t                         handshake;  /**< Current 4-way handshake progress state (1–4) */
    uint8_t                         validKey;   /**< Non-zero if a valid PTK has been derived and is ready for decryption */

    struct {
        uint8_t       key_ver;                              /**< EAPOL-Key descriptor version negotiated during the handshake */
        unsigned char nonce[DOT11DECRYPT_WPA_NONCE_LEN];   /**< ANonce captured from handshake message 1, used with SNonce to derive the PTK */
        int           akm;                                  /**< AKM suite selector identifying the authentication and key management method */
        int           cipher;                               /**< Pairwise cipher suite selector (e.g. CCMP, TKIP) */
        int           tmp_group_cipher;                     /**< Group cipher suite, cached between handshake messages 2 and 3 */
        int           pmk_len;                              /**< Length in bytes of the Pairwise Master Key (PMK) */
        unsigned char ptk[DOT11DECRYPT_WPA_PTK_MAX_LEN];   /**< Derived Pairwise Transient Key (PTK) used as the session decryption key */
        int           ptk_len;                              /**< Length in bytes of the derived PTK */

        /* MLD info */
        uint8_t mld           : 1;                         /**< 1 if both the AP MLD MAC and STA MLD MAC have been set */
        uint8_t ap_mld_mac_set : 1;                        /**< 1 if @p ap_mld_mac has been populated */
        uint8_t sta_mld_mac_set : 1;                       /**< 1 if @p sta_mld_mac has been populated */
        uint8_t ap_mld_mac[DOT11DECRYPT_MAC_LEN];          /**< Multi-Link Device MAC address of the AP */
        uint8_t sta_mld_mac[DOT11DECRYPT_MAC_LEN];         /**< Multi-Link Device MAC address of the station */

        /**
         * @brief Per-link identity and address information for a single MLO affiliated link.
         */
        struct DOT11DECRYPT_MLO_LINK_INFO {
            uint8_t id_set     : 1;                        /**< 1 if the link ID has been set */
            uint8_t sta_mac_set : 1;                       /**< 1 if @p sta_mac has been populated for this link */
            uint8_t ap_mac_set  : 1;                       /**< 1 if @p ap_mac has been populated for this link */
            uint8_t id          : 4;                       /**< Link ID assigned by the AP for this affiliated link */
            uint8_t sta_mac[DOT11DECRYPT_MAC_LEN];         /**< STA MAC address on this affiliated link */
            uint8_t ap_mac[DOT11DECRYPT_MAC_LEN];          /**< AP MAC address on this affiliated link */
        } mlo_links[DOT11DECRYPT_MAX_MLO_LINKS];           /**< Array of per-link info for all MLO affiliated links */
    } wpa; /**< WPA/RSN-specific handshake and key derivation state */

} DOT11DECRYPT_SEC_ASSOCIATION, *PDOT11DECRYPT_SEC_ASSOCIATION;

/**
 * @brief Global decryption context holding keys and session state for dot11decrypt.
 */
typedef struct _DOT11DECRYPT_CONTEXT {
    GHashTable *sa_hash;                          /**< Hash table of active Security Associations (SA), keyed by address/session info */
    DOT11DECRYPT_KEY_ITEM keys[DOT11DECRYPT_MAX_KEYS_NR]; /**< Array of configured decryption keys */
    size_t keys_nr;                               /**< Number of valid entries in @ref keys */
    uint8_t pkt_ssid[DOT11DECRYPT_WPA_SSID_MAX_LEN]; /**< SSID extracted from the current packet */
    size_t pkt_ssid_len;                          /**< Length in bytes of @ref pkt_ssid */
} DOT11DECRYPT_CONTEXT, *PDOT11DECRYPT_CONTEXT;


/**
 * @brief EAPOL handshake message type, identifying the step within a 4-Way or Group handshake.
 */
typedef enum _DOT11DECRYPT_HS_MSG_TYPE {
    DOT11DECRYPT_HS_MSG_TYPE_INVALID = 0, /**< Invalid or unrecognized handshake message */
    DOT11DECRYPT_HS_MSG_TYPE_4WHS_1,      /**< 4-Way Handshake message 1 (ANonce from AP) */
    DOT11DECRYPT_HS_MSG_TYPE_4WHS_2,      /**< 4-Way Handshake message 2 (SNonce from STA, MIC) */
    DOT11DECRYPT_HS_MSG_TYPE_4WHS_3,      /**< 4-Way Handshake message 3 (GTK, MIC from AP) */
    DOT11DECRYPT_HS_MSG_TYPE_4WHS_4,      /**< 4-Way Handshake message 4 (ACK from STA) */
    DOT11DECRYPT_HS_MSG_TYPE_GHS_1,       /**< Group Handshake message 1 (new GTK from AP) */
    DOT11DECRYPT_HS_MSG_TYPE_GHS_2        /**< Group Handshake message 2 (ACK from STA) */
} DOT11DECRYPT_HS_MSG_TYPE;


/**
 * @brief Parsed fields from an IEEE 802.11r Fast Transition Element (FTE).
 */
typedef struct _DOT11DECRYPT_FTE {
    uint8_t *mic;         /**< Pointer to the Message Integrity Code (MIC) field */
    uint8_t  mic_len;     /**< Length in bytes of @ref mic */
    uint8_t *anonce;      /**< Pointer to the Authenticator Nonce (ANonce) */
    uint8_t *snonce;      /**< Pointer to the Supplicant Nonce (SNonce) */
    uint8_t *r0kh_id;     /**< Pointer to the R0 Key Holder Identifier */
    uint8_t  r0kh_id_len; /**< Length in bytes of @ref r0kh_id */
    uint8_t *r1kh_id;     /**< Pointer to the R1 Key Holder Identifier */
    uint8_t  r1kh_id_len; /**< Length in bytes of @ref r1kh_id */
} DOT11DECRYPT_FTE, *PDOT11DECRYPT_FTE;


/**
 * @brief Parsed representation of an EAPOL key frame for WPA/WPA2/WPA3 handshake processing.
 */
typedef struct _DOT11DECRYPT_EAPOL_PARSED {
    DOT11DECRYPT_HS_MSG_TYPE msg_type; /**< Identified handshake step this EAPOL frame belongs to */
    uint16_t len;                      /**< Total length of the EAPOL frame in bytes */
    uint8_t  key_type;                 /**< Key descriptor type (e.g., RSN vs. WPA legacy) */
    uint8_t  key_version;              /**< Key descriptor version field */
    uint16_t key_len;                  /**< Length of the temporal key in bytes */
    uint8_t *key_iv;                   /**< Pointer to the key IV field */
    uint8_t *key_data;                 /**< Pointer to the Key Data payload */
    uint16_t key_data_len;             /**< Length in bytes of @ref key_data */
    uint8_t  group_cipher;             /**< Group cipher suite selector */
    uint8_t  cipher;                   /**< Pairwise cipher suite selector */
    uint8_t  akm;                      /**< Authentication and Key Management (AKM) suite selector */
    uint8_t *nonce;                    /**< Pointer to the nonce field (ANonce or SNonce depending on direction) */
    uint8_t *mic;                      /**< Pointer to the Message Integrity Code (MIC) */
    uint16_t mic_len;                  /**< Length in bytes of @ref mic */
    uint8_t *gtk;                      /**< Pointer to the Group Temporal Key (GTK), if present */
    uint16_t gtk_len;                  /**< Length in bytes of @ref gtk */
    uint8_t *mld_mac;                  /**< Pointer to the MLD (Multi-Link Device) MAC address, if present */

    uint8_t mlo_link_count;            /**< Number of valid entries in @ref mlo_link */
    /** @brief Per-link identity record for an MLO (Multi-Link Operation) association. */
    struct DOT11DECRYPT_EAPOL_PARSED_MLO_LINK {
        uint8_t  id;  /**< Link ID */
        uint8_t *mac; /**< Pointer to the MAC address for this link */
    } mlo_link[DOT11DECRYPT_MAX_MLO_LINKS]; /**< Array of MLO link identifiers */

    uint8_t mlo_gtk_count;             /**< Number of valid entries in @ref mlo_gtk */
    /** @brief Per-link Group Temporal Key record for an MLO association. */
    struct DOT11DECRYPT_EAPOL_PARSED_MLO_GTK {
        uint8_t  link_id; /**< Link ID this GTK applies to */
        uint8_t *key;     /**< Pointer to the GTK key material */
        uint8_t  len;     /**< Length in bytes of @ref key */
    } mlo_gtk[DOT11DECRYPT_MAX_MLO_LINKS]; /**< Array of per-link GTKs */

    /* For fast BSS transition AKMs */
    uint8_t        *mdid; /**< Pointer to the Mobility Domain Identifier (MDID), used for 802.11r FT AKMs */
    DOT11DECRYPT_FTE fte; /**< Parsed Fast Transition Element (FTE) fields */
} DOT11DECRYPT_EAPOL_PARSED, *PDOT11DECRYPT_EAPOL_PARSED;


/**
 * @brief Parsed representation of an 802.11 association or reassociation frame.
 */
typedef struct _DOT11DECRYPT_ASSOC_PARSED {
    uint8_t  frame_subtype;          /**< 802.11 frame subtype (e.g., association request/response) */
    uint8_t  group_cipher;           /**< Group cipher suite selector from RSNE */
    uint8_t  cipher;                 /**< Pairwise cipher suite selector from RSNE */
    uint8_t  akm;                    /**< AKM suite selector from RSNE */
    uint8_t *mdid;                   /**< Pointer to the Mobility Domain Identifier (MDID), for FT AKMs */
    DOT11DECRYPT_FTE fte;            /**< Parsed Fast Transition Element (FTE) fields */
    uint8_t *rsne_tag;               /**< Pointer to the raw RSN Element (RSNE) tag in the frame */
    uint8_t *rsnxe_tag;              /**< Pointer to the raw RSN Extension Element (RSNXE) tag */
    uint8_t *mde_tag;                /**< Pointer to the raw Mobility Domain Element (MDE) tag */
    uint8_t *fte_tag;                /**< Pointer to the raw Fast Transition Element (FTE) tag */
    uint8_t *rde_tag;                /**< Pointer to the raw Resource Request/Response Element (RDE) tag */
    uint8_t *gtk;                    /**< Pointer to the Group Temporal Key (GTK), if present */
    uint16_t gtk_len;                /**< Length in bytes of @ref gtk */
    uint16_t gtk_subelem_key_len;    /**< Length in bytes of the GTK subelement key field */
    uint8_t  bssid[DOT11DECRYPT_MAC_LEN]; /**< BSSID of the access point */
    uint8_t  sa[DOT11DECRYPT_MAC_LEN];    /**< Source MAC address */
    uint8_t  da[DOT11DECRYPT_MAC_LEN];    /**< Destination MAC address */
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

/**
 * @brief Retrieves the Key Encryption Key (KEK) for a given decryption key item.
 *
 * @param kek Pointer to a pointer that will receive the KEK data.
 * @return The length of the KEK in bytes, or 0 if an error occurred.
 */
int
Dot11DecryptGetKEK(const PDOT11DECRYPT_KEY_ITEM key, const uint8_t **kek);

int

/**
 * @brief Retrieves the TK (Temporal Key) from a given key item.
 *
 * This function extracts the TK from a DOT11DECRYPT_KEY_ITEM and returns its pointer along with its length.
 *
 * @param key Pointer to the DOT11DECRYPT_KEY_ITEM containing the key information.
 * @param tk Pointer to store the extracted TK.
 * @return Length of the TK in bytes, or 0 if an error occurred.
 */
Dot11DecryptGetTK(const PDOT11DECRYPT_KEY_ITEM key, const uint8_t **tk);

int

/**
 * @brief Retrieves the GTK (Group Temporal Key) from a given key item.
 *
 * This function extracts the Group Temporal Key (GTK) from the provided key item and stores it in the gtk pointer.
 *
 * @param key Pointer to the DOT11DECRYPT_KEY_ITEM containing the encryption keys.
 * @param gtk Pointer to store the retrieved GTK.
 * @return The length of the GTK if successful, 0 otherwise.
 */
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
