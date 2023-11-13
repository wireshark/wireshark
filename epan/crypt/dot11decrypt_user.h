/** @file
 *
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
 */

#ifndef	_DOT11DECRYPT_USER_H
#define	_DOT11DECRYPT_USER_H

/******************************************************************************/
/*	File includes																					*/
/*																										*/
#include <glib.h>

#include "ws_symbol_export.h"

/*																										*/
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	Constant definitions																			*/
/*																										*/
/*	Decryption key types																			*/
#define	DOT11DECRYPT_KEY_TYPE_WEP		0
#define	DOT11DECRYPT_KEY_TYPE_WEP_40	1
#define	DOT11DECRYPT_KEY_TYPE_WEP_104	2
#define	DOT11DECRYPT_KEY_TYPE_WPA_PWD	3
#define	DOT11DECRYPT_KEY_TYPE_WPA_PSK	4
#define	DOT11DECRYPT_KEY_TYPE_WPA_PMK	5
#define	DOT11DECRYPT_KEY_TYPE_TK		6
#define DOT11DECRYPT_KEY_TYPE_MSK		7

#define	DOT11DECRYPT_KEY_TYPE_TKIP		100
#define	DOT11DECRYPT_KEY_TYPE_CCMP		101
#define	DOT11DECRYPT_KEY_TYPE_CCMP_256	102
#define	DOT11DECRYPT_KEY_TYPE_GCMP		103
#define	DOT11DECRYPT_KEY_TYPE_GCMP_256	104
#define	DOT11DECRYPT_KEY_TYPE_UNKNOWN   -1

/*	Decryption algorithms fields size definition (bytes)								*/
#define	DOT11DECRYPT_WEP_KEY_MINLEN		1
#define	DOT11DECRYPT_WEP_KEY_MAXLEN		32
#define	DOT11DECRYPT_WEP_40_KEY_LEN		5
#define	DOT11DECRYPT_WEP_104_KEY_LEN	13

#define	DOT11DECRYPT_WPA_PASSPHRASE_MIN_LEN	8
#define	DOT11DECRYPT_WPA_PASSPHRASE_MAX_LEN	63	/* null-terminated string, the actual length of the storage is 64	*/
#define	DOT11DECRYPT_WPA_SSID_MIN_LEN			0
#define	DOT11DECRYPT_WPA_SSID_MAX_LEN			32
#define	DOT11DECRYPT_WPA_PMK_MAX_LEN				48
#define	DOT11DECRYPT_WPA_PWD_PSK_LEN				32
#define	DOT11DECRYPT_TK_MAX_LEN					32
#define DOT11DECRYPT_MSK_MIN_LEN				64
#define DOT11DECRYPT_MSK_MAX_LEN				128
/*																										*/
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	Macro definitions																				*/
/*																										*/
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	Type definitions																				*/
/*																										*/
/**
 * Struct to store info about a specific decryption key.
 */
typedef struct {
    GByteArray *key;
    GByteArray *ssid;
    unsigned    bits;
    unsigned    type;
} decryption_key_t;

/**
 * Key item used during the decryption process.
 */
typedef struct _DOT11DECRYPT_KEY_ITEM {
	/**
	 * Type of key. The type will remain unchanged during the
	 * processing, even if some fields could be changed (e.g., WPA
	 * fields).
	 * @note
	 * You can use constants DOT11DECRYPT_KEY_TYPE_xxx to indicate the
	 * key type.
	 */
	uint8_t KeyType;

	/**
	 * Key data.
	 * This field can be used for the following decryptographic
	 * algorithms: WEP-40, with a key of 40 bits (10 hex-digits);
	 * WEP-104, with a key of 104 bits (or 26 hex-digits); WPA or
	 * WPA2.
	 * @note
	 * For WPA/WPA2, the PMK is calculated from the PSK, and the PSK
	 * is calculated from the passphrase-SSID pair. You can enter one
	 * of these 3 values and subsequent fields will be automatically
	 * calculated.
	 * @note
	 * For WPA and WPA2 this implementation will use standards as
	 * defined in 802.11i (2004) and 802.1X (2004).
	 */
	union DOT11DECRYPT_KEY_ITEMDATA {
		struct DOT11DECRYPT_KEY_ITEMDATA_WEP {
			/**
			 * The binary value of the WEP key.
			 * @note
			 * It is accepted a key of length between
			 * DOT11DECRYPT_WEP_KEY_MINLEN and
			 * DOT11DECRYPT_WEP_KEY_MAXLEN. A WEP key
			 * standard-compliante should be either 40 bits
			 * (10 hex-digits, 5 bytes) for WEP-40 or 104 bits
			 * (26 hex-digits, 13 bytes) for WEP-104.
			 */
			unsigned char WepKey[DOT11DECRYPT_WEP_KEY_MAXLEN];
			/**
			 * The length of the WEP key. Acceptable range
			 * is [DOT11DECRYPT_WEP_KEY_MINLEN;DOT11DECRYPT_WEP_KEY_MAXLEN].
			 */
			size_t WepKeyLen;
		} Wep;

		/**
		 * WPA/WPA2 key data. Note that the decryption process
		 * will use the PMK (equal to PSK), that is calculated
		 * from passphrase-SSID pair. You can define one of these
		 * three fields and necessary fields will be automatically
		 * calculated.
		 */
		struct DOT11DECRYPT_KEY_ITEMDATA_WPA {
			unsigned char Psk[DOT11DECRYPT_WPA_PMK_MAX_LEN];
			unsigned char Ptk[DOT11DECRYPT_WPA_PTK_MAX_LEN];
			uint8_t PskLen;
			uint8_t PtkLen;
			uint8_t Akm;
			uint8_t Cipher;
		} Wpa;

	} KeyData;

	struct DOT11DECRYPT_KEY_ITEMDATA_TK {
		uint8_t Tk[DOT11DECRYPT_TK_MAX_LEN];
		uint8_t Len;
	} Tk;

	struct DOT11DECRYPT_KEY_ITEMDATA_MSK {
		uint8_t Msk[DOT11DECRYPT_MSK_MAX_LEN];
		uint8_t Len;
	} Msk;

        struct DOT11DECRYPT_KEY_ITEMDATA_PWD {
                /**
                 * The octet string value of the passphrase.
                 * (The passphrase is technically an opaque octet string, even
                 * if recommended to be ASCII printable. It could (unlikely)
                 * even include internal NULs, which a Wireshark user could
                 * enter into the UAT percent-encoded.)
                 */
                char Passphrase[DOT11DECRYPT_WPA_PASSPHRASE_MAX_LEN];
                /**
                 *The length of the passphrase
                 */
                size_t PassphraseLen;
                /**
                 * The value of the SSID (up to
                 * DOT11DECRYPT_WPA_SSID_MAX_LEN octets).
                 * @note
                 * A zero-length SSID indicates broadcast.
                 */
                char Ssid[DOT11DECRYPT_WPA_SSID_MAX_LEN];
                /**
                 *The length of the SSID
                 */
                size_t SsidLen;
        } UserPwd;
} DOT11DECRYPT_KEY_ITEM, *PDOT11DECRYPT_KEY_ITEM;

/**
 * Collection of keys to use to decrypt packets
 */
typedef struct _DOT11DECRYPT_KEYS_COLLECTION {
	/**
	 * Number of stored keys
	 */
	size_t nKeys;

	/**
	 * Array of nKeys keys
	 */
	DOT11DECRYPT_KEY_ITEM Keys[256];
} DOT11DECRYPT_KEYS_COLLECTION, *PDOT11DECRYPT_KEYS_COLLECTION;
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	Function prototype declarations															*/

/**
 * Returns the decryption_key_t struct given a string describing the key.
 * @param key_string [IN] Key string in one of the following formats:
 * - 0102030405 (40/64-bit WEP)
 * - 01:02:03:04:05 (40/64-bit WEP)
 * - 0102030405060708090a0b0c0d (104/128-bit WEP)
 * - 01:02:03:04:05:06:07:08:09:0a:0b:0c:0d (104/128-bit WEP)
 * - MyPassword (WPA + plaintext password + "wildcard" SSID)
 * - MyPassword:MySSID (WPA + plaintext password + specific SSID)
 * - 01020304... (WPA + 256-bit raw key)
 * @param key_type [IN] Type of key used for string. Possibilities include:
 * - DOT11DECRYPT_KEY_TYPE_WEP (40/64-bit and 104/128-bit WEP)
 * - DOT11DECRYPT_KEY_TYPE_WPA_PWD (WPA + plaintext password + "wildcard" SSID or
 * WPA + plaintext password + specific SSID)
 * - DOT11DECRYPT_KEY_TYPE_WPA_PSK (WPA + 256-bit raw key)
 * @param error [OUT] If not NULL, on failure will be set to point to an
 *   error message explaining why parsing failed. Must be freed.
 * @return A pointer to a freshly-g_malloc()ed decryption_key_t struct on
 *   success, or NULL on failure.
 * @see free_key_string()
 */
WS_DLL_PUBLIC
decryption_key_t*
parse_key_string(char* key_string, uint8_t key_type, char **error);

/**
 * Releases memory associated with a given decryption_key_t struct.
 * @param dk [IN] Pointer to the key to be freed
 * @see parse_key_string()
 */
WS_DLL_PUBLIC
void
free_key_string(decryption_key_t *dk);

/******************************************************************************/

#endif /* _DOT11DECRYPT_USER_H */
