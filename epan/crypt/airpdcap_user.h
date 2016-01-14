/* airpdcap_user.h
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

#ifndef	_AIRPDCAP_USER_H
#define	_AIRPDCAP_USER_H

/******************************************************************************/
/*	File includes																					*/
/*																										*/
#include "airpdcap_interop.h"
#include "ws_symbol_export.h"

/*																										*/
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	Constant definitions																			*/
/*																										*/
/*	Decryption key types																			*/
#define	AIRPDCAP_KEY_TYPE_WEP		0
#define	AIRPDCAP_KEY_TYPE_WEP_40	1
#define	AIRPDCAP_KEY_TYPE_WEP_104	2
#define	AIRPDCAP_KEY_TYPE_WPA_PWD	3
#define	AIRPDCAP_KEY_TYPE_WPA_PSK	4
#define	AIRPDCAP_KEY_TYPE_WPA_PMK	5
#define	AIRPDCAP_KEY_TYPE_TKIP		6
#define	AIRPDCAP_KEY_TYPE_CCMP		7

/*	Decryption algorithms fields size definition (bytes)								*/
#define	AIRPDCAP_WEP_KEY_MINLEN		1
#define	AIRPDCAP_WEP_KEY_MAXLEN		32
#define	AIRPDCAP_WEP_40_KEY_LEN		5
#define	AIRPDCAP_WEP_104_KEY_LEN	13

#define	AIRPDCAP_WPA_PASSPHRASE_MIN_LEN	8
#define	AIRPDCAP_WPA_PASSPHRASE_MAX_LEN	63	/* null-terminated string, the actual length of the storage is 64	*/
#define	AIRPDCAP_WPA_SSID_MIN_LEN			0
#define	AIRPDCAP_WPA_SSID_MAX_LEN			32
#define	AIRPDCAP_WPA_PSK_LEN				32
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
    GString    *key;
    GByteArray *ssid;
    guint       bits;
    guint       type;
} decryption_key_t;

/**
 * Key item used during the decryption process.
 */
typedef struct _AIRPDCAP_KEY_ITEM {
	/**
	 * Type of key. The type will remain unchanged during the
	 * processing, even if some fields could be changed (e.g., WPA
	 * fields).
	 * @note
	 * You can use constants AIRPDCAP_KEY_TYPE_xxx to indicate the
	 * key type.
	 */
	UINT8 KeyType;

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
	union AIRPDCAP_KEY_ITEMDATA {
		struct AIRPDCAP_KEY_ITEMDATA_WEP {
			/**
			 * The binary value of the WEP key.
			 * @note
			 * It is accepted a key of length between
			 * AIRPDCAP_WEP_KEY_MINLEN and
			 * AIRPDCAP_WEP_KEY_MAXLEN. A WEP key
			 * standard-compliante should be either 40 bits
			 * (10 hex-digits, 5 bytes) for WEP-40 or 104 bits
			 * (26 hex-digits, 13 bytes) for WEP-104.
			 */
			UCHAR WepKey[AIRPDCAP_WEP_KEY_MAXLEN];
			/**
			 * The length of the WEP key. Acceptable range
			 * is [AIRPDCAP_WEP_KEY_MINLEN;AIRPDCAP_WEP_KEY_MAXLEN].
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
		struct AIRPDCAP_KEY_ITEMDATA_WPA {
			UCHAR Psk[AIRPDCAP_WPA_PSK_LEN];
			UCHAR Ptk[AIRPDCAP_WPA_PTK_LEN];
		} Wpa;
	} KeyData;

        struct AIRPDCAP_KEY_ITEMDATA_PWD {
                /**
                 * The string (null-terminated) value of
                 * the passphrase.
                 */
                CHAR Passphrase[AIRPDCAP_WPA_PASSPHRASE_MAX_LEN+1];
                /**
                 * The value of the SSID (up to
                 * AIRPDCAP_WPA_SSID_MAX_LEN octets).
                 * @note
                 * A zero-length SSID indicates broadcast.
                 */
                CHAR Ssid[AIRPDCAP_WPA_SSID_MAX_LEN];
                /**
                 *The length of the SSID
                 */
                size_t SsidLen;
        } UserPwd;
} AIRPDCAP_KEY_ITEM, *PAIRPDCAP_KEY_ITEM;

/**
 * Collection of keys to use to decrypt packets
 */
typedef struct _AIRPDCAP_KEYS_COLLECTION {
	/**
	 * Number of stored keys
	 */
	size_t nKeys;

	/**
	 * Array of nKeys keys
	 */
	AIRPDCAP_KEY_ITEM Keys[256];
} AIRPDCAP_KEYS_COLLECTION, *PAIRPDCAP_KEYS_COLLECTION;
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
 * - AIRPDCAP_KEY_TYPE_WEP (40/64-bit and 104/128-bit WEP)
 * - AIRPDCAP_KEY_TYPE_WPA_PWD (WPA + plaintext password + "wildcard" SSID or
 * WPA + plaintext password + specific SSID)
 * - AIRPDCAP_KEY_TYPE_WPA_PSK (WPA + 256-bit raw key)
 * @return A pointer to a freshly-g_malloc()ed decryption_key_t struct on
 *   success, or NULL on failure.
 * @see get_key_string(), free_key_string()
 */
WS_DLL_PUBLIC
decryption_key_t*
parse_key_string(gchar* key_string, guint8 key_type);

/**
 * Returns a newly allocated string representing the given decryption_key_t
 * struct.
 * @param dk [IN] Pointer to the key to be converted
 * @return A g_malloc()ed string representation of the key
 * @see parse_key_string()
 */
WS_DLL_PUBLIC
gchar*
get_key_string(decryption_key_t* dk);

/**
 * Releases memory associated with a given decryption_key_t struct.
 * @param dk [IN] Pointer to the key to be freed
 * @see parse_key_string()
 */
WS_DLL_PUBLIC
void
free_key_string(decryption_key_t *dk);

/******************************************************************************/

#endif /* _AIRPDCAP_USER_H */
