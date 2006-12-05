#ifndef	_AIRPDCAP_USER_H
#define	_AIRPDCAP_USER_H

/******************************************************************************/
/*	File includes																					*/
/*																										*/
#include "airpdcap_interop.h"
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
#define	AIRPDCAP_WPA_PSK_LEN					64
#define	AIRPDCAP_WPA_PMK_LEN					32
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
/*!
/brief
It represent a key item used during the decryption process.
*/
typedef struct _AIRPDCAP_KEY_ITEM {
	/*!
	/brief
	Type of key. The type will remain unchanged during the processing, even if some fields could be changed (e.g., WPA fields).

	/note
	You can use constants AIRPDCAP_KEY_TYPE_xxx to indicate the key type.
	*/
	UINT8 KeyType;

	/*!
	/brief
	Key data.
	This field can be used for the following decryptographic algorithms: WEP-40, with a key of 40 bits (10 hex-digits); WEP-104, with a key of 104 bits (or 26 hex-digits); WPA or WPA2.
	/note
	For WPA/WPA2, the PMK is calculated from the PSK, and the PSK is calculated from the passphrase-SSID pair. You can enter one of these 3 values and subsequent fields will be automatically calculated.
	/note
	For WPA and WPA2 this implementation will use standards as defined in 802.11i (2004) and 802.1X (2004).
	*/
	union AIRPDCAP_KEY_ITEMDATA {
		struct AIRPDCAP_KEY_ITEMDATA_WEP {
			/*!
			/brief
			The binary value of the WEP key.
			/note
			It is accepted a key of lenght between AIRPDCAP_WEP_KEY_MINLEN and AIRPDCAP_WEP_KEY_MAXLEN. A WEP key standard-compliante should be either 40 bits (10 hex-digits, 5 bytes) for WEP-40 or 104 bits (26 hex-digits, 13 bytes) for WEP-104.
			*/
			UCHAR WepKey[AIRPDCAP_WEP_KEY_MAXLEN];
			/*!
			/brief
			The length of the WEP key. Acceptable range is [AIRPDCAP_WEP_KEY_MINLEN;AIRPDCAP_WEP_KEY_MAXLEN].
			*/
			size_t WepKeyLen;
		} Wep;

		/*!
		/brief
		WPA/WPA2 key data. Note that the decryption process will use the PMK (equal to PSK), that is calculated from passphrase-SSID pair. You can define one of these three fields and necessary fields will be automatically calculated.
		*/
		union AIRPDCAP_KEY_ITEMDATA_WPA {
			struct AIRPDCAP_KEY_ITEMDATA_PWD {
				/*!
				/brief
				The string (null-terminated) value of the passphrase.
				*/
				CHAR Passphrase[AIRPDCAP_WPA_PASSPHRASE_MAX_LEN+1];
				/*!
				/brief
				The value of the SSID (up to AIRPDCAP_WPA_SSID_MAX_LEN octets).
				/note
				A zero-length SSID indicates broadcast.
				*/
				CHAR Ssid[AIRPDCAP_WPA_SSID_MAX_LEN];
				/*!
				/brief
				The length of the SSID
				*/
				size_t SsidLen;
			} UserPwd;

			UCHAR Psk[AIRPDCAP_WPA_PSK_LEN];

			UCHAR Pmk[AIRPDCAP_WPA_PMK_LEN];
		} Wpa;
	} KeyData;
} AIRPDCAP_KEY_ITEM, *PAIRPDCAP_KEY_ITEM;

/*!
/brief
Collection of keys to use to decrypt packets
*/
typedef struct _AIRPDCAP_KEYS_COLLECTION {
	/*!
	/brief
	Number of stored keys
	*/
	size_t nKeys;

	/*!
	/brief
	Array of nKeys keys
	*/
	AIRPDCAP_KEY_ITEM Keys[256];
} AIRPDCAP_KEYS_COLLECTION, *PAIRPDCAP_KEYS_COLLECTION;
/*																										*/
/******************************************************************************/

/******************************************************************************/
/*	Function prototype declarations															*/
/*																										*/
/*																										*/
/*																										*/
/******************************************************************************/

#endif