/* dot11decrypt_ccmp_compat.c
 *
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
 */

/*
 * This file is only used for backwards compatibility with libgcrypt
 * versions < 1.6.0 that don't support AEAD. When building towards later
 * versions dot11decrypt_ccmp.c file is used instead
 */

/*
 * Note: This file was derived from the FreeBSD source code, RELENG 6,
 *		sys/net80211/ieee80211_crypto_ccmp.c
 */

/****************************************************************************/
/* File includes								*/
#include "config.h"
#include "dot11decrypt_system.h"
#include "dot11decrypt_int.h"

#include "dot11decrypt_debug.h"
#include <glib.h>
#include <wsutil/wsgcrypt.h>

/****************************************************************************/
/*	Internal definitions							*/

#define AES_BLOCK_LEN 16

/****************************************************************************/
/* Internal macros								*/

#define XOR_BLOCK(b, a, len) {						\
	INT __i__;										\
	for (__i__ = 0; __i__ < (INT)(len); __i__++)	\
			(b)[__i__] ^= (a)[__i__];				\
}

#define CCMP_DECRYPT(_i, _b, _b0, _pos, _a, _len) {					\
	/* Decrypt, with counter */							\
	_b0[14] = (UINT8)((_i >> 8) & 0xff);						\
	_b0[15] = (UINT8)(_i & 0xff);							\
	gcry_cipher_encrypt(rijndael_handle, _b, AES_BLOCK_LEN, _b0, AES_BLOCK_LEN);	\
	XOR_BLOCK(_pos, _b, _len);							\
	/* Authentication */								\
	XOR_BLOCK(_a, _pos, _len);							\
	gcry_cipher_encrypt(rijndael_handle, _a, AES_BLOCK_LEN, NULL, 0);		\
}

#define READ_6(b0, b1, b2, b3, b4, b5) \
	((((UINT64)((UINT16)((b4 << 0) | (b5 << 8)))) << 32) | \
	    ((UINT32)((b0 << 0) | (b1 << 8) | (b2 << 16) | (b3 << 24))))

/****************************************************************************/
/* Internal function prototypes declarations					*/

static void ccmp_init_blocks(
	gcry_cipher_hd_t rijndael_handle,
	PDOT11DECRYPT_MAC_FRAME wh,
	UINT64 pn,
	size_t dlen,
	UINT8 b0[AES_BLOCK_LEN],
	UINT8 aad[2 * AES_BLOCK_LEN],
	UINT8 a[AES_BLOCK_LEN],
	UINT8 b[AES_BLOCK_LEN])
	;

/****************************************************************************/
/* Function definitions							*/

static void ccmp_init_blocks(
	gcry_cipher_hd_t rijndael_handle,
	PDOT11DECRYPT_MAC_FRAME wh,
	UINT64 pn,
	size_t dlen,
	UINT8 b0[AES_BLOCK_LEN],
	UINT8 aad[2 * AES_BLOCK_LEN],
	UINT8 a[AES_BLOCK_LEN],
	UINT8 b[AES_BLOCK_LEN])
{
	UINT8 mgmt = (DOT11DECRYPT_TYPE(wh->fc[0]) == DOT11DECRYPT_TYPE_MANAGEMENT);

	memset(aad, 0, 2*AES_BLOCK_LEN);

	/* CCM Initial Block:
	* Flag (Include authentication header, M=3 (8-octet MIC),
	*       L=1 (2-octet Dlen))
	* Nonce: 0x00 | A2 | PN
	* Dlen */
	b0[0] = 0x59;
	/* NB: b0[1] set below */
	DOT11DECRYPT_ADDR_COPY(b0 + 2, wh->addr2);
	b0[8] = (UINT8)(pn >> 40);
	b0[9] = (UINT8)(pn >> 32);
	b0[10] = (UINT8)(pn >> 24);
	b0[11] = (UINT8)(pn >> 16);
	b0[12] = (UINT8)(pn >> 8);
	b0[13] = (UINT8)(pn >> 0);
	b0[14] = (UINT8)((UINT8)(dlen >> 8) & 0xff);
	b0[15] = (UINT8)(dlen & 0xff);

	/* AAD:
	* FC with bits 4..6 and 11..13 masked to zero; 14 is always one
	* A1 | A2 | A3
	* SC with bits 4..15 (seq#) masked to zero
	* A4 (if present)
	* QC (if present)
	*/
	aad[0] = 0;     /* AAD length >> 8 */
	/* NB: aad[1] set below */
	if (!mgmt)
		aad[2] = (UINT8)(wh->fc[0] & 0x8f);    /* XXX magic #s */
	else
		aad[2] = wh->fc[0];
	aad[3] = (UINT8)(wh->fc[1] & 0xc7);    /* XXX magic #s */
	/* NB: we know 3 addresses are contiguous */
	memcpy(aad + 4, (guint8 *)wh->addr1, 3 * DOT11DECRYPT_MAC_LEN);
	aad[22] = (UINT8)(wh->seq[0] & DOT11DECRYPT_SEQ_FRAG_MASK);
	aad[23] = 0; /* all bits masked */
	/*
	* Construct variable-length portion of AAD based
	* on whether this is a 4-address frame/QOS frame.
	* We always zero-pad to 32 bytes before running it
	* through the cipher.
	*
	* We also fill in the priority bits of the CCM
	* initial block as we know whether or not we have
	* a QOS frame.
	*/
	if (DOT11DECRYPT_IS_4ADDRESS(wh)) {
		DOT11DECRYPT_ADDR_COPY(aad + 24,
			((PDOT11DECRYPT_MAC_FRAME_ADDR4)wh)->addr4);
		if (DOT11DECRYPT_IS_QOS_DATA(wh)) {
			PDOT11DECRYPT_MAC_FRAME_ADDR4_QOS qwh4 =
				(PDOT11DECRYPT_MAC_FRAME_ADDR4_QOS) wh;
			aad[30] = (UINT8)(qwh4->qos[0] & 0x0f);/* just priority bits */
			aad[31] = 0;
			b0[1] = aad[30];
			aad[1] = 22 + DOT11DECRYPT_MAC_LEN + 2;
		} else {
			memset(&aad[30], 0, 2);
			b0[1] = 0;
			aad[1] = 22 + DOT11DECRYPT_MAC_LEN;
		}
	} else {
		if (DOT11DECRYPT_IS_QOS_DATA(wh)) {
			PDOT11DECRYPT_MAC_FRAME_QOS qwh =
				(PDOT11DECRYPT_MAC_FRAME_QOS) wh;
			aad[24] = (UINT8)(qwh->qos[0] & 0x0f); /* just priority bits */
			aad[25] = 0;
			b0[1] = aad[24];
			aad[1] = 22 + 2;
		} else {
			memset(&aad[24], 0, 2);
			b0[1] = 0;
			aad[1] = 22;
		}
		if (mgmt)
			b0[1] |= 0x10; /* set MGMT flag */
		memset(&aad[26], 0, 4);
	}

	/* Start with the first block and AAD */
	gcry_cipher_encrypt(rijndael_handle, a, AES_BLOCK_LEN, b0, AES_BLOCK_LEN);
	XOR_BLOCK(a, aad, AES_BLOCK_LEN);
	gcry_cipher_encrypt(rijndael_handle, a, AES_BLOCK_LEN, NULL, 0);
	XOR_BLOCK(a, &aad[AES_BLOCK_LEN], AES_BLOCK_LEN);
	gcry_cipher_encrypt(rijndael_handle, a, AES_BLOCK_LEN, NULL, 0);
	b0[0] &= 0x07;
	b0[14] = b0[15] = 0;
	gcry_cipher_encrypt(rijndael_handle, b, AES_BLOCK_LEN, b0, AES_BLOCK_LEN);

	/** //XOR( m + len - 8, b, 8 ); **/
}

int Dot11DecryptCcmpDecrypt(
	guint8 *m,
	int mac_header_len,
	int len,
	guint8 *TK1,
	int tk_len,
	int mic_len)
{
	PDOT11DECRYPT_MAC_FRAME wh;
	UINT8 aad[2 * AES_BLOCK_LEN];
	UINT8 b0[AES_BLOCK_LEN], b[AES_BLOCK_LEN], a[AES_BLOCK_LEN];
	UINT8 mic[AES_BLOCK_LEN];
	ssize_t data_len;
	UINT i;
	UINT8 *pos;
	UINT space;
	INT z = mac_header_len;
	gcry_cipher_hd_t rijndael_handle;
	UINT64 PN;
	UINT8 *ivp=m+z;

	if (tk_len > 16 || mic_len > 8) {
		/* NOT SUPPORTED*/
		return 1;
	}

	PN = READ_6(ivp[0], ivp[1], ivp[4], ivp[5], ivp[6], ivp[7]);

	if (gcry_cipher_open(&rijndael_handle, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, 0)) {
		return 1;
	}
	if (gcry_cipher_setkey(rijndael_handle, TK1, 16)) {
		gcry_cipher_close(rijndael_handle);
		return 1;
	}

	wh = (PDOT11DECRYPT_MAC_FRAME )m;
	data_len = len - (z + DOT11DECRYPT_CCMP_HEADER+DOT11DECRYPT_CCMP_TRAILER);
	if (data_len < 1) {
		gcry_cipher_close(rijndael_handle);
		return 0;
	}
	ccmp_init_blocks(rijndael_handle, wh, PN, data_len, b0, aad, a, b);
	memcpy(mic, m+len-DOT11DECRYPT_CCMP_TRAILER, DOT11DECRYPT_CCMP_TRAILER);
	XOR_BLOCK(mic, b, DOT11DECRYPT_CCMP_TRAILER);

	i = 1;
	pos = (UINT8 *)m + z + DOT11DECRYPT_CCMP_HEADER;
	space = len - (z + DOT11DECRYPT_CCMP_HEADER);

	if (space > data_len)
		space = (UINT)data_len;
	while (space >= AES_BLOCK_LEN) {
		CCMP_DECRYPT(i, b, b0, pos, a, AES_BLOCK_LEN);
		pos += AES_BLOCK_LEN;
		space -= AES_BLOCK_LEN;
		i++;
	}

	if (space != 0)         /* short last block */
		CCMP_DECRYPT(i, b, b0, pos, a, space);

	gcry_cipher_close(rijndael_handle);
	/* MIC Key ?= MIC */
	if (memcmp(mic, a, DOT11DECRYPT_CCMP_TRAILER) == 0) {
		return 0;
	}

	/* TODO replay check	(IEEE 802.11i-2004, pg. 62)			*/
	/* TODO PN must be incremental (IEEE 802.11i-2004, pg. 62)		*/

	return 1;
}
