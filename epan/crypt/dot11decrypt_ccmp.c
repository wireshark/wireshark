/* dot11decrypt_ccmp.c
 *
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
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

#define FC0_AAD_MASK 0x8f
#define FC1_AAD_MASK 0xc7

/****************************************************************************/
/* Internal macros								*/

#define READ_6(b0, b1, b2, b3, b4, b5) \
	((((UINT64)((UINT16)((b4 << 0) | (b5 << 8)))) << 32) | \
	    ((UINT32)((b0 << 0) | (b1 << 8) | (b2 << 16) | (b3 << 24))))

/****************************************************************************/
/* Internal function prototypes declarations					*/

/****************************************************************************/
/* Function definitions							*/

/* From IEEE 802.11 2016 Chapter 12.5.3.3.3 Construct AAD */
static void ccmp_construct_aad(
	PDOT11DECRYPT_MAC_FRAME wh,
	guint8 *aad,
	size_t *aad_len)
{
	guint8 mgmt = (DOT11DECRYPT_TYPE(wh->fc[0]) == DOT11DECRYPT_TYPE_MANAGEMENT);
	int alen = 22;

	/* AAD:
	* FC with bits 4..6 and 11..13 masked to zero; 14 is always one
	* A1 | A2 | A3
	* SC with bits 4..15 (seq#) masked to zero
	* A4 (if present)
	* QC (if present)
	*/

	/* NB: aad[1] set below */
	if (!mgmt) {
		aad[0] = (UINT8)(wh->fc[0] & FC0_AAD_MASK);
	} else {
		aad[0] = wh->fc[0];
	}
	aad[1] = (UINT8)(wh->fc[1] & FC1_AAD_MASK);
	/* NB: we know 3 addresses are contiguous */
	memcpy(aad + 2, &wh->addr1[0], 3 * DOT11DECRYPT_MAC_LEN);
	aad[20] = (UINT8)(wh->seq[0] & DOT11DECRYPT_SEQ_FRAG_MASK);
	aad[21] = 0; /* all bits masked */

	/*
	* Construct variable-length portion of AAD based
	* on whether this is a 4-address frame/QOS frame.
	*/
	if (DOT11DECRYPT_IS_4ADDRESS(wh)) {
		alen += 6;
		DOT11DECRYPT_ADDR_COPY(aad + 22,
			((PDOT11DECRYPT_MAC_FRAME_ADDR4)wh)->addr4);
		if (DOT11DECRYPT_IS_QOS_DATA(wh)) {
			PDOT11DECRYPT_MAC_FRAME_ADDR4_QOS qwh4 =
				(PDOT11DECRYPT_MAC_FRAME_ADDR4_QOS) wh;
			aad[28] = (UINT8)(qwh4->qos[0] & 0x0f);/* just priority bits */
			aad[29] = 0;
			alen += 2;
		}
	} else {
		if (DOT11DECRYPT_IS_QOS_DATA(wh)) {
			PDOT11DECRYPT_MAC_FRAME_QOS qwh =
				(PDOT11DECRYPT_MAC_FRAME_QOS) wh;
			aad[22] = (UINT8)(qwh->qos[0] & 0x0f); /* just priority bits */
			aad[23] = 0;
			alen += 2;
		}
	}
	*aad_len = alen;
}

/* From IEEE 802.11 2016 Chapter 12.5.3.3.4 Construct CCM nonce */
/* Nonce: Flags | A2 | PN */
static void ccmp_construct_nonce(
	PDOT11DECRYPT_MAC_FRAME wh,
	guint64 pn,
	guint8 nonce[13])
{
	guint8 mgmt = (DOT11DECRYPT_TYPE(wh->fc[0]) == DOT11DECRYPT_TYPE_MANAGEMENT);

	if (DOT11DECRYPT_IS_4ADDRESS(wh) && DOT11DECRYPT_IS_QOS_DATA(wh)) {
		PDOT11DECRYPT_MAC_FRAME_ADDR4_QOS qwh4 =
			(PDOT11DECRYPT_MAC_FRAME_ADDR4_QOS) wh;
		nonce[0] = (UINT8)(qwh4->qos[0] & 0x0f);/* just priority bits */
	} else if (DOT11DECRYPT_IS_QOS_DATA(wh)) {
		PDOT11DECRYPT_MAC_FRAME_QOS qwh =
			(PDOT11DECRYPT_MAC_FRAME_QOS) wh;
			nonce[0] = (UINT8)(qwh->qos[0] & 0x0f); /* just priority bits */
	} else {
		nonce[0] = 0;
	}
	if (mgmt) {
		nonce[0] |= 0x10; /* set MGMT flag */
	}

	DOT11DECRYPT_ADDR_COPY(nonce + 1, wh->addr2);
	nonce[7] = (UINT8)(pn >> 40);
	nonce[8] = (UINT8)(pn >> 32);
	nonce[9] = (UINT8)(pn >> 24);
	nonce[10] = (UINT8)(pn >> 16);
	nonce[11] = (UINT8)(pn >> 8);
	nonce[12] = (UINT8)(pn >> 0);
}

int Dot11DecryptCcmpDecrypt(
	guint8 *m,
	int mac_header_len,
	int len,
	guint8 *TK1)
{
	PDOT11DECRYPT_MAC_FRAME wh;
	guint8 aad[30]; /* Max aad_len. See Table 12-1 IEEE 802.11 2016 */
	guint8 nonce[13];
	guint8 mic[8];
	ssize_t data_len;
	size_t aad_len;
	int z = mac_header_len;
	gcry_cipher_hd_t handle;
	guint64 pn;
	guint8 *ivp = m + z;

	wh = (PDOT11DECRYPT_MAC_FRAME )m;
	data_len = len - (z + DOT11DECRYPT_CCMP_HEADER + DOT11DECRYPT_CCMP_TRAILER);
	if (data_len < 1) {
		return 0;
	}

	memcpy(mic, m + len - DOT11DECRYPT_CCMP_TRAILER, DOT11DECRYPT_CCMP_TRAILER);
	pn = READ_6(ivp[0], ivp[1], ivp[4], ivp[5], ivp[6], ivp[7]);
	ccmp_construct_nonce(wh, pn, nonce);
	ccmp_construct_aad(wh, aad, &aad_len);

	if (gcry_cipher_open(&handle, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CCM, 0)) {
		return 1;
	}
	if (gcry_cipher_setkey(handle, TK1, 16)) {
		goto err_out;
	}
	if (gcry_cipher_setiv(handle, nonce, sizeof(nonce))) {
		goto err_out;
	}

	guint64 ccm_lengths[3];
	ccm_lengths[0] = data_len;
	ccm_lengths[1] = aad_len;
	ccm_lengths[2] = DOT11DECRYPT_CCMP_TRAILER;
	if (gcry_cipher_ctl(handle, GCRYCTL_SET_CCM_LENGTHS, ccm_lengths, sizeof(ccm_lengths))) {
		goto err_out;
	}
	if (gcry_cipher_authenticate(handle, aad, aad_len)) {
		goto err_out;
	}
	if (gcry_cipher_decrypt(handle, m + z + DOT11DECRYPT_CCMP_HEADER, data_len, NULL, 0)) {
		goto err_out;
	}
	if (gcry_cipher_checktag(handle, mic, DOT11DECRYPT_CCMP_TRAILER)) {
		goto err_out;
	}

	/* TODO replay check	(IEEE 802.11i-2004, pg. 62)			*/
	/* TODO PN must be incremental (IEEE 802.11i-2004, pg. 62)		*/

	gcry_cipher_close(handle);
	return 0;
err_out:
	gcry_cipher_close(handle);
	return 1;
}
