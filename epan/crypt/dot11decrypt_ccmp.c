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

#include "dot11decrypt_debug.h"
#include "dot11decrypt_system.h"
#include "dot11decrypt_util.h"
#include "dot11decrypt_int.h"

#include <wsutil/wsgcrypt.h>

/****************************************************************************/
/*	Internal definitions							*/

/****************************************************************************/
/* Internal macros								*/

#define READ_6(b0, b1, b2, b3, b4, b5) \
	((((uint64_t)((uint16_t)((b4 << 0) | (b5 << 8)))) << 32) | \
	    ((uint32_t)((b0 << 0) | (b1 << 8) | (b2 << 16) | (b3 << 24))))

/****************************************************************************/
/* Internal function prototypes declarations					*/

/****************************************************************************/
/* Function definitions							*/

/* From IEEE 802.11 2016 Chapter 12.5.3.3.4 Construct CCM nonce */
/* Nonce: Flags | A2 | PN */
static void ccmp_construct_nonce(
	PDOT11DECRYPT_MAC_FRAME wh,
	uint64_t pn,
	uint8_t nonce[13])
{
	uint8_t mgmt = (DOT11DECRYPT_TYPE(wh->fc[0]) == DOT11DECRYPT_TYPE_MANAGEMENT);

	if (DOT11DECRYPT_IS_4ADDRESS(wh) && DOT11DECRYPT_IS_QOS_DATA(wh)) {
		PDOT11DECRYPT_MAC_FRAME_ADDR4_QOS qwh4 =
			(PDOT11DECRYPT_MAC_FRAME_ADDR4_QOS) wh;
		nonce[0] = (uint8_t)(qwh4->qos[0] & 0x0f);/* just priority bits */
	} else if (DOT11DECRYPT_IS_QOS_DATA(wh)) {
		PDOT11DECRYPT_MAC_FRAME_QOS qwh =
			(PDOT11DECRYPT_MAC_FRAME_QOS) wh;
			nonce[0] = (uint8_t)(qwh->qos[0] & 0x0f); /* just priority bits */
	} else {
		nonce[0] = 0;
	}
	if (mgmt) {
		nonce[0] |= 0x10; /* set MGMT flag */
	}

	DOT11DECRYPT_ADDR_COPY(nonce + 1, wh->addr2);
	nonce[7] = (uint8_t)(pn >> 40);
	nonce[8] = (uint8_t)(pn >> 32);
	nonce[9] = (uint8_t)(pn >> 24);
	nonce[10] = (uint8_t)(pn >> 16);
	nonce[11] = (uint8_t)(pn >> 8);
	nonce[12] = (uint8_t)(pn >> 0);
}

int Dot11DecryptCcmpDecrypt(
	uint8_t *m,
	int mac_header_len,
	int len,
	uint8_t *TK1,
	int tk_len,
	int mic_len)
{
	PDOT11DECRYPT_MAC_FRAME wh;
	uint8_t aad[30]; /* Max aad_len. See Table 12-1 IEEE 802.11 2016 */
	uint8_t nonce[13];
	uint8_t mic[16]; /* Big enough for CCMP-256 */
	ssize_t data_len;
	size_t aad_len;
	int z = mac_header_len;
	gcry_cipher_hd_t handle;
	uint64_t pn;
	uint8_t *ivp = m + z;

	wh = (PDOT11DECRYPT_MAC_FRAME )m;
	data_len = len - (z + DOT11DECRYPT_CCMP_HEADER + mic_len);
	if (data_len < 1) {
		return 0;
	}

	memcpy(mic, m + len - mic_len, mic_len);
	pn = READ_6(ivp[0], ivp[1], ivp[4], ivp[5], ivp[6], ivp[7]);
	ccmp_construct_nonce(wh, pn, nonce);
	dot11decrypt_construct_aad(wh, aad, &aad_len);

	if (gcry_cipher_open(&handle, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CCM, 0)) {
		return 1;
	}
	if (gcry_cipher_setkey(handle, TK1, tk_len)) {
		goto err_out;
	}
	if (gcry_cipher_setiv(handle, nonce, sizeof(nonce))) {
		goto err_out;
	}

	uint64_t ccm_lengths[3];
	ccm_lengths[0] = data_len;
	ccm_lengths[1] = aad_len;
	ccm_lengths[2] = mic_len;
	if (gcry_cipher_ctl(handle, GCRYCTL_SET_CCM_LENGTHS, ccm_lengths, sizeof(ccm_lengths))) {
		goto err_out;
	}
	if (gcry_cipher_authenticate(handle, aad, aad_len)) {
		goto err_out;
	}
	if (gcry_cipher_decrypt(handle, m + z + DOT11DECRYPT_CCMP_HEADER, data_len, NULL, 0)) {
		goto err_out;
	}
	if (gcry_cipher_checktag(handle, mic, mic_len)) {
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
