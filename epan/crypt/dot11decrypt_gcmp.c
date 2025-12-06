/* dot11decrypt_gcmp.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/****************************************************************************/
/* File includes								*/
#include "config.h"

#include "dot11decrypt_debug.h"
#include "dot11decrypt_int.h"
#include "dot11decrypt_system.h"
#include "dot11decrypt_util.h"

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

/* From IEEE 802.11 2016 Chapter 12.5.5.3.4 Construct GCM nonce */
static void
gcmp_construct_nonce(
	const uint8_t *A2,
	uint64_t pn,
	uint8_t nonce[12])
{
	/* Nonce: A2 | PN */
	DOT11DECRYPT_ADDR_COPY(nonce, A2);
	nonce[6] = (uint8_t)(pn >> 40);
	nonce[7] = (uint8_t)(pn >> 32);
	nonce[8] = (uint8_t)(pn >> 24);
	nonce[9] = (uint8_t)(pn >> 16);
	nonce[10] = (uint8_t)(pn >> 8);
	nonce[11] = (uint8_t)(pn >> 0);
}

int Dot11DecryptGcmpDecrypt(
	uint8_t *m,
	int mac_header_len,
	int len,
	uint8_t *TK1,
	int tk_len,
	const uint8_t *ap_mld_mac,
	const uint8_t *sta_mld_mac)
{
	PDOT11DECRYPT_MAC_FRAME wh;
	uint8_t aad[30];
	uint8_t nonce[12];
	ssize_t data_len;
	size_t aad_len;
	int z = mac_header_len;
	gcry_cipher_hd_t handle;
	uint64_t pn;
	uint8_t *ivp = m + z;
	const uint8_t *A1, *A2, *A3;

	wh = (PDOT11DECRYPT_MAC_FRAME )m;
	data_len = len - (z + DOT11DECRYPT_GCMP_HEADER + DOT11DECRYPT_GCMP_TRAILER);
	if (data_len < 1) {
		return -1;
	}

	dot11decrypt_get_nonce_aad_addrs(wh, ap_mld_mac, sta_mld_mac, &A1, &A2, &A3);
	pn = READ_6(ivp[0], ivp[1], ivp[4], ivp[5], ivp[6], ivp[7]);
	gcmp_construct_nonce(A2, pn, nonce);
	dot11decrypt_construct_aad(wh, A1, A2, A3, aad, &aad_len);

	if (gcry_cipher_open(&handle, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM, 0)) {
		return 1;
	}
	if (gcry_cipher_setkey(handle, TK1, tk_len)) {
		goto err_out;
	}
	if (gcry_cipher_setiv(handle, nonce, sizeof(nonce))) {
		goto err_out;
	}
	if (gcry_cipher_authenticate(handle, aad, aad_len)) {
		goto err_out;
	}
	if (gcry_cipher_decrypt(handle, m + z + DOT11DECRYPT_GCMP_HEADER, data_len, NULL, 0)) {
		goto err_out;
	}
	if (gcry_cipher_checktag(handle, m + len - DOT11DECRYPT_GCMP_TRAILER, DOT11DECRYPT_GCMP_TRAILER)) {
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
