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

#include <glib.h>
#include <wsutil/wsgcrypt.h>

/****************************************************************************/
/*	Internal definitions							*/

/****************************************************************************/
/* Internal macros								*/

#define READ_6(b0, b1, b2, b3, b4, b5) \
	((((guint64)((guint16)((b4 << 0) | (b5 << 8)))) << 32) | \
	    ((guint32)((b0 << 0) | (b1 << 8) | (b2 << 16) | (b3 << 24))))

/****************************************************************************/
/* Internal function prototypes declarations					*/

/****************************************************************************/
/* Function definitions							*/

/* From IEEE 802.11 2016 Chapter 12.5.5.3.4 Construct GCM nonce */
static void
gcmp_construct_nonce(
	PDOT11DECRYPT_MAC_FRAME wh,
	guint64 pn,
	guint8 nonce[12])
{
	/* Nonce: A2 | PN */
	DOT11DECRYPT_ADDR_COPY(nonce, wh->addr2);
	nonce[6] = (guint8)(pn >> 40);
	nonce[7] = (guint8)(pn >> 32);
	nonce[8] = (guint8)(pn >> 24);
	nonce[9] = (guint8)(pn >> 16);
	nonce[10] = (guint8)(pn >> 8);
	nonce[11] = (guint8)(pn >> 0);
}

int Dot11DecryptGcmpDecrypt(
	guint8 *m,
	int mac_header_len,
	int len,
	guint8 *TK1,
	int tk_len)
{
	PDOT11DECRYPT_MAC_FRAME wh;
	guint8 aad[30];
	guint8 nonce[12];
	guint8 mic[16];
	ssize_t data_len;
	size_t aad_len;
	int z = mac_header_len;
	gcry_cipher_hd_t handle;
	guint64 pn;
	guint8 *ivp = m + z;

	wh = (PDOT11DECRYPT_MAC_FRAME )m;
	data_len = len - (z + DOT11DECRYPT_GCMP_HEADER + sizeof(mic));
	if (data_len < 1) {
		return 0;
	}

	memcpy(mic, m + len - sizeof(mic), sizeof(mic));
	pn = READ_6(ivp[0], ivp[1], ivp[4], ivp[5], ivp[6], ivp[7]);
	gcmp_construct_nonce(wh, pn, nonce);
	dot11decrypt_construct_aad(wh, aad, &aad_len);

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
	if (gcry_cipher_checktag(handle, mic, sizeof(mic))) {
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
