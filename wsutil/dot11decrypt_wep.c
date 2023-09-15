/* dot11decrypt_wep.c
 *
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "config.h"

/************************************************************************/
/*	File includes							*/

#include "crc32.h"

/************************************************************************/
/* Note: copied from net80211/ieee80211_airpdcap_tkip.c			*/
#define S_SWAP(a,b) { uint8_t t = S[a]; S[a] = S[b]; S[b] = t; }

/* Note: copied from FreeBSD source code, RELENG 6,			*/
/*		sys/net80211/ieee80211_crypto_wep.c, 391		*/
int Dot11DecryptWepDecrypt(
	const unsigned char *seed,
	const size_t seed_len,
	unsigned char *cypher_text,
	const size_t data_len)
{
	uint32_t i, j, k, crc;
	uint8_t S[256];
	uint8_t icv[4];
	size_t buflen;

	/* Generate key stream (RC4 Pseudo-Random Number Generator) */
	for (i = 0; i < 256; i++)
		S[i] = (uint8_t)i;
	for (j = i = 0; i < 256; i++) {
		j = (j + S[i] + seed[i % seed_len]) & 0xff;
		S_SWAP(i, j);
	}

	/* Apply RC4 to data and compute CRC32 over decrypted data */
	crc = ~(uint32_t)0;
	buflen = data_len;

	for (i = j = k = 0; k < buflen; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		*cypher_text ^= S[(S[i] + S[j]) & 0xff];
		crc = crc32_ccitt_table_lookup((crc ^ *cypher_text) & 0xff) ^ (crc >> 8);
		cypher_text++;
	}

	crc = ~crc;

	/* Encrypt little-endian CRC32 and verify that it matches with the received ICV */
	icv[0] = (uint8_t)crc;
	icv[1] = (uint8_t)(crc >> 8);
	icv[2] = (uint8_t)(crc >> 16);
	icv[3] = (uint8_t)(crc >> 24);
	for (k = 0; k < 4; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		if ((icv[k] ^ S[(S[i] + S[j]) & 0xff]) != *cypher_text++) {
			/* ICV mismatch - drop frame */
			return 1/*DOT11DECRYPT_RET_UNSUCCESS*/;
		}
	}

	return 0/*DOT11DECRYPT_RET_SUCCESS*/;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
