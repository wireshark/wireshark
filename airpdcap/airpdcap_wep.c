/******************************************************************************/
/*	File includes																					*/
/*																										*/
#include "airpdcap_system.h"
#include "airpdcap_int.h"

#include "airpdcap_wep.h"

#include "airpdcap_debug.h"
/*																										*/
/******************************************************************************/

extern const UINT32 crc32_table[256];

/* Note: copied from FreeBSD source code, RELENG 6,									*/
/*		sys/net80211/ieee80211_crypto_wep.c, 391											*/
INT AirPDcapWepDecrypt(
	const UCHAR *seed,
	const size_t seed_len,
	UCHAR *cypher_text,
	const size_t data_len)
{
	UINT32 i, j, k, crc;
	UINT8 S[256];
	UINT8 icv[4];
	size_t buflen;

	/* Generate key stream (RC4 Pseude-Random Number Generator) */
	for (i = 0; i < 256; i++)
		S[i] = (UINT8)i;
	for (j = i = 0; i < 256; i++) {
		j = (j + S[i] + seed[i % seed_len]) & 0xff;
		S_SWAP(i, j);
	}

	/* Apply RC4 to data and compute CRC32 over decrypted data */
	crc = ~(UINT32)0;
	buflen = data_len;

	for (i = j = k = 0; k < buflen; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		*cypher_text ^= S[(S[i] + S[j]) & 0xff];
		crc = crc32_table[(crc ^ *cypher_text) & 0xff] ^ (crc >> 8);
		cypher_text++;
	}

	crc = ~crc;

	/* Encrypt little-endian CRC32 and verify that it matches with the received ICV */
	icv[0] = (UINT8)crc;
	icv[1] = (UINT8)(crc >> 8);
	icv[2] = (UINT8)(crc >> 16);
	icv[3] = (UINT8)(crc >> 24);
	for (k = 0; k < 4; k++) {
		i = (i + 1) & 0xff;
		j = (j + S[i]) & 0xff;
		S_SWAP(i, j);
		if ((icv[k] ^ S[(S[i] + S[j]) & 0xff]) != *cypher_text++) {
			/* ICV mismatch - drop frame */
			return AIRPDCAP_RET_UNSUCCESS;
		}
	}

	return AIRPDCAP_RET_SUCCESS;
}
