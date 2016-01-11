/* airpdcap_ccmp.c
 *
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
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
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Note: This file was derived from the FreeBSD source code, RELENG 6,
 *		sys/net80211/ieee80211_crypto_ccmp.c
 */

/****************************************************************************/
/* File includes								*/

#include "airpdcap_system.h"
#include "airpdcap_int.h"

#include "airpdcap_rijndael.h"

#include "airpdcap_debug.h"
#include <glib.h>
#include <wsutil/aes.h>

/****************************************************************************/
/*	Internal definitions							*/

#define AES_BLOCK_LEN 16

/* Note: copied from net80211/ieee80211.h					*/
#define AIRPDCAP_FC1_DIR_MASK                  0x03
#define AIRPDCAP_FC1_DIR_DSTODS                0x03    /* AP ->AP  */
#define AIRPDCAP_FC0_SUBTYPE_QOS               0x80
#define AIRPDCAP_FC0_TYPE_DATA                 0x08
#define AIRPDCAP_FC0_TYPE_MASK                 0x0c
#define AIRPDCAP_SEQ_FRAG_MASK                 0x000f
#define AIRPDCAP_QOS_HAS_SEQ(wh) \
	(((wh)->fc[0] & \
	(AIRPDCAP_FC0_TYPE_MASK | AIRPDCAP_FC0_SUBTYPE_QOS)) == \
	(AIRPDCAP_FC0_TYPE_DATA | AIRPDCAP_FC0_SUBTYPE_QOS))

/****************************************************************************/
/* Internal macros								*/

#define CCMP_DECRYPT(_i, _b, _b0, _pos, _a, _len) {		\
	/* Decrypt, with counter */                             \
	_b0[14] = (UINT8)((_i >> 8) & 0xff);                    \
	_b0[15] = (UINT8)(_i & 0xff);                           \
	rijndael_encrypt(&key, _b0, _b);		        \
	XOR_BLOCK(_pos, _b, _len);				\
	/* Authentication */					\
	XOR_BLOCK(_a, _pos, _len);				\
	rijndael_encrypt(&key, _a, _a);				\
}

#define READ_6(b0, b1, b2, b3, b4, b5) \
	((((UINT64)((UINT16)((b4 << 0) | (b5 << 8)))) << 32) | \
	    ((UINT32)((b0 << 0) | (b1 << 8) | (b2 << 16) | (b3 << 24))))

#define AIRPDCAP_ADDR_COPY(dst,src)    memcpy(dst,src,AIRPDCAP_MAC_LEN)

/****************************************************************************/
/* Internal function prototypes declarations					*/

static void ccmp_init_blocks(
	rijndael_ctx *ctx,
        PAIRPDCAP_MAC_FRAME wh,
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
	rijndael_ctx *ctx,
        PAIRPDCAP_MAC_FRAME wh,
	UINT64 pn,
	size_t dlen,
	UINT8 b0[AES_BLOCK_LEN],
	UINT8 aad[2 * AES_BLOCK_LEN],
	UINT8 a[AES_BLOCK_LEN],
	UINT8 b[AES_BLOCK_LEN])
{
	UINT8 mgmt = (AIRPDCAP_TYPE(wh->fc[0]) == AIRPDCAP_TYPE_MANAGEMENT);
#define IS_4ADDRESS(wh) \
	((wh->fc[1] & AIRPDCAP_FC1_DIR_MASK) == AIRPDCAP_FC1_DIR_DSTODS)
#define IS_QOS_DATA(wh) AIRPDCAP_QOS_HAS_SEQ(wh)

	memset(aad, 0, 2*AES_BLOCK_LEN);

	/* CCM Initial Block:
	* Flag (Include authentication header, M=3 (8-octet MIC),
	*       L=1 (2-octet Dlen))
	* Nonce: 0x00 | A2 | PN
	* Dlen */
	b0[0] = 0x59;
	/* NB: b0[1] set below */
	AIRPDCAP_ADDR_COPY(b0 + 2, wh->addr2);
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
	memcpy(aad + 4, &wh->addr1[0], 3 * AIRPDCAP_MAC_LEN);
	aad[22] = (UINT8)(wh->seq[0] & AIRPDCAP_SEQ_FRAG_MASK);
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
	if (IS_4ADDRESS(wh)) {
		AIRPDCAP_ADDR_COPY(aad + 24,
			((PAIRPDCAP_MAC_FRAME_ADDR4)wh)->addr4);
		if (IS_QOS_DATA(wh)) {
			PAIRPDCAP_MAC_FRAME_ADDR4_QOS qwh4 =
				(PAIRPDCAP_MAC_FRAME_ADDR4_QOS) wh;
			aad[30] = (UINT8)(qwh4->qos[0] & 0x0f);/* just priority bits */
			aad[31] = 0;
			b0[1] = aad[30];
			aad[1] = 22 + AIRPDCAP_MAC_LEN + 2;
		} else {
			memset(&aad[30], 0, 2);
			b0[1] = 0;
			aad[1] = 22 + AIRPDCAP_MAC_LEN;
		}
	} else {
		if (IS_QOS_DATA(wh)) {
			PAIRPDCAP_MAC_FRAME_QOS qwh =
				(PAIRPDCAP_MAC_FRAME_QOS) wh;
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
	rijndael_encrypt(ctx, b0, a);
	XOR_BLOCK(a, aad, AES_BLOCK_LEN);
	rijndael_encrypt(ctx, a, a);
	XOR_BLOCK(a, &aad[AES_BLOCK_LEN], AES_BLOCK_LEN);
	rijndael_encrypt(ctx, a, a);
	b0[0] &= 0x07;
	b0[14] = b0[15] = 0;
	rijndael_encrypt(ctx, b0, b);

	/** //XOR( m + len - 8, b, 8 ); **/
#undef  IS_QOS_DATA
#undef  IS_4ADDRESS
}

INT AirPDcapCcmpDecrypt(
	UINT8 *m,
        gint mac_header_len,
	INT len,
	UCHAR TK1[16])
{
	PAIRPDCAP_MAC_FRAME wh;
	UINT8 aad[2 * AES_BLOCK_LEN];
	UINT8 b0[AES_BLOCK_LEN], b[AES_BLOCK_LEN], a[AES_BLOCK_LEN];
	UINT8 mic[AES_BLOCK_LEN];
	size_t data_len;
	UINT i;
	UINT8 *pos;
	UINT space;
	INT z = mac_header_len;
	rijndael_ctx key;
	UINT64 PN;
	UINT8 *ivp=m+z;

	PN = READ_6(ivp[0], ivp[1], ivp[4], ivp[5], ivp[6], ivp[7]);

	/* freebsd	*/
	rijndael_set_key(&key, TK1, 128);
	wh = (PAIRPDCAP_MAC_FRAME )m;
	data_len = len - (z + AIRPDCAP_CCMP_HEADER+AIRPDCAP_CCMP_TRAILER);
	if (data_len < 1)
	    return 0;
	ccmp_init_blocks(&key, wh, PN, data_len, b0, aad, a, b);
	memcpy(mic, m+len-AIRPDCAP_CCMP_TRAILER, AIRPDCAP_CCMP_TRAILER);
	XOR_BLOCK(mic, b, AIRPDCAP_CCMP_TRAILER);

	i = 1;
	pos = (UINT8 *)m + z + AIRPDCAP_CCMP_HEADER;
	space = len - (z + AIRPDCAP_CCMP_HEADER);

	if (space > data_len)
		space = (UINT)data_len;
	while (space >= AES_BLOCK_LEN) {
		CCMP_DECRYPT(i, b, b0, pos, a, AES_BLOCK_LEN);
		pos += AES_BLOCK_LEN, space -= AES_BLOCK_LEN;
		i++;
	}

	if (space != 0)         /* short last block */
		CCMP_DECRYPT(i, b, b0, pos, a, space);

	/*	MIC Key ?= MIC																				*/
	if (memcmp(mic, a, AIRPDCAP_CCMP_TRAILER) == 0) {
		return 0;
	}

	/* TODO replay check	(IEEE 802.11i-2004, pg. 62)			*/
	/* TODO PN must be incremental (IEEE 802.11i-2004, pg. 62)		*/

	return 1;
}
