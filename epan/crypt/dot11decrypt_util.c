/* dot11decrypt_util.c
 *
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * Copyright (c) 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
 */

/****************************************************************************/
/* File includes								*/
#include "config.h"
#include "dot11decrypt_int.h"

#include "dot11decrypt_debug.h"
#include "dot11decrypt_util.h"
#include <glib.h>

/****************************************************************************/
/*	Internal definitions							*/

#define FC0_AAD_MASK 0x8f
#define FC1_AAD_MASK 0xc7

/****************************************************************************/
/* Internal macros								*/

/****************************************************************************/
/* Internal function prototypes declarations					*/

/****************************************************************************/
/* Function definitions							*/

/* From IEEE 802.11 2016 Chapter 12.5.3.3.3 and 12.5.5.3.3 Construct AAD */
void dot11decrypt_construct_aad(
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
	memcpy(aad + 2, (guint8 *)wh->addr1, 3 * DOT11DECRYPT_MAC_LEN);
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
