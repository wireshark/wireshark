/* packet-amr.h
 *
 * Adaptive Multi-Rate (AMR) speech codec 3GPP TS 26.101
 *
 * (C) 2024 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_AMR_H__
#define __PACKET_AMR_H__

#include "config.h"

#include <stddef.h>
#include <stdint.h>

#include "epan/packet.h"
#include "ws_symbol_export.h"

/* According to TS 26.101 Table A.1b: */
#define AMR_FT_0		0	/* 4.75 */
#define AMR_FT_1		1	/* 5.15 */
#define AMR_FT_2		2	/* 5.90 */
#define AMR_FT_3		3	/* 6.70 */
#define AMR_FT_4		4	/* 7.40 */
#define AMR_FT_5		5	/* 7.95 */
#define AMR_FT_6		6	/* 10.2 */
#define AMR_FT_7		7	/* 12.2 */
#define AMR_FT_SID		8	/* AMR SID */
#define AMR_FT_GSM_EFR_SID	9	/* GSM-EFR SID */
#define AMR_FT_TDMA_EFR_SID	10	/* TDMA-EFR SID */
#define AMR_FT_PDC_EFR_SID	11	/* PDC-EFR SID */
/* version 16.0.0 Release 16: 12-14 for future use */
#define AMR_FT_NO_DATA		15	/* NO_DATA */

struct amr_oa_hdr {
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
	/* Payload Header */
	uint8_t pad1:4,
		cmr:4;	/* Codec Mode Request */
	/* Table of Contents */
	uint8_t pad2:2,
		q:1,	/* OK (not damaged) at origin? */
		ft:4,	/* coding mode */
		f:1;	/* followed by another speech frame? */
#else
	uint8_t cmr:4, pad1:4;
	uint8_t f:1, ft:4, q:1, pad2:2;
#endif
	uint8_t data[0];
};

WS_DLL_PUBLIC
int amr_nb_bytes_to_ft(uint8_t bytes);

#endif /*__PACKET_AMR_H__*/
