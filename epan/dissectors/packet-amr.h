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

/* 1B Payload Header + 1B ToC: */
#define AMR_NB_OA_HDR_LEN 2


#endif /*__PACKET_AMR_H__*/
