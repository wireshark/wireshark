/* lapd_sapi.h
 * Declarations of LAPD SAPI values.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2004 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __LAPD_SAPI_H__
#define __LAPD_SAPI_H__

#define	LAPD_SAPI_Q931		0	/* Q.931 call control procedure */
#define	LAPD_SAPI_PM_Q931	1	/* Packet mode Q.931 call control procedure */
#define	LAPD_SAPI_X25		16	/* X.25 Level 3 procedures */
#define	LAPD_SAPI_L2		63	/* Layer 2 management procedures */

#define LAPD_GSM_SAPI_RA_SIG_PROC	0
#define LAPD_GSM_SAPI_NOT_USED_1	1
#define LAPD_GSM_SAPI_NOT_USED_16	16
#define LAPD_GSM_SAPI_OM_PROC		62

#endif /* lapd_sapi.h */
