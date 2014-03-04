/* lapd_sapi.h
 * Declarations of LAPD SAPI values.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2004 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
