/* rtp_pt.h
 * Defines RTP payload types
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#ifndef __RTP_PT_H__
#define __RTP_PT_H__

#include <epan/value_string.h>
#include "ws_symbol_export.h"

/*
 * RTP Payload types
 * Table B.2 / H.225.0
 * Also RFC 3551, and
 *
 *	http://www.iana.org/assignments/rtp-parameters
 */
#define PT_PCMU			0	/* RFC 3551 */
#define PT_1016			1	/* RFC 1890 (reserved in RFC 3551) */
#define PT_G721			2	/* RFC 1890 (reserved in RFC 3551) */
#define PT_GSM			3	/* RFC 3551 */
#define PT_G723			4	/* From Vineet Kumar of Intel; see the Web page */
#define PT_DVI4_8000	5	/* RFC 3551 */
#define PT_DVI4_16000	6	/* RFC 3551 */
#define PT_LPC			7	/* RFC 3551 */
#define PT_PCMA			8	/* RFC 3551 */
#define PT_G722			9	/* RFC 3551 */
#define PT_L16_STEREO	10	/* RFC 3551 */
#define PT_L16_MONO		11	/* RFC 3551 */
#define PT_QCELP		12	/* Qualcomm Code Excited Linear Predictive coding? */
#define PT_CN			13	/* RFC 3389 */
#define PT_MPA			14	/* RFC 3551, RFC 2250 */
#define PT_G728			15	/* RFC 3551 */
#define PT_DVI4_11025	16	/* from Joseph Di Pol of Sun; see the Web page */
#define PT_DVI4_22050	17	/* from Joseph Di Pol of Sun; see the Web page */
#define PT_G729			18
#define PT_CN_OLD		19	/* Payload type reserved (old version Comfort Noise) */
#define PT_CELB			25	/* RFC 2029 */
#define PT_JPEG			26	/* RFC 2435 */
#define PT_NV			28	/* RFC 1890 */
#define PT_H261			31	/* RFC 2032 */
#define PT_MPV			32	/* RFC 2250 */
#define PT_MP2T			33	/* RFC 2250 */
#define PT_H263			34	/* from Chunrong Zhu of Intel; see the Web page */

/* Added to by Alex Lindberg to cover port ranges 96-127 - Dynamic RTP
   Some of these ports are used by Avaya for Modem and FAX support */

#define PT_UNDF_96		96  /* RFC 3551 */
#define PT_UNDF_97		97
#define PT_UNDF_98		98
#define PT_UNDF_99		99
#define PT_UNDF_100		100
#define PT_UNDF_101		101
#define PT_UNDF_102		102
#define PT_UNDF_103		103
#define PT_UNDF_104		104
#define PT_UNDF_105		105
#define PT_UNDF_106		106
#define PT_UNDF_107		107
#define PT_UNDF_108		108
#define PT_UNDF_109		109
#define PT_UNDF_110		110
#define PT_UNDF_111		111
#define PT_UNDF_112		112
#define PT_UNDF_113		113
#define PT_UNDF_114		114
#define PT_UNDF_115		115
#define PT_UNDF_116		116
#define PT_UNDF_117		117
#define PT_UNDF_118		118
#define PT_UNDF_119		119
#define PT_UNDF_120		120
#define PT_UNDF_121		121
#define PT_UNDF_122		122
#define PT_UNDF_123		123
#define PT_UNDF_124		124
#define PT_UNDF_125		125
#define PT_UNDF_126		126
#define PT_UNDF_127		127

WS_DLL_PUBLIC value_string_ext rtp_payload_type_vals_ext;
WS_DLL_PUBLIC value_string_ext rtp_payload_type_short_vals_ext;

#endif
