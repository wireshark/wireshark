/* packet-ntp.h
 * Definitions for packet disassembly structures and routines
 *
 * $Id: packet-ntp.h,v 1.5 2001/01/06 09:42:10 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 * Joerg Mayer <jmayer@telemation.de>
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* This is from yahoolib.h from gtkyahoo */

#ifndef PACKET_NTP_H
#define PACKET_NTP_H

#define NTP_LI_MASK	192
#define NTP_LI_NONE	0
#define NTP_LI_61	64
#define NTP_LI_59	128
#define NTP_LI_ALARM	192

#define NTP_VN_MASK	56
#define NTP_VN_R0	0
#define NTP_VN_R1	8
#define NTP_VN_R2	16
#define NTP_VN_3	24
#define NTP_VN_4	32
#define NTP_VN_R5	40
#define NTP_VN_R6	48
#define NTP_VN_R7	56

#define NTP_MODE_MASK   7
#define NTP_MODE_RSV	0
#define NTP_MODE_SYMACT	1
#define NTP_MODE_SYMPAS	2
#define NTP_MODE_CLIENT	3
#define NTP_MODE_SERVER	4
#define NTP_MODE_BCAST	5
#define NTP_MODE_CTRL	6
#define NTP_MODE_PRIV	7

/* NTP_BASETIME is infact epoch - ntp_start_time */
#define NTP_BASETIME 2208988800ul
#define NTP_TS_SIZE 100

#endif
