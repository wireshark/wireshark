/* packet-ntp.h
 * Definitions for packet disassembly structures and routines
 * Joerg Mayer <jmayer@loplof.de>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This is from yahoolib.h from gtkyahoo
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef PACKET_NTP_H
#define PACKET_NTP_H

/* NTP_BASETIME is infact epoch - ntp_start_time */
#define NTP_BASETIME 2208988800ul
#define NTP_TS_SIZE 100

extern char * ntp_fmt_ts(const guint8 *reftime);

#endif
