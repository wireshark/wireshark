/* packet-wtp.h
 *
 * Declarations for disassembly of WTP component of WAP traffic.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * WAP dissector based on original work by Ben Fowler
 * Updated by Neil Hunter <neil.hunter@energis-squared.com>
 * WTLS support by Alexandre P. Ferreira (Splice IP)
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

#ifndef __PACKET_WTP_H__
#define __PACKET_WTP_H__

/* Implementation Status:
 *
 * All fixed headers decoded for non-concatenated PDUs.
 *
 * TODO:
 *	Support for concatenated PDUs
 *	Support for decoding TPIs in variable header
 */

/* WTP PDU Types
   See section 9.1 (p. 40) of spec-wtp-19990611.pdf
*/

enum {
	ERRONEOUS			= -0x01,
	NOT_ALLOWED			= 0x00,
	INVOKE				= 0x01,
	RESULT				= 0x02,
	ACK					= 0x03,
	ABORT				= 0x04,
	SEGMENTED_INVOKE	= 0x05,
	SEGMENTED_RESULT	= 0x06,
	NEGATIVE_ACK		= 0x07
};

enum {
	PROVIDER			= 0x00,
	USER				= 0x01
};

#endif /* packet-wtp.h */
