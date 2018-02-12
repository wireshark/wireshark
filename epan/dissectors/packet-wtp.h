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
 * SPDX-License-Identifier: GPL-2.0-or-later
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
