/* packet-wsp.h (c) 2000 Neil Hunter
 * Based on original work by Ben Fowler
 *
 * Declarations for disassembly of WSP component of WAP traffic.
 *
 * $Id: packet-wsp.h,v 1.1 2000/11/04 03:30:40 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
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
 *
 *
 */

#ifndef __PACKET_WSP_H__
#define __PACKET_WSP_H__

/* Implementation Status:
 *
 * Most PDUs decoded.
 * Some headers decoded.
 *
 * TODO:
 *	Capability encoding
 *	Remaining headers (perhaps a place holder for those yet to be implemented)
 *	Decoding of WMLC content
 *	Remaining PDUs
 */

/* Reason codes also used in WTP dissector as we assume WSP is the user */
static const value_string vals_wsp_reason_codes[] = {
	{ 0xE0, "Protocol Error (Illegal PDU)" },
	{ 0xE1, "Session disconnected" },
	{ 0xE2, "Session suspended" },
	{ 0xE3, "Session resumed" },
	{ 0xE4, "Peer congested" },
	{ 0xE5, "Session connect failed" },
	{ 0xE6, "Maximum receive unit size exceeded" },
	{ 0xE7, "Maximum outstanding requests exceeded" },
	{ 0xE8, "Peer request" },
	{ 0xE9, "Network error" },
	{ 0xEA, "User request" },
	{ 0xEB, "No specific cause, no retries" },
	{ 0xEC, "Push message cannot be delivered" },
	{ 0xED, "Push message discarded" },
	{ 0xEE, "Content type cannot be processed" },
};

void
dissect_wsp(tvbuff_t *, packet_info *, proto_tree *);

#endif /* packet-wsp.h */
