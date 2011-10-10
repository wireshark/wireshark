/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-tetra.h                                                             */
/* ../../tools/asn2wrs.py -u -p tetra -c ./tetra.cnf -s ./packet-tetra-template -D . -O ../../epan/dissectors tetra.asn */

/* Input file: packet-tetra-template.h */

#line 1 "../../asn1/tetra/packet-tetra-template.h"
/* packet-tetra.h
 * Routines for TETRA packet dissection
 *
 * Copyright (c) 2007 - 2011 Professional Mobile Communication Research Group,
 *    Beijing Institute of Technology, China
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * REF: ETSI EN 300 392-2 V3.2.1
 */

#ifndef PACKET_TETRA_H
#define PACKET_TETRA_H

enum {
	TETRA_CHAN_AACH		= 1,
	TETRA_CHAN_SCH_F	= 2,
	TETRA_CHAN_SCH_D	= 3,
	TETRA_CHAN_BSCH		= 5,
	TETRA_CHAN_BNCH		= 6,
	TETRA_CHAN_TCH_F	= 7,
	TETRA_CHAN_TCH_H	= 8,
	TETRA_CHAN_TCH_2_4	= 9,
	TETRA_CHAN_TCH_4_8	= 10,
	TETRA_CHAN_STCH		= 11,
	TETRA_CHAN_SCH_HU	= 15
};

enum {
	TETRA_UPLINK,
	TETRA_DOWNLINK
};

void tetra_dissect_pdu(int channel_type, int dir, tvbuff_t *pdu, proto_tree *head, packet_info *pinfo);

#endif  /* PACKET_TETRA_H */
