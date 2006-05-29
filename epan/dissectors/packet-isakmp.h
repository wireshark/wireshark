/* packet-isakmp.h
 * Declarations of routines for the Internet Security Association and Key
 * Management Protocol (ISAKMP) (RFC 2408) and the Internet IP Security
 * Domain of Interpretation for ISAKMP (RFC 2407)
 * Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
 *
 * Added routines for the Internet Key Exchange (IKEv2) Protocol
 * (draft-ietf-ipsec-ikev2-17.txt)
 * Shoichi Sakane <sakane@tanu.org>
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
 */

#ifndef __PACKET_ISAKMP_H__
#define __PACKET_ISAKMP_H__

void
isakmp_dissect_payloads(tvbuff_t *tvb, proto_tree *tree, int isakmp_verison,
			guint8 initial_payload, int offset, int length,
			packet_info *pinfo);

#endif
