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
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ISAKMP_H__
#define __PACKET_ISAKMP_H__

void
isakmp_dissect_payloads(tvbuff_t *tvb, proto_tree *tree, int isakmp_verison,
			guint8 initial_payload, int offset, int length,
			packet_info *pinfo);

#endif
