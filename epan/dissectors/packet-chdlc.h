/* packet-chdlc.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_CHDLC_H__
#define __PACKET_CHDLC_H__

/* Cisco HDLC packet types that aren't just Ethernet types */
#define CHDLCTYPE_FRARP		0x0808	/* Frame Relay ARP */
#define CHDLCTYPE_BPDU		0x4242	/* IEEE spanning tree protocol */
#define CHDLCTYPE_OSI 	        0xfefe  /* ISO network-layer protocols */

/*
 * See section 4.3.1 of RFC 1547, and
 *
 *	http://www.nethelp.no/net/cisco-hdlc.txt
 */

#define CHDLC_ADDR_UNICAST	0x0f
#define CHDLC_ADDR_MULTICAST	0x8f

extern const value_string chdlc_vals[];

void
chdlctype(dissector_handle_t sub_dissector, uint16_t chdlctype,
          tvbuff_t *tvb, int offset_after_chdlctype,
	  packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
	  int chdlctype_id);

#endif
