/* packet-jmirror.c
 * Routines for Jmirror protocol packet disassembly
 * By Wayne Brassem <wbrassem@juniper.net>
 * Copyright 2009 Wayne Brassem
 *           2012 Wayne Brassem - Correction to support IPv6 over PPP
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#define MIRROR_HDR_SZ           8
#define MIRROR_ID_SZ            4
#define SESSION_ID_SZ           4
#define DEF_JMIRROR_UDP_PORT    30030 /* a product of primes (1*2*3*5*7*11*13)  :-) */

/*
 * See www.juniper.net JUNOSe Packet Mirroring documentation
 */

/* Jmirror protocol variables */
static int proto_jmirror = -1;
static int hf_jmirror_mid = -1;
static int hf_jmirror_sid = -1;
static gint ett_jmirror = -1;

/* Handles which point to the packet dissectors */
static dissector_handle_t ipv4_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t hdlc_handle;

static guint global_jmirror_udp_port = DEF_JMIRROR_UDP_PORT;

/* Forward declaration */
void proto_reg_handoff_jmirror(void);

/* Routine to return the dissector handle based on heuristic packet inspection */
static dissector_handle_t
get_heuristic_handle(tvbuff_t *tvb)
{
	int offset = MIRROR_HDR_SZ;            /* Point past the 8 byte mirror header */
	int byte0, byte1, byte2, byte3;

	/* The following section is designed to determine the nature of the mirrored packet.
	 *
	 * The first four bytes will be inspected to deduce the type of traffic.
	 * The bit pattern shown below is the basis.  A bit of "x" is a variable field.
	 *
	 * IPv4 Header: 0100 0101 xxxx xx00                     ==> Pattern for standard IPv4 20-byte header
	 * IPv6 Header: 0110 xxxx xxxx 0000 0000 0000 0000 0000 ==> Pattern for standard IPv6 header with no flow label
	 * PPP/HDLC:    1111 1111 0000 0011 xx00 0000 0010 0001 ==> HDLC-like framing for PPP (FF 03 x0 21)
	 * PPP/HDLC:	1111 1111 0000 0011 0000 0000 0101 0111	==> HDLC-like framing for PPP IPv6 (FF 03 00 57)
	 */

	if (!tvb_bytes_exist(tvb, offset, 4))
		return NULL;   /* Not enough bytes for heuristic test */

	/* Filter for IPv4 and IPv6 packets */
	byte0 = tvb_get_guint8(tvb, offset + 0);
	byte1 = tvb_get_guint8(tvb, offset + 1);
	byte2 = tvb_get_guint8(tvb, offset + 2);
	byte3 = tvb_get_guint8(tvb, offset + 3);

	/* Look for IPv4 with standard header length */
	if ( byte0 == 0x45 && ipv4_handle )
		return ipv4_handle;

	/* Look for IPv6 with no flow label */
	else if ( hi_nibble(byte0) == 6 && lo_nibble(byte1) == 0 && byte2 == 0 && byte3 == 0 && ipv6_handle )
		return ipv6_handle;

	/* Look for PPP/HDLC for LCP and IPv4 */
	else if ( byte0 == 0xff && byte1 == 0x03 && lo_nibble(byte2) == 0 && byte3 == 0x21 && hdlc_handle )
		return hdlc_handle;

	/* Look for PPP/HDLC for IPv6 */
	else if ( byte0 == 0xff && byte1 == 0x03 && byte2 == 0 && byte3 == 0x57 && hdlc_handle )
		return hdlc_handle;

	/* If it's something else entirely return nothing */
	else
		return NULL;
}

/* Heuristic UDP dissector called by Wireshark looking for embedded IPv4, IPv6 or L2TP/HDLC Jmirror packets */
static int
dissect_jmirror(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	int offset = 0;
	dissector_handle_t dissector_handle;
	unsigned int midval, sidval;
	proto_item *ti = NULL;
	proto_tree *jmirror_tree = NULL;
	tvbuff_t *next_tvb = NULL;

	if ( !( dissector_handle = get_heuristic_handle(tvb) ) )
		return 0;

	/* Populate the Protocol field in the Wireshark packet display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Jmirror");

	/* Build the Jmirror Identifier value and store the string in a buffer */
	midval = tvb_get_ntohl(tvb, offset);

	/* Build the Session Identifier value and store the string in a buffer */
	sidval = tvb_get_ntohl(tvb, offset+MIRROR_ID_SZ);

	/* Populate the Info field in the Wireshark packet display */
	col_add_fstr(pinfo->cinfo, COL_INFO, "MID: 0X%08x (%d), SID: 0x%08x (%d)", midval, midval, sidval, sidval);

	/* Create a header for the Mirror Header in the protocol tree */
	ti = proto_tree_add_protocol_format(tree, proto_jmirror, tvb, offset, MIRROR_HDR_SZ,
		"Juniper Packet Mirror, MID: 0x%08x (%d), SID: 0x%08x (%d)", midval, midval, sidval, sidval);

	/* Add the Juniper Packet Mirror to the main protocol tree */
	jmirror_tree = proto_item_add_subtree(ti, ett_jmirror);

	/* Insert the Jmirror Identifier into the protocol tree and assign value to filter variable */
	proto_tree_add_item(jmirror_tree, hf_jmirror_mid, tvb, offset, MIRROR_ID_SZ, ENC_BIG_ENDIAN);

	/* Push the tvbuff_t offset pointer along to the Session Identifier */
	offset += MIRROR_ID_SZ;

	/* Insert the Session Identifier into the protocol tree and assign value to filter variable */
	proto_tree_add_item(jmirror_tree, hf_jmirror_sid, tvb, offset, SESSION_ID_SZ, ENC_BIG_ENDIAN);

	/* Push the tvbuff_t offset pointer along to the start of the mirrored packet */
	offset += SESSION_ID_SZ;

	/* Create a buffer pointer for the next dissector */
	next_tvb = tvb_new_subset(tvb, offset, -1, -1);

	/* Call the next dissector based on the heurstics and return the number of bytes dissected */
	return MIRROR_HDR_SZ + call_dissector(dissector_handle, next_tvb, pinfo, tree);

}

/* Register Jmirror dissector with Wireshark */
void
proto_register_jmirror(void)
{
	module_t	*jmirror_module = NULL;

	/* Used by the Expression dialog and filter box */
	static hf_register_info jmirror_hf[] = {
		{ &hf_jmirror_mid,
		  { "Jmirror Identifier", "jmirror.mid", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
		    "Unique identifier of the mirrored session", HFILL }
		},
		{ &hf_jmirror_sid,
		  { "Session Identifier", "jmirror.sid", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
		    "Unique identifier of the user session", HFILL }
		}
	};
	static gint *jmirror_ett[] = {
		&ett_jmirror
	};

	/* Register the Jmirror protocol with Wireshark */
	proto_jmirror = proto_register_protocol("Juniper Packet Mirror", "Jmirror", "jmirror");

	/* Register the Jmirror preferences with Wireshark */
	jmirror_module = prefs_register_protocol(proto_jmirror, proto_reg_handoff_jmirror);

	/* Allow the user to set the UDP port for the decode under the Edit -> Preferences menu */
	prefs_register_uint_preference(jmirror_module, "udp.port", "JMirror UDP Port",
		"Set the port for JMirror Port (if other than the default of 30030)",
		10, &global_jmirror_udp_port);

	/* Register the Jmirror subfields for filters */
	proto_register_field_array(proto_jmirror, jmirror_hf, array_length(jmirror_hf));
	proto_register_subtree_array(jmirror_ett, array_length(jmirror_ett));
}

/* Create attachment point for dissector in Wireshark */
void
proto_reg_handoff_jmirror(void)
{
	static int jmirror_inited = FALSE;
	static guint jmirror_udp_port;
	static dissector_handle_t jmirror_handle;

	if ( !jmirror_inited )
	{
		/* register as heuristic dissector for UDP */
		/* heur_dissector_add("udp", dissect_jmirror, proto_jmirror); */

		/* Create a dissector handle for the Jmirror protocol */
		jmirror_handle = new_create_dissector_handle(dissect_jmirror, proto_jmirror);

		/* Create pointer to ipv4, ipv6, ppp and data dissectors */
		ipv4_handle = find_dissector("ip");
		ipv6_handle = find_dissector("ipv6");
		hdlc_handle = find_dissector("pw_hdlc_nocw_hdlc_ppp");

		/* Set the init flag */
		jmirror_inited = TRUE;
	} else {
		/* Unregister from the old UDP port */
		dissector_delete_uint("udp.port", jmirror_udp_port, jmirror_handle);
	}

	jmirror_udp_port = global_jmirror_udp_port;

	/* Register as a normal IP dissector with default UDP port 30030 */
	dissector_add_uint("udp.port", jmirror_udp_port, jmirror_handle);
}
