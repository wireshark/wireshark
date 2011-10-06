/* packet-ax4000.c
 * Routines for Spirent AX/4000 Test Block dissection
 * Copyright 2004, SEKINE Hideki <sekineh@gf7.so-net.ne.jp>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <ipproto.h>

/* Initialize the protocol and registered fields */
static int proto_ax4000 = -1;
static int hf_ax4000_port = -1;
static int hf_ax4000_chassis = -1;
static int hf_ax4000_fill = -1;
static int hf_ax4000_index = -1;
static int hf_ax4000_timestamp = -1;
static int hf_ax4000_seq = -1;
static int hf_ax4000_crc = -1;

/* Initialize the subtree pointers */
static gint ett_ax4000 = -1;

/* Code to actually dissect the packets */
static void
dissect_ax4000(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *ax4000_tree;
	
	guint8  ax_port;
	guint8  ax_chassis;
	guint16 ax_index;
	guint32 ax_seq;
	guint32 ax_timestamp;

	/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "AX4000");
	col_clear(pinfo->cinfo, COL_INFO);

	ax_port = tvb_get_guint8(tvb, 0);
	ax_chassis = tvb_get_guint8(tvb, 1);
	ax_index = tvb_get_ntohs(tvb, 2) & 0x0FFF;
	ax_timestamp = tvb_get_letohl(tvb, 6);
	ax_seq = tvb_get_letohl(tvb, 10);
	
	col_append_fstr(pinfo->cinfo, COL_INFO,
			"Chss:%u Prt:%u Idx:%u Seq:0x%08x TS:%.6f[msec]",
			ax_chassis, ax_port, ax_index, ax_seq, ax_timestamp*1e-5);
	
	if (tree) {
		/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_ax4000, tvb, 0, -1, FALSE);

		ax4000_tree = proto_item_add_subtree(ti, ett_ax4000);

		proto_tree_add_uint(ax4000_tree,
		    hf_ax4000_port, tvb, 0, 1, ax_port);
		proto_tree_add_uint(ax4000_tree,
		    hf_ax4000_chassis, tvb, 1, 1, ax_chassis);
		proto_tree_add_item(ax4000_tree,
		    hf_ax4000_fill, tvb, 2, 1, ENC_BIG_ENDIAN);
		proto_tree_add_uint(ax4000_tree,
		    hf_ax4000_index, tvb, 2, 2, ax_index);
		proto_tree_add_uint(ax4000_tree,
		    hf_ax4000_timestamp, tvb, 6, 4, ax_timestamp);
		proto_tree_add_uint(ax4000_tree,
		    hf_ax4000_seq, tvb, 10, 4, ax_seq);
		proto_tree_add_uint(ax4000_tree,
		    hf_ax4000_crc, tvb, 14, 2, tvb_get_letohs(tvb, 14));
	}

}

/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_ax4000(void)
{
	static hf_register_info hf[] = {
		{ &hf_ax4000_port,
			{ "Port Number", "ax4000.port",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ax4000_chassis,
			{ "Chassis Number", "ax4000.chassis",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ax4000_fill,
			{ "Fill Type", "ax4000.fill",
			FT_UINT8, BASE_DEC, NULL, 0xc0,
			NULL, HFILL }
		},
		{ &hf_ax4000_index,
			{ "Index", "ax4000.index",
			FT_UINT16, BASE_DEC, NULL, 0x0FFF,
			NULL, HFILL }
		},
		{ &hf_ax4000_timestamp,
			{ "Timestamp", "ax4000.timestamp",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ax4000_seq,
			{ "Sequence Number", "ax4000.seq",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ax4000_crc,
			{ "CRC (unchecked)", "ax4000.crc",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ax4000
	};

	/* Register the protocol name and description */
	proto_ax4000 = proto_register_protocol("AX/4000 Test Block",
	    "AX4000", "ax4000");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_ax4000, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

#define AX4000_TCP_PORT 3357 /* assigned by IANA */
#define AX4000_UDP_PORT 3357 /* assigned by IANA */

void
proto_reg_handoff_ax4000(void)
{
	dissector_handle_t ax4000_handle;

	ax4000_handle = create_dissector_handle(dissect_ax4000,
	    proto_ax4000);
	dissector_add_uint("ip.proto", IP_PROTO_AX4000, ax4000_handle);
	dissector_add_uint("tcp.port", AX4000_TCP_PORT, ax4000_handle);
	dissector_add_uint("udp.port", AX4000_UDP_PORT, ax4000_handle);
}
