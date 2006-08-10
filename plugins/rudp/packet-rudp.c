/* packet-rudp.c
 * Routines for Reliable UDP Protocol.
 * Copyright 2004, Duncan Sargeant <dunc-ethereal@rcpt.to>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-data.c, README.developer, and various other files.
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


 * Reliable UDP is a lightweight protocol for providing TCP-like flow
 * control over UDP.  Cisco published an PFC a long time ago, and
 * their actual implementation is slightly different, having no
 * checksum field.
 *
 * I've cheated here - RUDP could be used for anything, but I've only
 * seen it used to switched telephony calls, so we just call the Cisco SM
 * dissector from here.
 *
 * Here are some links:
 * 
 * http://www.watersprings.org/pub/id/draft-ietf-sigtran-reliable-udp-00.txt
 * http://www.javvin.com/protocolRUDP.html
 * http://www.cisco.com/univercd/cc/td/doc/product/access/sc/rel7/omts/omts_apb.htm#30052

 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>

/* Disable rudp by default. The previously hardcoded value of
 * 7000 (used by Cisco) collides with afs and as the draft states:
 * "RUDP doesn't place any restrictions on which UDP port numbers are used.  
 *  Valid port numbers are ports not defined in RFC 1700."
 */
/* FIXME: The proper solution would be to convert this dissector into
 *        heuristic dissector, but it isn't complete anyway.
 */
static guint udp_port = 0;

void proto_reg_handoff_rudp(void);

static int proto_rudp = -1;

static int hf_rudp_flags = -1;
static int hf_rudp_flags_syn = -1;
static int hf_rudp_flags_ack = -1;
static int hf_rudp_flags_eak = -1;
static int hf_rudp_flags_rst = -1;
static int hf_rudp_flags_nul = -1;
static int hf_rudp_flags_chk = -1;
static int hf_rudp_flags_tcs = -1;
static int hf_rudp_flags_0 = -1;
static int hf_rudp_hlen = -1;
static int hf_rudp_seq = -1;
static int hf_rudp_ack = -1;
/* static int hf_rudp_cksum = -1; */

static gint ett_rudp = -1;
static gint ett_rudp_flags = -1;


static void
dissect_rudp(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
	tvbuff_t * next_tvb = NULL;
	proto_tree *rudp_tree = NULL, *flags_tree;
	proto_item *ti = NULL;
	int flags[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	int i;
	guint8 hlen;

	flags[0] = hf_rudp_flags_syn;
	flags[1] = hf_rudp_flags_ack;
	flags[2] = hf_rudp_flags_eak;
	flags[3] = hf_rudp_flags_rst;
	flags[4] = hf_rudp_flags_nul;
	flags[5] = hf_rudp_flags_chk;
	flags[6] = hf_rudp_flags_tcs;
	flags[7] = hf_rudp_flags_0;

	hlen = tvb_get_guint8(tvb, 1);

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RUDP");
	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_rudp, tvb, 0, hlen, FALSE);
		rudp_tree = proto_item_add_subtree(ti, ett_rudp);

		ti = proto_tree_add_item(rudp_tree, hf_rudp_flags, tvb, 0, 1, FALSE);
		flags_tree = proto_item_add_subtree(ti, ett_rudp_flags);

		for (i = 0; i < 8; i++)
			proto_tree_add_item(flags_tree, flags[i], tvb, 0, 1, FALSE);

		proto_tree_add_item(rudp_tree, hf_rudp_hlen, tvb, 1, 1, FALSE);
		proto_tree_add_item(rudp_tree, hf_rudp_seq, tvb, 2, 1, FALSE);
		proto_tree_add_item(rudp_tree, hf_rudp_ack, tvb, 3, 1, FALSE);
	}

	next_tvb = tvb_new_subset(tvb, hlen, -1, -1);
	if (tvb_length(next_tvb) && find_dissector("sm"))
		call_dissector(find_dissector("sm"), next_tvb, pinfo, tree);
}

void
proto_register_rudp(void)
{

	static hf_register_info hf[] = {
		{ &hf_rudp_flags,
			{ "RUDP Header flags",           "rudp.flags",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_rudp_flags_syn,
			{ "Syn",           "rudp.flags.syn",
			FT_BOOLEAN, 8, NULL, 0x80,
			"", HFILL }
		},
		{ &hf_rudp_flags_ack,
			{ "Ack",           "rudp.flags.ack",
			FT_BOOLEAN, 8, NULL, 0x40,
			"", HFILL }
		},
		{ &hf_rudp_flags_eak,
			{ "Eak",           "rudp.flags.eak",
			FT_BOOLEAN, 8, NULL, 0x20,
			"Extended Ack", HFILL }
		},
		{ &hf_rudp_flags_rst,
			{ "RST",           "rudp.flags.rst",
			FT_BOOLEAN, 8, NULL, 0x10,
			"Reset flag", HFILL }
		},
		{ &hf_rudp_flags_nul,
			{ "NULL",           "rudp.flags.nul",
			FT_BOOLEAN, 8, NULL, 0x08,
			"Null flag", HFILL }
		},
		{ &hf_rudp_flags_chk,
			{ "CHK",           "rudp.flags.chk",
			FT_BOOLEAN, 8, NULL, 0x04,
			"Checksum is on header or body", HFILL }
		},
		{ &hf_rudp_flags_tcs,
			{ "TCS",           "rudp.flags.tcs",
			FT_BOOLEAN, 8, NULL, 0x02,
			"Transfer Connection System", HFILL }
		},
		{ &hf_rudp_flags_0,
			{ "0",           "rudp.flags.0",
			FT_BOOLEAN, 8, NULL, 0x01,
			"", HFILL }
		},
		{ &hf_rudp_hlen,
			{ "Header Length",           "rudp.hlen",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_rudp_seq,
			{ "Seq",           "rudp.seq",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Sequence Number", HFILL }
		},
		{ &hf_rudp_ack,
			{ "Ack",           "rudp.ack",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Acknowledgement Number", HFILL }
		},
		/*

		A checksum is specified in the RFC, but Cisco don't use one.

		{ &hf_rudp_cksum,
			{ "Checksum",           "rudp.cksum",
			FT_UINT16, 8, NULL, 0x0,
			"", HFILL }
		},
		*/
	};


/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_rudp,
		&ett_rudp_flags,
	};


	if (proto_rudp == -1) {
	    proto_rudp = proto_register_protocol (
		"Reliable UDP",		/* name */
		"RUDP",		/* short name */
		"rudp"		/* abbrev */
		);
	}

	proto_register_field_array(proto_rudp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	{
		module_t *rudp_module;
		rudp_module = prefs_register_protocol(proto_rudp, proto_reg_handoff_rudp);
		prefs_register_uint_preference(rudp_module,
			"udp.port",
			"UDP port for RUDP",
			"Set the UDP port for Reliable UDP traffic",
			10,
			&udp_port);
	}

}

void
proto_reg_handoff_rudp(void) {
	static dissector_handle_t rudp_handle = NULL;

	if (!rudp_handle) {
		rudp_handle = create_dissector_handle(dissect_rudp, proto_rudp);
	}

	dissector_add("udp.port", udp_port, rudp_handle);
}
