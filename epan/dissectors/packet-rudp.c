/* packet-rudp.c
 * Routines for Reliable UDP Protocol.
 * Copyright 2004, Duncan Sargeant <dunc-ethereal@rcpt.to>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


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

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>


void proto_register_rudp(void);

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
static int hf_rudp_cksum = -1;

static gint ett_rudp = -1;
static gint ett_rudp_flags = -1;

static dissector_handle_t sm_handle = NULL;

static int
dissect_rudp(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree, void* data _U_)
{
	tvbuff_t * next_tvb;
	proto_tree *rudp_tree;
	proto_item *ti;
	guint8 hlen;
	static const int * flags[] = {
		&hf_rudp_flags_syn,
		&hf_rudp_flags_ack,
		&hf_rudp_flags_eak,
		&hf_rudp_flags_rst,
		&hf_rudp_flags_nul,
		&hf_rudp_flags_chk,
		&hf_rudp_flags_tcs,
		&hf_rudp_flags_0,
		NULL
	};

	hlen = tvb_get_guint8(tvb, 1);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RUDP");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_rudp, tvb, 0, hlen, ENC_NA);
	rudp_tree = proto_item_add_subtree(ti, ett_rudp);

	proto_tree_add_bitmask(rudp_tree, tvb, 0, hf_rudp_flags, ett_rudp_flags, flags, ENC_BIG_ENDIAN);

	proto_tree_add_item(rudp_tree, hf_rudp_hlen, tvb, 1, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(rudp_tree, hf_rudp_seq, tvb, 2, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(rudp_tree, hf_rudp_ack, tvb, 3, 1, ENC_BIG_ENDIAN);

	/* If the header is more than 4 bytes the next 2 bytes are the checksum */
	if (hlen > 4) {
		proto_tree_add_checksum(rudp_tree, tvb, 4, hf_rudp_cksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
	}

	/* If we have even more bytes their meaning is unknown - we have seen this
		* in live captures */
	if (hlen > 6) {
		next_tvb = tvb_new_subset_length(tvb, 6, hlen-6);
		call_data_dissector(next_tvb, pinfo, rudp_tree);
	}

	next_tvb = tvb_new_subset_remaining(tvb, hlen);
	if (tvb_captured_length(next_tvb) && sm_handle)
		call_dissector(sm_handle, next_tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}

void
proto_register_rudp(void)
{

	static hf_register_info hf[] = {
		{ &hf_rudp_flags,
			{ "RUDP Header flags",           "rudp.flags",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_rudp_flags_syn,
			{ "Syn",           "rudp.flags.syn",
			FT_BOOLEAN, 8, NULL, 0x80,
			NULL, HFILL }
		},
		{ &hf_rudp_flags_ack,
			{ "Ack",           "rudp.flags.ack",
			FT_BOOLEAN, 8, NULL, 0x40,
			NULL, HFILL }
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
			NULL, HFILL }
		},
		{ &hf_rudp_hlen,
			{ "Header Length",           "rudp.hlen",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
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
		{ &hf_rudp_cksum,
			{ "Checksum",           "rudp.cksum",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
	};


/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_rudp,
		&ett_rudp_flags,
	};


	proto_rudp = proto_register_protocol (
		"Reliable UDP",		/* name */
		"RUDP",		/* short name */
		"rudp"		/* abbrev */
		);

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

	static gboolean initialized = FALSE;
	static dissector_handle_t rudp_handle;
	static guint saved_udp_port;

	if (!initialized) {
		rudp_handle = create_dissector_handle(dissect_rudp, proto_rudp);
		dissector_add_for_decode_as("udp.port", rudp_handle);
		sm_handle = find_dissector_add_dependency("sm", proto_rudp);
		initialized = TRUE;
	} else {
		if (saved_udp_port != 0) {
			dissector_delete_uint("udp.port", saved_udp_port, rudp_handle);
		}
	}

	if (udp_port != 0) {
		dissector_add_uint("udp.port", udp_port, rudp_handle);
	}
	saved_udp_port = udp_port;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
