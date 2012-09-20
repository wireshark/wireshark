/* packet-ayiya.c
 * Anything in Anything protocol
 * Copyright 2008, Jelmer Vernooij <jelmer@samba.org>
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
 *
 * ref: http://unfix.org/~jeroen/archive/drafts/draft-massar-v6ops-ayiya-02.html#anchor4
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/strutil.h>

static dissector_table_t ip_dissector_table;

static int proto_ayiya = -1;
static int hf_id_len = -1;
static int hf_id_type = -1;
static int hf_sig_len = -1;
static int hf_hash_method = -1;
static int hf_auth_method = -1;
static int hf_opcode = -1;
static int hf_next_header = -1;
static int hf_epoch = -1;
static int hf_identity = -1;
static int hf_signature = -1;

static gint ett_ayiya = -1;

static const value_string identity_types[] = {
	{ 0x0, "None" },
	{ 0x1, "Integer" },
	{ 0x2, "ASCII string" },
	{ 0, NULL }
};

static const value_string hash_methods[] = {
	{ 0x0, "No hash" },
	{ 0x1, "MD5" },
	{ 0x2, "SHA1" },
	{ 0, NULL }
};

static const value_string auth_methods[] = {
	{ 0x0, "No authentication" },
	{ 0x1, "Hash using a Shared Secret" },
	{ 0x2, "Hash using a public/private key method" },
	{ 0, NULL }
};

#define OPCODE_FORWARD 1

static const value_string opcodes[] = {
	{ 0x0, "No Operation / Heartbeat" },
	{ 0x1, "Forward" },
	{ 0x2, "Echo Request" },
	{ 0x3, "Echo Request and Forward" },
	{ 0x4, "Echo Response" },
	{ 0x5, "MOTD" },
	{ 0x6, "Query Request" },
	{ 0x7, "Query Response" },
	{ 0, NULL }
};

#define UDP_PORT_AYIYA			5072

static void
dissect_ayiya(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *ayiya_tree;
	int offset = 0;
	int idlen, siglen, ayiya_len;
	guint8 next_header, opcode;
	tvbuff_t *payload;

	idlen = 1 << tvb_get_bits8(tvb, 0, 4);
	siglen = tvb_get_bits8(tvb, 8, 4) * 4;
	opcode = tvb_get_bits8(tvb, 20, 4);
	next_header = tvb_get_guint8(tvb, 3);

	ayiya_len = 8+idlen+siglen;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "AYIYA");

	if (tree) {
		proto_item *ti;
		nstime_t tv;
		ti = proto_tree_add_protocol_format( tree, proto_ayiya, tvb,
											 offset, ayiya_len, "AYIYA" );
		ayiya_tree = proto_item_add_subtree(ti, ett_ayiya);

		proto_tree_add_bits_item(ayiya_tree, hf_id_len, tvb, 0, 4, ENC_BIG_ENDIAN);
		proto_tree_add_bits_item(ayiya_tree, hf_id_type, tvb, 4, 4, ENC_BIG_ENDIAN);
		proto_tree_add_bits_item(ayiya_tree, hf_sig_len, tvb, 8, 4, ENC_BIG_ENDIAN);
		proto_tree_add_bits_item(ayiya_tree, hf_hash_method, tvb, 12, 4, ENC_BIG_ENDIAN);
		proto_tree_add_bits_item(ayiya_tree, hf_auth_method, tvb, 16, 4, ENC_BIG_ENDIAN);
		proto_tree_add_bits_item(ayiya_tree, hf_opcode, tvb, 20, 4, ENC_BIG_ENDIAN);
		proto_tree_add_uint_format(ayiya_tree, hf_next_header, tvb,
								   3, 1, next_header,
								   "Next header: %s (0x%02x)",
								   ipprotostr(next_header), next_header);
		tv.secs = tvb_get_ntohl(tvb, 4);
		tv.nsecs = 0;
		proto_tree_add_time(ayiya_tree, hf_epoch, tvb, 4, 4, &tv);
		proto_tree_add_item(ayiya_tree, hf_identity, tvb, 8, idlen, ENC_NA);
		proto_tree_add_item(ayiya_tree, hf_signature, tvb, 8+idlen, siglen, ENC_NA);
	}
	offset = ayiya_len;
	switch (opcode) {
	case OPCODE_FORWARD:
		payload = tvb_new_subset_remaining(tvb, offset);
		dissector_try_uint(ip_dissector_table, next_header, payload, pinfo, tree);
		break;
	}
}

void
proto_register_ayiya(void)
{
	static hf_register_info hf[] = {
		{ &hf_id_len,
		  { "Identity field length", "ayiya.idlen", FT_UINT8,
		    BASE_HEX, NULL, 0x0, NULL, HFILL
		  }
		},
		{ &hf_id_type,
		  { "Identity field type", "ayiya.idtype", FT_UINT8,
		    BASE_HEX, VALS(identity_types), 0x0, NULL, HFILL
		  }
		},
		{ &hf_sig_len,
		  { "Signature Length", "ayiya.siglen", FT_UINT8,
		    BASE_HEX, NULL, 0x0, NULL, HFILL
		  }
		},
		{ &hf_hash_method,
		  { "Hash method", "ayiya.hashmethod", FT_UINT8,
		    BASE_HEX, VALS(hash_methods), 0x0, NULL, HFILL
		  }
		},
		{ &hf_auth_method,
		  { "Authentication method", "ayiya.authmethod", FT_UINT8,
		    BASE_HEX, VALS(auth_methods), 0x0, NULL, HFILL
		  }
		},
		{ &hf_opcode,
		  { "Operation Code", "ayiya.opcode", FT_UINT8,
		    BASE_HEX, VALS(opcodes), 0x0, NULL, HFILL
		  }
		},
		{ &hf_next_header,
		  { "Next Header", "ayiya.nextheader", FT_UINT8,
		    BASE_HEX, NULL, 0x0, NULL, HFILL
		  }
		},
		{ &hf_epoch,
		  { "Epoch", "ayiya.epoch", FT_ABSOLUTE_TIME,
		    ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL
		  }
		},
		{ &hf_identity,
		  { "Identity", "ayiya.identity", FT_BYTES,
		    BASE_NONE, NULL, 0x0, NULL, HFILL
		  }
		},
		{ &hf_signature,
		  { "Signature", "ayiya.signature", FT_BYTES,
		    BASE_NONE, NULL, 0x0, NULL, HFILL
		  }
		},
	};
	static gint *ett[] = {
		&ett_ayiya,
	};

	proto_ayiya = proto_register_protocol("Anything in Anything Protocol",
					      "AYIYA", "ayiya");
	register_dissector("ayiya", dissect_ayiya, proto_ayiya);
	proto_register_field_array(proto_ayiya, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ayiya(void)
{
	dissector_handle_t ayiya_handle;

	ayiya_handle = find_dissector("ayiya");
	dissector_add_uint("udp.port", UDP_PORT_AYIYA, ayiya_handle);

	ip_dissector_table = find_dissector_table("ip.proto");
}
