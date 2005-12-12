/* packet-3com-njack.c
 * Routines for the disassembly of the 3com NetworkJack management protocol
 *
 * $Id$
 *
 * Copyright 2005 Joerg Mayer (see AUTHORS file)
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

/*
  TODO:
  - Find out lots more values :-)
  - Create common code for set and get response tlv decoding
  - Support for other 3com devices that use the same protocol
  - Do any devices use TCP or different ports?
  - Sanity checks for tlv_length depending on tlv_type

Specs:
	No specs available. All knowledge gained by looking at traffic dumps
	Packets to Managementstation: PORT_NJACK1
	Packets to Switch: PORT_NJACK2

	Type 0x07 (set):      M -> S, Magic, type, length (16 bit be)
	Type 0x08 (set resp): S -> M, Magic, type, net length (8 bit), result status
	Type 0x0b (get):      M -> S, Magic, type, 00 00 63 ff
	Type 0x0c (get resp): S -> M, Magic, type, T(8 bit) L(8 bit) V(L bytes)
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

/* protocol handles */
static int proto_njack = -1;

/* ett handles */
static int ett_njack = -1;
static int ett_njack_getresp_tlv_header = -1;
static int ett_njack_set_tlv_header = -1;

/* hf elements */
static int hf_njack_magic = -1;
static int hf_njack_type = -1;
/* type 07: set */
static int hf_njack_set_length = -1;
static int hf_njack_set_unknown1 = -1;
static int hf_njack_set_seqno = -1;
static int hf_njack_set_unknown2 = -1;
static int hf_njack_set_data = -1;
static int hf_njack_set_tlv_type = -1;
static int hf_njack_set_tlv_length = -1;
static int hf_njack_set_tlv_data = -1;
static int hf_njack_set_tlv_typeip = -1;
static int hf_njack_set_tlv_typestring = -1;
static int hf_njack_set_tlv_typeyesno = -1;
/* type 08: set result */
static int hf_njack_setresult = -1;
/* type 0b: get */
static int hf_njack_get_data = -1;
/* type 0c: get response */
static int hf_njack_getresp_tlv_type = -1;
static int hf_njack_getresp_tlv_length = -1;
static int hf_njack_getresp_tlv_data = -1;
static int hf_njack_getresp_tlv_typeip = -1;
static int hf_njack_getresp_tlv_typestring = -1;
static int hf_njack_getresp_tlv_typeyesno = -1;

#define PROTO_SHORT_NAME "NJACK"
#define PROTO_LONG_NAME "3com Network Jack"

#define PORT_NJACK1	5264
#define PORT_NJACK2	5265

typedef enum {
	NJACK_TYPE_SET		= 0x07,
	NJACK_TYPE_SETRESULT	= 0x08,

	NJACK_TYPE_GET		= 0x0b,
	NJACK_TYPE_GETRESP	= 0x0c
} njack_type_t;

static const value_string njack_type_vals[] = {
	{ NJACK_TYPE_SET,	"Set"},
	{ NJACK_TYPE_SETRESULT,	"Set result"},
	{ NJACK_TYPE_GET,	"Get"},
	{ NJACK_TYPE_GETRESP,	"Get response"},

	{ 0,	NULL }
};

typedef enum {
	NJACK_CMD_IPADDRESS		= 0x02,
	NJACK_CMD_NETWORK		= 0x03,
	NJACK_CMD_MASK			= 0x04,
	NJACK_CMD_REMOVETAG		= 0x0c,
	NJACK_CMD_GROUP			= 0x0d,
	NJACK_CMD_LOCATION		= 0x0e,
	NJACK_CMD_PORT1			= 0x13,
	NJACK_CMD_PORT2			= 0x14,
	NJACK_CMD_PORT3			= 0x15,
	NJACK_CMD_PORT4			= 0x16,
	NJACK_CMD_PASSWORD		= 0x19,
	NJACK_CMD_ROCOMMUNITY		= 0x1b,
	NJACK_CMD_IPGATEWAY		= 0x20,
	NJACK_CMD_RWCOMMUNITY		= 0x25,
	NJACK_CMD_DEVICETYPE		= 0x2a,
	NJACK_CMD_SERIALNO		= 0x2b,
	NJACK_CMD_ENDOFPACKET		= 0xff
} njack_cmd_type_t;

static const value_string njack_cmd_vals[] = {
	{ NJACK_CMD_IPADDRESS,		"IP address" },
	{ NJACK_CMD_NETWORK,		"IP network" },
	{ NJACK_CMD_MASK,		"IP netmask" },
	{ NJACK_CMD_REMOVETAG,		"Remove tag" },
	{ NJACK_CMD_GROUP,		"Device group" },
	{ NJACK_CMD_LOCATION,		"Location" },
	{ NJACK_CMD_PORT1,		"Port 1 (??)" },
	{ NJACK_CMD_PORT2,		"Port 2 (??)" },
	{ NJACK_CMD_PORT3,		"Port 3 (??)" },
	{ NJACK_CMD_PORT4,		"Port 4 (??)" },
	{ NJACK_CMD_PASSWORD,		"Device password" },
	{ NJACK_CMD_ROCOMMUNITY,	"RO community (??)" },
	{ NJACK_CMD_IPGATEWAY,		"IP gateway" },
	{ NJACK_CMD_RWCOMMUNITY,	"RW community (??)" },
	{ NJACK_CMD_DEVICETYPE,		"Device type(??)" },
	{ NJACK_CMD_SERIALNO,		"Serial no(??)" },
	{ NJACK_CMD_ENDOFPACKET,	"End of packet" },

	{ 0,	NULL }
};

typedef enum {
	NJACK_SETRESULT_SUCCESS	= 0x01,
	NJACK_SETRESULT_FAILAUTH	= 0xFD
} njack_setresult_t;

static const value_string njack_setresult_vals[] = {
	{ NJACK_SETRESULT_SUCCESS,		"Success" },
	{ NJACK_SETRESULT_FAILAUTH,	"Failauth" },

	{ 0,	NULL }
};

static const true_false_string tfs_yes_no = {
	"Yes",
	"No"
};

static int
dissect_njack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_item *tlv_item;
	proto_tree *njack_tree = NULL;
	proto_item *tlv_tree;
	guint32 offset = 0;
	guint8 packet_type;
	guint8 setresult;
	guint8 tlv_type;
	guint8 tlv_length;
	guint16 total_length;
	gboolean last = FALSE;

	packet_type = tvb_get_guint8(tvb, 5);
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, val_to_str(packet_type,
			njack_type_vals, "Type 0x%02x"));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_njack, tvb, offset, -1,
		    FALSE);
		njack_tree = proto_item_add_subtree(ti, ett_njack);

		proto_tree_add_item(njack_tree, hf_njack_magic, tvb, offset, 5,
			FALSE);
		offset += 5;

		proto_tree_add_item(njack_tree, hf_njack_type, tvb, offset, 1,
			FALSE);
		offset += 1;
		switch (packet_type) {
		case NJACK_TYPE_SET:
			/* Type 0x07: S -> M, Magic, type, length (16 bit be) */
			total_length = tvb_get_ntohs(tvb, offset);
			proto_tree_add_item(njack_tree, hf_njack_set_length, tvb, offset,
				2, FALSE);
			offset += 2;
			proto_tree_add_item(njack_tree, hf_njack_set_unknown1, tvb, offset,
				1, FALSE);
			offset += 1;
			proto_tree_add_item(njack_tree, hf_njack_set_seqno, tvb, offset,
				1, FALSE);
			offset += 1;
			proto_tree_add_item(njack_tree, hf_njack_set_unknown2, tvb, offset,
				2, FALSE);
			offset += 2;
			proto_tree_add_item(njack_tree, hf_njack_set_data, tvb, offset,
				16, FALSE);
			offset += 16;
			for (;;) {
				tlv_type = tvb_get_guint8(tvb, offset);
				if (tlv_type == 0xff) {
					proto_tree_add_item(njack_tree, hf_njack_set_tlv_type,
						tvb, offset, 1, FALSE);
					offset += 1;
					break;
				}
				tlv_length = tvb_get_guint8(tvb, offset + 1);
				tlv_item = proto_tree_add_text(njack_tree, tvb,
					offset, tlv_length + 2,
					"T %02x, L %02x: %s",
					tlv_type,
					tlv_length,
					val_to_str(tlv_type, njack_cmd_vals, "Unknown"));
				tlv_tree = proto_item_add_subtree(tlv_item,
					ett_njack_set_tlv_header);
				proto_tree_add_item(tlv_tree, hf_njack_set_tlv_type,
					tvb, offset, 1, FALSE);
				offset += 1;
				proto_tree_add_item(tlv_tree, hf_njack_set_tlv_length,
					tvb, offset, 1, FALSE);
				offset += 1;
				switch (tlv_type) {
				case 0x0c: /* Strip tags */
					proto_tree_add_item(tlv_tree, hf_njack_set_tlv_typeyesno,
						tvb, offset, 1, FALSE);
					offset += 1;
					break;
				case 0x02: /* IP address */
				case 0x03: /* Network address */
				case 0x04: /* Network mask */
				case 0x20: /* Default gateway */
					proto_tree_add_item(tlv_tree, hf_njack_set_tlv_typeip,
						tvb, offset, 4, FALSE);
					offset += 4;
					break;
				case 0x0d: /* group name */
				case 0x0e: /* location */
				case 0x19: /* password */
				case 0x1b: /* ro community ? */
				case 0x25: /* rw community ? */
				case 0x2a: /* Device string ? */
				case 0x2b: /* Serialno ? */
					proto_tree_add_item(tlv_tree, hf_njack_set_tlv_typestring,
						tvb, offset, tlv_length, FALSE);
					offset += tlv_length;
					break;
				default:
					if (tlv_length > 0) {
						proto_tree_add_item(tlv_tree, hf_njack_set_tlv_data,
							tvb, offset, tlv_length, FALSE);
						offset += tlv_length;
					}
					break;
				}
			}
			break;
		case NJACK_TYPE_SETRESULT:
			/* Type 0x08: M -> S, Magic, type, setresult (8 bit) */
			setresult = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(njack_tree, hf_njack_setresult, tvb, offset,
				1, FALSE);
			offset += 1;
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
					val_to_str(setresult, njack_setresult_vals, "[0x%02x]"));
			break;
		case NJACK_TYPE_GET:
			/* Type 0x0b: S -> M, Magic, type, 00 00 63 ff */
			proto_tree_add_item(njack_tree, hf_njack_get_data, tvb, offset,
				4, FALSE);
			offset += 4;
			break;
		case NJACK_TYPE_GETRESP:
			/* Type 0x0c: M -> S, Magic, type, T(8 bit) L(8 bit) V(L bytes) */
			while (!last) {
				tlv_type = tvb_get_guint8(tvb, offset);
				tlv_length = tvb_get_guint8(tvb, offset + 1);
				tlv_item = proto_tree_add_text(njack_tree, tvb,
					offset, tlv_length + 2,
					"T %02x, L %02x: %s",
					tlv_type,
					tlv_length,
					val_to_str(tlv_type, njack_cmd_vals, "Unknown"));
				tlv_tree = proto_item_add_subtree(tlv_item,
					ett_njack_getresp_tlv_header);
				proto_tree_add_item(tlv_tree, hf_njack_getresp_tlv_type,
					tvb, offset, 1, FALSE);
				offset += 1;
				proto_tree_add_item(tlv_tree, hf_njack_getresp_tlv_length,
					tvb, offset, 1, FALSE);
				offset += 1;
				switch (tlv_type) {
				case 0x0c: /* Strip tags */
					proto_tree_add_item(tlv_tree, hf_njack_getresp_tlv_typeyesno,
						tvb, offset, 1, FALSE);
					offset += 1;
					break;
				case 0x02: /* IP address */
				case 0x03: /* Network address */
				case 0x04: /* Network mask */
				case 0x20: /* Default gateway */
					proto_tree_add_item(tlv_tree, hf_njack_getresp_tlv_typeip,
						tvb, offset, 4, FALSE);
					offset += 4;
					break;
				case 0x0d: /* group name */
				case 0x0e: /* location */
				case 0x19: /* password */
				case 0x1b: /* ro community ? */
				case 0x25: /* rw community ? */
				case 0x2a: /* Device string ? */
				case 0x2b: /* Serialno ? */
					proto_tree_add_item(tlv_tree, hf_njack_getresp_tlv_typestring,
						tvb, offset, tlv_length, FALSE);
					offset += tlv_length;
					break;
				case 0xff: /* End of packet */
					last = TRUE;
					break;
				default:
					if (tlv_length > 0) {
						proto_tree_add_item(tlv_tree, hf_njack_getresp_tlv_data,
							tvb, offset, tlv_length, FALSE);
						offset += tlv_length;
					}
					break;
				}
			}
			break;
		default:
			/* Unknown type */
			break;
		}
	}
	return offset;
}

static gboolean
test_njack(tvbuff_t *tvb)
{
	/* We need at least 'NJ200' + 1 Byte packet type */
	if ( !tvb_bytes_exist(tvb, 0, 6) || 
		    g_strncasecmp(tvb_get_ptr(tvb, 0, 5), "NJ200", 5) ) {
        	return FALSE;
	}
	return TRUE;
}

static gboolean
dissect_njack_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if ( !test_njack(tvb) ) {
		return FALSE;
	}
	dissect_njack(tvb, pinfo, tree);
	return TRUE;
}

static int
dissect_njack_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if ( !test_njack(tvb) ) {
		return 0;
	}
	return dissect_njack(tvb, pinfo, tree);
}

void
proto_register_njack(void)
{
	static hf_register_info hf[] = {

	/* NJACK header */
		{ &hf_njack_magic,
		{ "Magic",	"njack.magic", FT_STRING, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_njack_type,
		{ "Type",	"njack.type", FT_UINT8, BASE_HEX, NULL,
			0x0, "", HFILL }},

	/* Type 0x07: set */
		{ &hf_njack_set_length,
		{ "SetLength",	"njack.set.length", FT_UINT16, BASE_HEX, NULL,
			0x0, "", HFILL }},

		{ &hf_njack_set_unknown1,
		{ "Unknown1",	"njack.set.unknown1", FT_UINT8, BASE_HEX, NULL,
			0x0, "", HFILL }},

		{ &hf_njack_set_seqno,
		{ "Seqno",	"njack.set.seqno", FT_UINT8, BASE_HEX, NULL,
			0x0, "", HFILL }},

		{ &hf_njack_set_unknown2,
		{ "Unknown2",	"njack.set.unknown2", FT_UINT16, BASE_HEX, NULL,
			0x0, "", HFILL }},

                { &hf_njack_set_data,
                { "Authdata??",   "njack.set.data", FT_BYTES, BASE_NONE, NULL,
                        0x0, "", HFILL }},

		{ &hf_njack_set_tlv_type,
		{ "SetTlvType",	"njack.set.tlv.type", FT_UINT8, BASE_HEX, VALS(njack_cmd_vals),
			0x0, "", HFILL }},

		{ &hf_njack_set_tlv_length,
		{ "SetTlvLength",	"njack.set.tlv.length", FT_UINT8, BASE_HEX, NULL,
			0x0, "", HFILL }},

                { &hf_njack_set_tlv_data,
                { "SetTlvData",   "njack.set.tlv.data", FT_BYTES, BASE_NONE, NULL,
                        0x0, "", HFILL }},

                { &hf_njack_set_tlv_typeip,
                { "SetTlvTypeIP",   "njack.set.tlv.typeip", FT_IPv4, BASE_NONE, NULL,
                        0x0, "", HFILL }},

                { &hf_njack_set_tlv_typestring,
                { "SetTlvTypeString",   "njack.set.tlv.typestring", FT_STRING, BASE_DEC, NULL,
                        0x0, "", HFILL }},

                { &hf_njack_set_tlv_typeyesno,
                { "SetTlvTypeYesNo",   "njack.set.tlv.typeyesno", FT_BOOLEAN, 8, TFS(&tfs_yes_no),
                        0xff, "", HFILL }},

	/* Type 0x08: set result */
                { &hf_njack_setresult,
                { "SetResult",   "njack.setresult", FT_UINT8, BASE_HEX, VALS(njack_setresult_vals),
                        0x0, "", HFILL }},
	/* Type 0x0b get */
                { &hf_njack_get_data,
                { "GetData",   "njack.get.data", FT_BYTES, BASE_NONE, NULL,
                        0x0, "", HFILL }},
	/* Type 0x0c get response */
		{ &hf_njack_getresp_tlv_type,
		{ "TlvType",	"njack.getresp.tlv.type", FT_UINT8, BASE_HEX, VALS(njack_cmd_vals),
			0x0, "", HFILL }},

		{ &hf_njack_getresp_tlv_length,
		{ "TlvLength",	"njack.getresp.tlv.length", FT_UINT8, BASE_HEX, NULL,
			0x0, "", HFILL }},

                { &hf_njack_getresp_tlv_data,
                { "GetResponeTlvData",   "njack.getresp.tlv.data", FT_BYTES, BASE_NONE, NULL,
                        0x0, "", HFILL }},

                { &hf_njack_getresp_tlv_typeip,
                { "GetResponeTlvTypeIP",   "njack.getresp.tlv.typeip", FT_IPv4, BASE_NONE, NULL,
                        0x0, "", HFILL }},

                { &hf_njack_getresp_tlv_typestring,
                { "GetResponeTlvTypeString",   "njack.getresp.tlv.typestring", FT_STRING, BASE_DEC, NULL,
                        0x0, "", HFILL }},

                { &hf_njack_getresp_tlv_typeyesno,
                { "GetTlvTypeYesNo",   "njack.getresp.tlv.typeyesno", FT_BOOLEAN, 8, TFS(&tfs_yes_no),
                        0xff, "", HFILL }},

        };
	static gint *ett[] = {
		&ett_njack,
		&ett_njack_getresp_tlv_header,
		&ett_njack_set_tlv_header,
	};

        proto_njack = proto_register_protocol(PROTO_LONG_NAME,
	    PROTO_SHORT_NAME, "njack");
        proto_register_field_array(proto_njack, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_njack(void)
{
	dissector_handle_t njack_handle;

	njack_handle = new_create_dissector_handle(dissect_njack_static, proto_njack);
	dissector_add("udp.port", PORT_NJACK1, njack_handle);
	/* dissector_add("tcp.port", PORT_NJACK1, njack_handle); */
	dissector_add("udp.port", PORT_NJACK2, njack_handle);
	/* dissector_add("tcp.port", PORT_NJACK2, njack_handle); */

        heur_dissector_add("udp", dissect_njack_heur, proto_njack);
        /* heur_dissector_add("tcp", dissect_njack_heur, proto_njack); */
}
