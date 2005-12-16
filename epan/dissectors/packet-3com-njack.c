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
  - Find out set authentication mechanism, offer verification option
  - Support for other 3com devices that use the same protocol
  - Do any devices use TCP or different ports?
  - Sanity checks for tlv_length depending on tlv_type
  - Replace numbers by their enum-values
  - Consistent nameing of tfs elements

Specs:
	No specs available. All knowledge gained by looking at traffic dumps
	Packets to Managementstation: PORT_NJACK1 (5264)
	Packets to Switch: PORT_NJACK2 (5265)

	Type 0x07 (set):      M -> S, Magic, type, length (16 bit be)
	Type 0x08 (set resp): S -> M, Magic, type, net length (8 bit), result status
	Type 0x0b (get):      M -> S, Magic, type, 00 00 63 ff
	Type 0x0c (get resp): S -> M, Magic, type, T(8 bit) L(8 bit) V(L bytes)
	Type 0x0d (dhcpinfo): S -> M, Magic, type, tlv, t=00 = last (no length)
	Type 0x10 (clear counters):      M -> S, Magic, type, 0400
	Type 0x10 (clear counters resp): M -> S, Magic, type, 00
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
static int ett_njack_tlv_header = -1;

/* hf elements */
static int hf_njack_magic = -1;
static int hf_njack_type = -1;
/* type set/get response */
static int hf_njack_auth_data = -1;
static int hf_njack_tlv_length = -1;
static int hf_njack_tlv_data = -1;
static int hf_njack_tlv_type = -1;
static int hf_njack_tlv_typeip = -1;
static int hf_njack_tlv_typemac = -1;
static int hf_njack_tlv_typestring = -1;
static int hf_njack_tlv_typeyesno = -1;
static int hf_njack_tlv_typecountermode = -1;
static int hf_njack_tlv_typescheduling = -1;
/* type 07: set */
static int hf_njack_set_length = -1;
static int hf_njack_set_unknown1 = -1;
static int hf_njack_set_seqno = -1;
/* type 08: set result */
static int hf_njack_setresult = -1;
/* type 0b: get */
/* type 0c: get response */
static int hf_njack_getresp_unknown1 = -1;

#define PROTO_SHORT_NAME "NJACK"
#define PROTO_LONG_NAME "3com Network Jack"

#define PORT_NJACK1	5264
#define PORT_NJACK2	5265

typedef enum {
	NJACK_TYPE_SET		= 0x07,
	NJACK_TYPE_SETRESULT	= 0x08,

	NJACK_TYPE_GET		= 0x0b,
	NJACK_TYPE_GETRESP	= 0x0c,

	NJACK_TYPE_DHCPINFO	= 0x0d,

	NJACK_TYPE_CLEARCOUNTER	= 0x10,
	NJACK_TYPE_COUNTERRESP	= 0x11
} njack_type_t;

static const value_string njack_type_vals[] = {
	{ NJACK_TYPE_SET,		"Set"},
	{ NJACK_TYPE_SETRESULT,		"Set result"},
	{ NJACK_TYPE_GET,		"Get"},
	{ NJACK_TYPE_GETRESP,		"Get response"},
	{ NJACK_TYPE_DHCPINFO,		"DHCP info\?\?"},
	{ NJACK_TYPE_CLEARCOUNTER,	"Clear counters\?\?"},
	{ NJACK_TYPE_COUNTERRESP,	"Clear counters response\?\?"},

	{ 0,	NULL }
};

typedef enum {
	NJACK_CMD_STARTOFPARAMS		= 0x00,
	NJACK_CMD_MACADDRESS		= 0x01,
	NJACK_CMD_IPADDRESS		= 0x02,
	NJACK_CMD_NETWORK		= 0x03,
	NJACK_CMD_MASK			= 0x04,
	NJACK_CMD_COUNTERMODE		= 0x06,
	NJACK_CMD_QUEUEING		= 0x0a,
	NJACK_CMD_REMOVETAG		= 0x0c,
	NJACK_CMD_GROUP			= 0x0d,
	NJACK_CMD_LOCATION		= 0x0e,
	NJACK_CMD_PORT1			= 0x13,
	NJACK_CMD_PORT2			= 0x14,
	NJACK_CMD_PORT3			= 0x15,
	NJACK_CMD_PORT4			= 0x16,
	NJACK_CMD_PASSWORD		= 0x19,
	NJACK_CMD_ENABLESNMPWRITE	= 0x1a,
	NJACK_CMD_ROCOMMUNITY		= 0x1b,
	NJACK_CMD_RWCOMMUNITY		= 0x1c,
	NJACK_CMD_DHCPCONTROL		= 0x1f,
	NJACK_CMD_IPGATEWAY		= 0x20,
	NJACK_CMD_PRODUCTNAME		= 0x2a,
	NJACK_CMD_SERIALNO		= 0x2b,
	NJACK_CMD_GETALLPARMAMS		= 0x63,
	NJACK_CMD_ENDOFPACKET		= 0xff
} njack_cmd_type_t;

static const value_string njack_cmd_vals[] = {
	{ NJACK_CMD_STARTOFPARAMS,	"Start of Parameters" },
	{ NJACK_CMD_MACADDRESS,		"MAC address" },
	{ NJACK_CMD_IPADDRESS,		"IP address" },
	{ NJACK_CMD_NETWORK,		"IP network" },
	{ NJACK_CMD_MASK,		"IP netmask" },
	{ NJACK_CMD_COUNTERMODE,	"Countermode" },
	{ NJACK_CMD_QUEUEING,		"Priority scheduling policy" },
	{ NJACK_CMD_REMOVETAG,		"Remove tag" },
	{ NJACK_CMD_GROUP,		"Device group" },
	{ NJACK_CMD_LOCATION,		"Location" },
	{ NJACK_CMD_PORT1,		"Port 1" },
	{ NJACK_CMD_PORT2,		"Port 2" },
	{ NJACK_CMD_PORT3,		"Port 3" },
	{ NJACK_CMD_PORT4,		"Port 4" },
	{ NJACK_CMD_PASSWORD,		"Device password" },
	{ NJACK_CMD_ENABLESNMPWRITE,	"SNMP write enable" },
	{ NJACK_CMD_ROCOMMUNITY,	"RO community" },
	{ NJACK_CMD_RWCOMMUNITY,	"RW community" },
	{ NJACK_CMD_DHCPCONTROL,	"DHCP control" },
	{ NJACK_CMD_IPGATEWAY,		"IP gateway" },
	{ NJACK_CMD_PRODUCTNAME,	"Product name" },
	{ NJACK_CMD_SERIALNO,		"Serial no" },
	{ NJACK_CMD_GETALLPARMAMS,	"Get all parameters" },
	{ NJACK_CMD_ENDOFPACKET,	"End of packet" },

	{ 0,	NULL }
};

typedef enum {
	NJACK_SETRESULT_SUCCESS		= 0x01,
	NJACK_SETRESULT_FAILAUTH	= 0xFD
} njack_setresult_t;

static const value_string njack_setresult_vals[] = {
	{ NJACK_SETRESULT_SUCCESS,	"Success" },
	{ NJACK_SETRESULT_FAILAUTH,	"Failauth" },

	{ 0,	NULL }
};

static const true_false_string tfs_yes_no = {
	"Yes",
	"No"
};

static const true_false_string tfs_good_errors = {
	"Good frames",
	"RX errors, TX collisions"
};

static const true_false_string tfs_scheduling = {
	"Weighted fair",
	"Priority"
};

static int
dissect_portsettings(tvbuff_t *tvb, proto_tree *port_tree, guint32 offset)
{
	proto_tree_add_item(port_tree, hf_njack_tlv_data,
		tvb, offset, 8, FALSE);
	return offset;
}

static int
dissect_tlvs(tvbuff_t *tvb, proto_tree *njack_tree, guint32 offset, gboolean is_set)
{
	guint8 tlv_type;
	guint8 tlv_length;
	proto_item *tlv_item;
	proto_item *tlv_tree;

	for (;;) {
		tlv_type = tvb_get_guint8(tvb, offset);
		/* Special cases that don't have a length field */
		if (tlv_type == NJACK_CMD_ENDOFPACKET) {
			proto_tree_add_item(njack_tree, hf_njack_tlv_type,
				tvb, offset, 1, FALSE);
			offset += 1;
			break;
		}
		if (tlv_type == NJACK_CMD_GETALLPARMAMS) {
			proto_tree_add_item(njack_tree, hf_njack_tlv_type,
				tvb, offset, 1, FALSE);
			offset += 1;
			continue;
		}
		tlv_length = tvb_get_guint8(tvb, offset + 1);
		tlv_item = proto_tree_add_text(njack_tree, tvb,
			offset, tlv_length + 2,
			"T %02x, L %02x: %s",
			tlv_type,
			tlv_length,
			val_to_str(tlv_type, njack_cmd_vals, "Unknown"));
		tlv_tree = proto_item_add_subtree(tlv_item,
			ett_njack_tlv_header);
		proto_tree_add_item(tlv_tree, hf_njack_tlv_type,
			tvb, offset, 1, FALSE);
		offset += 1;
		proto_tree_add_item(tlv_tree, hf_njack_tlv_length,
			tvb, offset, 1, FALSE);
		offset += 1;
		switch (tlv_type) {
		case NJACK_CMD_STARTOFPARAMS:
			if (is_set) { /* followed by authdata? in case of set */
				proto_tree_add_item(njack_tree, hf_njack_auth_data, tvb,
					offset, 16, FALSE);
				offset += 16;
			}
			break;
		case 0x06: /* Counter mode */
			proto_tree_add_item(tlv_tree, hf_njack_tlv_typecountermode,
				tvb, offset, 1, FALSE);
			offset += 1;
			break;
		case 0x0a: /* Scheduling */
			proto_tree_add_item(tlv_tree, hf_njack_tlv_typescheduling,
				tvb, offset, 1, FALSE);
			offset += 1;
			break;
		case 0x0c: /* Strip tags */
		case 0x1a: /* Enable SNMP write */
		case 0x1f: /* DHCP control (disabled/enabled) */
			proto_tree_add_item(tlv_tree, hf_njack_tlv_typeyesno,
				tvb, offset, 1, FALSE);
			offset += 1;
			break;
		case 0x01: /* MAC address */
			proto_tree_add_item(tlv_tree, hf_njack_tlv_typemac,
				tvb, offset, 6, FALSE);
			offset += 6;
			break;
		case 0x02: /* IP address */
		case 0x03: /* Network address */
		case 0x04: /* Network mask */
		case 0x20: /* Default gateway */
			proto_tree_add_item(tlv_tree, hf_njack_tlv_typeip,
				tvb, offset, 4, FALSE);
			offset += 4;
			break;
		case 0x0d: /* group name */
		case 0x0e: /* location */
		case 0x19: /* password */
		case 0x1b: /* ro community */
		case 0x1c: /* rw community */
		case 0x25: /* ? */
		case 0x2a: /* Product name */
		case 0x2b: /* Serialno - ending in last 3 bytes of MAC address */
			proto_tree_add_item(tlv_tree, hf_njack_tlv_typestring,
				tvb, offset, tlv_length, FALSE);
			offset += tlv_length;
			break;
		case NJACK_CMD_PORT1:
		case NJACK_CMD_PORT2:
		case NJACK_CMD_PORT3:
		case NJACK_CMD_PORT4:
			if (tlv_length == 8) {
				dissect_portsettings(tvb, tlv_tree, offset);
			}
			offset += tlv_length;
			break;
		default:
			if (tlv_length > 0) {
				proto_tree_add_item(tlv_tree, hf_njack_tlv_data,
					tvb, offset, tlv_length, FALSE);
				offset += tlv_length;
			}
			break;
		}
	}
	return offset;
}

static int
dissect_njack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *njack_tree = NULL;
	guint32 offset = 0;
	guint8 packet_type;
	guint8 setresult;
	gint remaining;

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
			proto_tree_add_item(njack_tree, hf_njack_set_length, tvb, offset,
				2, FALSE);
			offset += 2;
			proto_tree_add_item(njack_tree, hf_njack_set_unknown1, tvb, offset,
				1, FALSE);
			offset += 1;
			proto_tree_add_item(njack_tree, hf_njack_set_seqno, tvb, offset,
				1, FALSE);
			offset += 1;
			offset = dissect_tlvs(tvb, njack_tree, offset, TRUE);
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
			offset = dissect_tlvs(tvb, njack_tree, offset, FALSE);
			break;
		case NJACK_TYPE_GETRESP:
			/* Type 0x0c: M -> S, Magic, type, T(8 bit) L(8 bit) V(L bytes) */
			offset = dissect_tlvs(tvb, njack_tree, offset, FALSE);
			proto_tree_add_item(njack_tree, hf_njack_getresp_unknown1, tvb, offset,
				1, FALSE);
			offset += 1;
			break;
		case NJACK_TYPE_DHCPINFO: /* not completely understood */
		default:
			/* Unknown type */
			remaining = tvb_reported_length_remaining(tvb, offset);
			if (remaining > 0) {
				proto_tree_add_item(njack_tree, hf_njack_tlv_data,
					tvb, offset, remaining, FALSE);
				offset += remaining;
			}
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

	/* TLV fields */
                { &hf_njack_auth_data,
                { "Authdata\?\?",   "njack.tlv.authdata", FT_BYTES, BASE_NONE, NULL,
                        0x0, "", HFILL }},

		{ &hf_njack_tlv_type,
		{ "TlvType",	"njack.tlv.type", FT_UINT8, BASE_HEX, VALS(njack_cmd_vals),
			0x0, "", HFILL }},

		{ &hf_njack_tlv_length,
		{ "TlvLength",	"njack.tlv.length", FT_UINT8, BASE_HEX, NULL,
			0x0, "", HFILL }},

                { &hf_njack_tlv_data,
                { "TlvData",   "njack.tlv.data", FT_BYTES, BASE_NONE, NULL,
                        0x0, "", HFILL }},

                { &hf_njack_tlv_typeip,
                { "TlvTypeIP",   "njack.tlv.typeip", FT_IPv4, BASE_NONE, NULL,
                        0x0, "", HFILL }},

                { &hf_njack_tlv_typemac,
                { "TlvTypeMAC",   "njack.tlv.typemac", FT_ETHER, BASE_NONE, NULL,
                        0x0, "", HFILL }},

                { &hf_njack_tlv_typestring,
                { "TlvTypeString",   "njack.tlv.typestring", FT_STRING, BASE_DEC, NULL,
                        0x0, "", HFILL }},

                { &hf_njack_tlv_typecountermode,
                { "TlvTypeCountermode",   "njack.tlv.typecontermode", FT_BOOLEAN, 8, TFS(&tfs_good_errors),
                        0xff, "", HFILL }},

                { &hf_njack_tlv_typescheduling,
                { "TlvTypeScheduling",   "njack.tlv.typescheduling", FT_BOOLEAN, 8, TFS(&tfs_scheduling),
                        0xff, "", HFILL }},

                { &hf_njack_tlv_typeyesno,
                { "TlvTypeYesNo",   "njack.tlv.typeyesno", FT_BOOLEAN, 8, TFS(&tfs_yes_no),
                        0xff, "", HFILL }},

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

	/* Type 0x08: set result */
                { &hf_njack_setresult,
                { "SetResult",   "njack.setresult", FT_UINT8, BASE_HEX, VALS(njack_setresult_vals),
                        0x0, "", HFILL }},

	/* Type 0x0b get */

	/* Type 0x0c get response */
		{ &hf_njack_getresp_unknown1,
		{ "Unknown1",	"njack.getresp.unknown1", FT_UINT8, BASE_HEX, NULL,
			0x0, "", HFILL }},

        };
	static gint *ett[] = {
		&ett_njack,
		&ett_njack_tlv_header,
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
