/* packet-cisco-wireless.c
 * Routines for the disassembly of some (unknown) L2 packets
 * sent by Ciscos Access Points (Aironet)
 *
 * Copyright 2005 Joerg Mayer (see AUTHORS file)
 *
 * $Id$
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
 * I couldn't find any documentation on this protocol. Neither
 * what it's good for nor what the elements do. This is purely
 * reverse engineered by looking at the hex dump of the packets.
 *
 * Sample capture in wiki (ciscowl.pcap.gz)
 *
 * TODO
 *	- Find out more about unknown fields
 *	- Currently only one type of packet is really handled at all
 * 
 * Packets are sent in two possible encapsulations:
 * Ethernet V2 with type 0x872d or SNAP with OUI 0x004096
 *
 * Header (Eth V2 or SNAP)
 * Length (2 bytes)
 * Type (2 bytes)
 *	0202: Unknown, Length 36 (14 + 20 + 2)
 *	4001: Unknown, Length 48 (14 + 32 + 2)
 *	4601: Unknown, Length 34 (14 + 18 + 2)
 *	4081 on Eth V2: Name, Version Length 84 (14 + 48 + 20 + 2)
 *	4081 on 802.3: Name Length 72 (14 + 56 + 2)
 * Dst MAC (6 bytes)
 * Src MAC (6 bytes)
 * Unknown1 (2 bytes)  Unknown19 + Unknown2 may be a MAC address on type 0202
 * Unknown2 (4 bytes)	see Unknown19
 * 0 (17 bytes)
 * Device IP (4 bytes)
 * 0 (2 bytes)
 * Device name (8 bytes)
 * 0 (20 bytes)
 * Unknown3 (2 bytes)
 * Unknown4 (4 bytes)
 * Version string (10 bytes)
 * 0 (4 bytes)
 * 0 (2 bytes)
 */


#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include "packet-llc.h"
#include <epan/oui.h>
#include <epan/etypes.h>

static int hf_llc_ciscowl_pid = -1;

static int proto_ciscowl = -1;

static int hf_ciscowl_length = -1;
static int hf_ciscowl_type = -1;
static int hf_ciscowl_srcmac = -1;
static int hf_ciscowl_dstmac = -1;
static int hf_ciscowl_somemac = -1;
static int hf_ciscowl_unknown1 = -1;
static int hf_ciscowl_unknown2 = -1;
static int hf_ciscowl_null1 = -1;
static int hf_ciscowl_ip = -1;
static int hf_ciscowl_null2 = -1;
static int hf_ciscowl_name = -1;
static int hf_ciscowl_unknown3 = -1;
static int hf_ciscowl_unknown4 = -1;
static int hf_ciscowl_version = -1;
static int hf_ciscowl_rest = -1;

static gint ett_ciscowl = -1;

#define PROTO_SHORT_NAME "CISCOWL-L2"
#define PROTO_LONG_NAME "Cisco Wireless Layer 2"

static const value_string cisco_pid_vals[] = {
	{ 0x0000,	"CiscoWL" },

	{ 0,		NULL }
};

static void
dissect_ciscowl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *ciscowl_tree = NULL;
	guint32 offset = 0;
	guint32 length, type;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, PROTO_SHORT_NAME);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ciscowl, tvb, offset, -1,
		    FALSE);
		ciscowl_tree = proto_item_add_subtree(ti, ett_ciscowl);

		length = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(ciscowl_tree, hf_ciscowl_length, tvb, offset, 2,
			FALSE);
		offset += 2;

		type = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(ciscowl_tree, hf_ciscowl_type, tvb, offset, 2,
			FALSE);
		offset += 2;

		proto_tree_add_item(ciscowl_tree, hf_ciscowl_dstmac, tvb, offset, 6,
			FALSE);
		offset += 6;

		proto_tree_add_item(ciscowl_tree, hf_ciscowl_srcmac, tvb, offset, 6,
			FALSE);
		offset += 6;

		if (type == 0x0202) {
			proto_tree_add_item(ciscowl_tree, hf_ciscowl_somemac, tvb,
			offset, 6, FALSE);
			offset += 6;
		} else {
			proto_tree_add_item(ciscowl_tree, hf_ciscowl_unknown1, tvb,
				offset, 2, FALSE);
			offset += 2;

			proto_tree_add_item(ciscowl_tree, hf_ciscowl_unknown2, tvb,
				offset, 4, FALSE);
			offset += 4;
		}
		if (type == 0x4081) {
			proto_tree_add_item(ciscowl_tree, hf_ciscowl_null1, tvb,
				offset, 16, FALSE);
			offset += 16;

			proto_tree_add_item(ciscowl_tree, hf_ciscowl_ip, tvb,
				offset, 4, FALSE);
			offset += 4;

			proto_tree_add_item(ciscowl_tree, hf_ciscowl_null2, tvb,
				offset, 2, FALSE);
			offset += 2;

			proto_tree_add_item(ciscowl_tree, hf_ciscowl_name, tvb,
				offset, 28, FALSE);
			offset += 28;

			proto_tree_add_item(ciscowl_tree, hf_ciscowl_unknown3, tvb,
				offset, 2, FALSE);
			offset += 2;

			/* Frames in IEEE 802.3 format don't have a version field? */
			if (length > offset) {
				proto_tree_add_item(ciscowl_tree, hf_ciscowl_unknown4, tvb,
					offset, 4, FALSE);
				offset += 4;

				proto_tree_add_item(ciscowl_tree, hf_ciscowl_version, tvb,
					offset, 14, FALSE);
				offset += 14;
			}
			proto_tree_add_item(ciscowl_tree, hf_ciscowl_rest, tvb,
				offset, length - offset, FALSE);
			offset = length;
		} else {
			proto_tree_add_item(ciscowl_tree, hf_ciscowl_rest, tvb,
				offset, length - offset, FALSE);
			offset = length;
		}

	}
}

void
proto_register_ciscowl(void)
{
	static hf_register_info hf[] = {

		{ &hf_ciscowl_length,
		{ "Length",	"ciscowl.length", FT_UINT16, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_ciscowl_type,
		{ "Type",	"ciscowl.type", FT_UINT16, BASE_HEX, NULL,
			0x0, "Type(?)", HFILL }},

		{ &hf_ciscowl_srcmac,
		{ "Src MAC",	"ciscowl.srcmac", FT_ETHER, BASE_NONE, NULL,
			0x0, "Source MAC", HFILL }},

		{ &hf_ciscowl_dstmac,
		{ "Dst MAC",	"ciscowl.dstmac", FT_ETHER, BASE_NONE, NULL,
			0x0, "Destination MAC", HFILL }},

		{ &hf_ciscowl_somemac,
		{ "Some MAC",	"ciscowl.somemac", FT_ETHER, BASE_NONE, NULL,
			0x0, "Some unknown MAC", HFILL }},

		{ &hf_ciscowl_unknown1,
		{ "Unknown1",	"ciscowl.unknown1", FT_BYTES, BASE_HEX, NULL,
			0x0, "", HFILL }},

		{ &hf_ciscowl_unknown2,
		{ "Unknown2",	"ciscowl.unknown2", FT_BYTES, BASE_HEX, NULL,
			0x0, "", HFILL }},

		{ &hf_ciscowl_null1,
		{ "Null1",	"ciscowl.null1", FT_BYTES, BASE_HEX, NULL,
			0x0, "", HFILL }},

		{ &hf_ciscowl_ip,
		{ "IP",	"ciscowl.ip", FT_IPv4, BASE_NONE, NULL,
			0x0, "Device IP", HFILL }},

		{ &hf_ciscowl_null2,
		{ "Null2",	"ciscowl.null2", FT_BYTES, BASE_HEX, NULL,
			0x0, "", HFILL }},

		{ &hf_ciscowl_name,
		{ "Name",	"ciscowl.name", FT_STRING, BASE_NONE, NULL,
			0x0, "Device Name", HFILL }},

		{ &hf_ciscowl_unknown3,
		{ "Unknown3",	"ciscowl.unknown3", FT_BYTES, BASE_HEX, NULL,
			0x0, "", HFILL }},

		{ &hf_ciscowl_unknown4,
		{ "Unknown4",	"ciscowl.unknown4", FT_BYTES, BASE_HEX, NULL,
			0x0, "", HFILL }},

		{ &hf_ciscowl_version,
		{ "Version",	"ciscowl.version", FT_STRING, BASE_NONE, NULL,
			0x0, "Device Version String", HFILL }},

		{ &hf_ciscowl_rest,
		{ "Rest",	"ciscowl.rest", FT_BYTES, BASE_HEX, NULL,
			0x0, "Unknown remaining data", HFILL }},

        };
	static gint *ett[] = {
		&ett_ciscowl,
	};

        proto_ciscowl = proto_register_protocol(PROTO_LONG_NAME,
	    PROTO_SHORT_NAME, "ciscowl");
        proto_register_field_array(proto_ciscowl, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ciscowl(void)
{
	dissector_handle_t ciscowl_handle;

	ciscowl_handle = create_dissector_handle(dissect_ciscowl, proto_ciscowl);
	dissector_add("llc.ciscowl_pid", 0x0000, ciscowl_handle);
	dissector_add("ethertype", ETHERTYPE_CISCOWL, ciscowl_handle);
}

void
proto_register_ciscowl_oui(void)
{
	static hf_register_info hf = {
	    &hf_llc_ciscowl_pid,
		{ "PID",	"llc.ciscowl_pid",  FT_UINT16, BASE_HEX,
		  VALS(cisco_pid_vals), 0x0, "", HFILL },
	};

	llc_add_oui(OUI_CISCOWL, "llc.ciscowl_pid", "Cisco Wireless OUI PID", &hf);
}
