/* packet-rmp.c
 * Routines for HP remote management protocol
 * Gilbert Ramirez <jochen@scram.de>
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>

#include "packet-hpext.h"

void proto_register_rmp(void);
void proto_reg_handoff_rmp(void);

static dissector_handle_t data_handle;

static int proto_rmp = -1;

static int hf_rmp_type = -1;
static int hf_rmp_retcode = -1;
static int hf_rmp_seqnum = -1;
static int hf_rmp_sessionid = -1;
static int hf_rmp_version = -1;
static int hf_rmp_machtype = -1;
static int hf_rmp_filename = -1;
static int hf_rmp_offset = -1;
static int hf_rmp_size = -1;

static gint ett_rmp = -1;

/*
 *  Possible values for "rmp_type" fields.
 */

#define RMP_BOOT_REQ    1       /* boot request packet */
#define RMP_BOOT_REPL   129     /* boot reply packet */
#define RMP_READ_REQ    2       /* read request packet */
#define RMP_READ_REPL   130     /* read reply packet */
#define RMP_BOOT_DONE   3       /* boot complete packet */

/*
 *  RMP error codes
 */

#define RMP_E_OKAY      0
#define RMP_E_EOF       2       /* read reply: returned end of file */
#define RMP_E_ABORT     3       /* abort operation */
#define RMP_E_BUSY      4       /* boot reply: server busy */
#define RMP_E_TIMEOUT   5       /* lengthen time out (not implemented) */
#define RMP_E_NOFILE    16      /* boot reply: file does not exist */
#define RMP_E_OPENFILE  17      /* boot reply: file open failed */
#define RMP_E_NODFLT    18      /* boot reply: default file does not exist */
#define RMP_E_OPENDFLT  19      /* boot reply: default file open failed */
#define RMP_E_BADSID    25      /* read reply: bad session ID */
#define RMP_E_BADPACKET 27      /* Bad packet detected */

const value_string rmp_type_vals[] = {
	{ RMP_BOOT_REQ,       "Boot Request" },
	{ RMP_BOOT_REPL,      "Boot Reply" },
	{ RMP_READ_REQ,       "Read Request" },
	{ RMP_READ_REPL,      "Read Reply" },
	{ RMP_BOOT_DONE,      "Boot Done" },
	{ 0x00,               NULL }
};

const value_string rmp_error_vals[] = {
	{ RMP_E_OKAY,         "OK" },
	{ RMP_E_EOF,          "End Of File" },
	{ RMP_E_ABORT,        "Abort Operation" },
	{ RMP_E_BUSY,         "Server Busy" },
	{ RMP_E_TIMEOUT,      "Lengthen Time Out" },
	{ RMP_E_NOFILE,       "File Does Not Exist" },
	{ RMP_E_OPENFILE,     "File Open Failed" },
	{ RMP_E_NODFLT,       "Default File Does Not Exist" },
	{ RMP_E_OPENDFLT,     "Default File Open Failed" },
	{ RMP_E_BADSID,       "Bad Session Id" },
	{ RMP_E_OPENDFLT,     "Bad Packet Detected" },
	{ 0x00,               NULL }
};

static void
dissect_rmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*rmp_tree = NULL;
	proto_item	*ti = NULL;
	guint8		type, len;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RMP");

	col_clear(pinfo->cinfo, COL_INFO);

	type = tvb_get_guint8(tvb, 0);

	col_set_str(pinfo->cinfo, COL_INFO,
		    val_to_str_const(type, rmp_type_vals, "Unknown Type"));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_rmp, tvb, 0, -1, ENC_NA);
		rmp_tree = proto_item_add_subtree(ti, ett_rmp);
		proto_tree_add_uint(rmp_tree, hf_rmp_type, tvb, 0, 1, type);

		switch (type) {
			case RMP_BOOT_REQ:
				proto_tree_add_item(rmp_tree,
				    hf_rmp_retcode, tvb, 1, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(rmp_tree,
				    hf_rmp_seqnum, tvb, 2, 4, ENC_BIG_ENDIAN);
				proto_tree_add_item(rmp_tree,
				    hf_rmp_sessionid, tvb, 6, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(rmp_tree,
				    hf_rmp_version, tvb, 8, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(rmp_tree,
				    hf_rmp_machtype, tvb, 10, 20, ENC_ASCII|ENC_NA);
				/* The remaining fields are optional */
				if(!tvb_offset_exists(tvb, 30))
					return;
				len = tvb_get_guint8(tvb, 30);
				proto_tree_add_item(rmp_tree,
				    hf_rmp_filename, tvb, 30, 1, ENC_ASCII|ENC_NA);
				if(tvb_offset_exists(tvb, len+31))
					call_dissector(data_handle,
					    tvb_new_subset_remaining(tvb, len+31),
					    pinfo, tree);
				break;

			case RMP_BOOT_REPL:
				proto_tree_add_item(rmp_tree,
				    hf_rmp_retcode, tvb, 1, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(rmp_tree,
				    hf_rmp_seqnum, tvb, 2, 4, ENC_BIG_ENDIAN);
				proto_tree_add_item(rmp_tree,
				    hf_rmp_sessionid, tvb, 6, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(rmp_tree,
				    hf_rmp_version, tvb, 8, 2, ENC_BIG_ENDIAN);
				len = tvb_get_guint8(tvb, 10);
				proto_tree_add_item(rmp_tree,
				    hf_rmp_filename, tvb, 10, 1, ENC_ASCII|ENC_NA);
				if(tvb_offset_exists(tvb, len+11))
					call_dissector(data_handle,
					    tvb_new_subset_remaining(tvb, len+11),
					    pinfo, tree);
				break;

			case RMP_READ_REQ:
				proto_tree_add_item(rmp_tree,
				    hf_rmp_retcode, tvb, 1, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(rmp_tree,
				    hf_rmp_offset, tvb, 2, 4, ENC_BIG_ENDIAN);
				proto_tree_add_item(rmp_tree,
				    hf_rmp_sessionid, tvb, 6, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(rmp_tree,
				    hf_rmp_size, tvb, 8, 2, ENC_BIG_ENDIAN);
				if(tvb_offset_exists(tvb, 10))
					call_dissector(data_handle,
					    tvb_new_subset_remaining(tvb, 10),
					    pinfo, tree);
				break;

			case RMP_READ_REPL:
				proto_tree_add_item(rmp_tree,
				    hf_rmp_retcode, tvb, 1, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(rmp_tree,
				    hf_rmp_offset, tvb, 2, 4, ENC_BIG_ENDIAN);
				proto_tree_add_item(rmp_tree,
				    hf_rmp_sessionid, tvb, 6, 2, ENC_BIG_ENDIAN);
				call_dissector(data_handle, tvb_new_subset_remaining(tvb,
				    8), pinfo, rmp_tree);
				break;

			case RMP_BOOT_DONE:
				proto_tree_add_item(rmp_tree,
				    hf_rmp_retcode, tvb, 1, 1, ENC_BIG_ENDIAN);
				proto_tree_add_text(rmp_tree,
				    tvb, 2, 4, "Reserved");
				proto_tree_add_item(rmp_tree,
				    hf_rmp_sessionid, tvb, 6, 2, ENC_BIG_ENDIAN);
				if(tvb_offset_exists(tvb, 8))
					call_dissector(data_handle,
					    tvb_new_subset_remaining(tvb, 6),
					    pinfo, tree);
				break;
			default:
				call_dissector(data_handle, tvb_new_subset_remaining(tvb,
				    1), pinfo, tree);
		}
	}
}

void
proto_register_rmp(void)
{
	static hf_register_info hf[] = {
		{ &hf_rmp_type,
		{ "Type", "rmp.type", FT_UINT8, BASE_HEX,
			VALS(rmp_type_vals), 0x0, NULL, HFILL }},
		{ &hf_rmp_retcode,
		{ "Returncode", "rmp.retcode", FT_UINT8, BASE_HEX,
			VALS(rmp_error_vals), 0x0, NULL, HFILL }},
		{ &hf_rmp_seqnum,
		{ "Sequence Number", "rmp.seqnum", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_rmp_sessionid,
		{ "Session ID", "rmp.sessionid", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_rmp_version,
		{ "Version", "rmp.version", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_rmp_machtype,
		{ "Machine Type", "rmp.machtype", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_rmp_filename,
		{ "Filename", "rmp.filename", FT_UINT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_rmp_offset,
		{ "Offset", "rmp.offset", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_rmp_size,
		{ "Size", "rmp.size", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_rmp,
	};

	proto_rmp = proto_register_protocol(
	    "HP Remote Maintenance Protocol", "RMP", "rmp");
	proto_register_field_array(proto_rmp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("rmp", dissect_rmp, proto_rmp);
}

void
proto_reg_handoff_rmp(void)
{
	dissector_handle_t rmp_handle;

	data_handle = find_dissector("data");

	rmp_handle = find_dissector("rmp");
	dissector_add_uint("hpext.dxsap", HPEXT_DXSAP, rmp_handle);
	dissector_add_uint("hpext.dxsap", HPEXT_SXSAP, rmp_handle);
}
