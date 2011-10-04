/* packet-aim-sst.c
 * Routines for AIM (OSCAR) dissection, SNAC Server Stored Themes
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
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

#include <stdlib.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-aim.h"

#define FAMILY_SST    0x0010


/* Initialize the protocol and registered fields */
static int proto_aim_sst = -1;
static int hf_aim_sst_unknown = -1;
static int hf_aim_sst_md5_hash = -1;
static int hf_aim_sst_md5_hash_size = -1;
static int hf_aim_sst_ref_num = -1;
static int hf_aim_sst_icon_size = -1;
static int hf_aim_sst_icon = -1;

/* Initialize the subtree pointers */
static gint ett_aim_sst      = -1;

static int dissect_aim_sst_buddy_down_req (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = dissect_aim_buddyname(tvb, pinfo, 0, tree);
	guint8 md5_size;

	proto_tree_add_item(tree, hf_aim_sst_unknown, tvb, offset, 4, ENC_NA);
	offset+=4;

	proto_tree_add_item(tree, hf_aim_sst_md5_hash_size, tvb, offset, 1, FALSE);
	md5_size = tvb_get_guint8(tvb, offset);
	offset++;

	proto_tree_add_item(tree, hf_aim_sst_md5_hash, tvb, offset, md5_size, ENC_NA);

	offset+=md5_size;
	return offset;
}

static int dissect_aim_sst_buddy_down_repl (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = dissect_aim_buddyname(tvb, pinfo, 0, tree);
	guint8 md5_size;
	guint16 icon_size;

	proto_tree_add_item(tree, hf_aim_sst_unknown, tvb, offset, 3, ENC_NA);
	offset+=3;

	proto_tree_add_item(tree, hf_aim_sst_md5_hash_size, tvb, offset, 1, FALSE);
	md5_size = tvb_get_guint8(tvb, offset);
	offset++;

	proto_tree_add_item(tree, hf_aim_sst_md5_hash, tvb, offset, md5_size, ENC_NA);

	offset+=md5_size;

	proto_tree_add_item(tree, hf_aim_sst_icon_size, tvb, offset, 2, FALSE);
	icon_size = tvb_get_ntohs(tvb, offset);
	offset+=2;

	if (icon_size)
	{
		proto_tree_add_item(tree, hf_aim_sst_icon, tvb, offset, icon_size, ENC_NA);
	}

	offset+=icon_size;

	return offset;
}

static int dissect_aim_sst_buddy_up_repl (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	guint8 md5_size;

	proto_tree_add_item(tree, hf_aim_sst_unknown, tvb, offset, 4, ENC_NA);
	offset+=4;

	proto_tree_add_item(tree, hf_aim_sst_md5_hash_size, tvb, offset, 1, FALSE);
	md5_size = tvb_get_guint8(tvb, offset);
	offset++;

	proto_tree_add_item(tree, hf_aim_sst_md5_hash, tvb, offset, md5_size, ENC_NA);

	offset+=md5_size;
	return offset;
}

static int dissect_aim_sst_buddy_up_req (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	guint16 icon_size;

	proto_tree_add_item(tree, hf_aim_sst_ref_num, tvb, offset, 2, FALSE);
	offset+=2;

	proto_tree_add_item(tree, hf_aim_sst_icon_size, tvb, offset, 2, FALSE);
	icon_size = tvb_get_ntohs(tvb, offset);
	offset+=2;

	if (icon_size)
	{
		proto_tree_add_item(tree, hf_aim_sst_icon, tvb, offset, icon_size, ENC_NA);
	}

	offset+=icon_size;
	return offset;
}

static const aim_subtype aim_fnac_family_sst[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Upload Buddy Icon Request", dissect_aim_sst_buddy_up_req },
	{ 0x0003, "Upload Buddy Icon Reply", dissect_aim_sst_buddy_up_repl },
	{ 0x0004, "Download Buddy Icon Request", dissect_aim_sst_buddy_down_req },
	{ 0x0005, "Download Buddy Icon Reply", dissect_aim_sst_buddy_down_repl },
	{ 0, NULL, NULL }
};


/* Register the protocol with Wireshark */
void
proto_register_aim_sst(void)
{

/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_aim_sst_md5_hash,
		  { "MD5 Hash", "aim_sst.md5", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_sst_md5_hash_size,
		  { "MD5 Hash Size", "aim_sst.md5.size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_sst_unknown,
		  { "Unknown Data", "aim_sst.unknown", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_sst_ref_num,
		  { "Reference Number", "aim_sst.ref_num", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_sst_icon_size,
		  { "Icon Size", "aim_sst.icon_size", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_sst_icon,
		  { "Icon", "aim_sst.icon", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_aim_sst,
	};

/* Register the protocol name and description */
	proto_aim_sst = proto_register_protocol("AIM Server Side Themes", "AIM SST", "aim_sst");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_aim_sst, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_sst(void)
{
	aim_init_family(proto_aim_sst, ett_aim_sst, FAMILY_SST, aim_fnac_family_sst);
}
