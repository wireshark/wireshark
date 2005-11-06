/* packet-smb2.c
 * Routines for smb2 packet dissection
 *
 * $Id: packet-smb2.c 16113 2005-10-04 10:23:40Z guy $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/tap.h>
#include <epan/emem.h>

#include "packet-dcerpc.h"
#include "packet-ntlmssp.h"



static int proto_smb2 = -1;
static int hf_smb2_cmd = -1;
static int hf_smb2_mpxid = -1;
static int hf_smb2_tid = -1;
static int hf_smb2_flags_response = -1;
static int hf_smb2_unknown = -1;


static gint ett_smb2 = -1;


#define SMB2_FLAGS_RESPONSE	0x01

static const true_false_string tfs_flags_response = {
	"This is a RESPONSE",
	"This is a REQUEST"
};

/* names here are just until we find better names for these functions */
const value_string smb2_cmd_vals[] = {
  { 0x00, "NegotiateProtocol" },
  { 0x01, "SessionSetupAndX" },
  { 0x02, "unknown-0x02" },
  { 0x03, "TreeConnectAndX" },
  { 0x04, "unknown-0x04" },
  { 0x05, "unknown-0x05" },
  { 0x06, "unknown-0x06" },
  { 0x07, "unknown-0x07" },
  { 0x08, "unknown-0x08" },
  { 0x09, "unknown-0x09" },
  { 0x0A, "unknown-0x0A" },
  { 0x0B, "unknown-0x0B" },
  { 0x0C, "unknown-0x0C" },
  { 0x0D, "unknown-0x0D" },
  { 0x0E, "unknown-0x0E" },
  { 0x0F, "unknown-0x0F" },
  { 0x10, "unknown-0x10" },
  { 0x11, "unknown-0x11" },
  { 0x12, "unknown-0x12" },
  { 0x13, "unknown-0x13" },
  { 0x14, "unknown-0x14" },
  { 0x15, "unknown-0x15" },
  { 0x16, "unknown-0x16" },
  { 0x17, "unknown-0x17" },
  { 0x18, "unknown-0x18" },
  { 0x19, "unknown-0x19" },
  { 0x1A, "unknown-0x1A" },
  { 0x1B, "unknown-0x1B" },
  { 0x1C, "unknown-0x1C" },
  { 0x1D, "unknown-0x1D" },
  { 0x1E, "unknown-0x1E" },
  { 0x1F, "unknown-0x1F" },
  { 0x20, "unknown-0x20" },
  { 0x21, "unknown-0x21" },
  { 0x22, "unknown-0x22" },
  { 0x23, "unknown-0x23" },
  { 0x24, "unknown-0x24" },
  { 0x25, "unknown-0x25" },
  { 0x26, "unknown-0x26" },
  { 0x27, "unknown-0x27" },
  { 0x28, "unknown-0x28" },
  { 0x29, "unknown-0x29" },
  { 0x2A, "unknown-0x2A" },
  { 0x2B, "unknown-0x2B" },
  { 0x2C, "unknown-0x2C" },
  { 0x2D, "unknown-0x2D" },
  { 0x2E, "unknown-0x2E" },
  { 0x2F, "unknown-0x2F" },
  { 0x30, "unknown-0x30" },
  { 0x31, "unknown-0x31" },
  { 0x32, "unknown-0x32" },
  { 0x33, "unknown-0x33" },
  { 0x34, "unknown-0x34" },
  { 0x35, "unknown-0x35" },
  { 0x36, "unknown-0x36" },
  { 0x37, "unknown-0x37" },
  { 0x38, "unknown-0x38" },
  { 0x39, "unknown-0x39" },
  { 0x3A, "unknown-0x3A" },
  { 0x3B, "unknown-0x3B" },
  { 0x3C, "unknown-0x3C" },
  { 0x3D, "unknown-0x3D" },
  { 0x3E, "unknown-0x3E" },
  { 0x3F, "unknown-0x3F" },
  { 0x40, "unknown-0x40" },
  { 0x41, "unknown-0x41" },
  { 0x42, "unknown-0x42" },
  { 0x43, "unknown-0x43" },
  { 0x44, "unknown-0x44" },
  { 0x45, "unknown-0x45" },
  { 0x46, "unknown-0x46" },
  { 0x47, "unknown-0x47" },
  { 0x48, "unknown-0x48" },
  { 0x49, "unknown-0x49" },
  { 0x4A, "unknown-0x4A" },
  { 0x4B, "unknown-0x4B" },
  { 0x4C, "unknown-0x4C" },
  { 0x4D, "unknown-0x4D" },
  { 0x4E, "unknown-0x4E" },
  { 0x4F, "unknown-0x4F" },
  { 0x50, "unknown-0x50" },
  { 0x51, "unknown-0x51" },
  { 0x52, "unknown-0x52" },
  { 0x53, "unknown-0x53" },
  { 0x54, "unknown-0x54" },
  { 0x55, "unknown-0x55" },
  { 0x56, "unknown-0x56" },
  { 0x57, "unknown-0x57" },
  { 0x58, "unknown-0x58" },
  { 0x59, "unknown-0x59" },
  { 0x5A, "unknown-0x5A" },
  { 0x5B, "unknown-0x5B" },
  { 0x5C, "unknown-0x5C" },
  { 0x5D, "unknown-0x5D" },
  { 0x5E, "unknown-0x5E" },
  { 0x5F, "unknown-0x5F" },
  { 0x60, "unknown-0x60" },
  { 0x61, "unknown-0x61" },
  { 0x62, "unknown-0x62" },
  { 0x63, "unknown-0x63" },
  { 0x64, "unknown-0x64" },
  { 0x65, "unknown-0x65" },
  { 0x66, "unknown-0x66" },
  { 0x67, "unknown-0x67" },
  { 0x68, "unknown-0x68" },
  { 0x69, "unknown-0x69" },
  { 0x6A, "unknown-0x6A" },
  { 0x6B, "unknown-0x6B" },
  { 0x6C, "unknown-0x6C" },
  { 0x6D, "unknown-0x6D" },
  { 0x6E, "unknown-0x6E" },
  { 0x6F, "unknown-0x6F" },
  { 0x70, "unknown-0x70" },
  { 0x71, "unknown-0x71" },
  { 0x72, "unknown-0x72" },
  { 0x73, "unknown-0x73" },
  { 0x74, "unknown-0x74" },
  { 0x75, "unknown-0x75" },
  { 0x76, "unknown-0x76" },
  { 0x77, "unknown-0x77" },
  { 0x78, "unknown-0x78" },
  { 0x79, "unknown-0x79" },
  { 0x7A, "unknown-0x7A" },
  { 0x7B, "unknown-0x7B" },
  { 0x7C, "unknown-0x7C" },
  { 0x7D, "unknown-0x7D" },
  { 0x7E, "unknown-0x7E" },
  { 0x7F, "unknown-0x7F" },
  { 0x80, "unknown-0x80" },
  { 0x81, "unknown-0x81" },
  { 0x82, "unknown-0x82" },
  { 0x83, "unknown-0x83" },
  { 0x84, "unknown-0x84" },
  { 0x85, "unknown-0x85" },
  { 0x86, "unknown-0x86" },
  { 0x87, "unknown-0x87" },
  { 0x88, "unknown-0x88" },
  { 0x89, "unknown-0x89" },
  { 0x8A, "unknown-0x8A" },
  { 0x8B, "unknown-0x8B" },
  { 0x8C, "unknown-0x8C" },
  { 0x8D, "unknown-0x8D" },
  { 0x8E, "unknown-0x8E" },
  { 0x8F, "unknown-0x8F" },
  { 0x90, "unknown-0x90" },
  { 0x91, "unknown-0x91" },
  { 0x92, "unknown-0x92" },
  { 0x93, "unknown-0x93" },
  { 0x94, "unknown-0x94" },
  { 0x95, "unknown-0x95" },
  { 0x96, "unknown-0x96" },
  { 0x97, "unknown-0x97" },
  { 0x98, "unknown-0x98" },
  { 0x99, "unknown-0x99" },
  { 0x9A, "unknown-0x9A" },
  { 0x9B, "unknown-0x9B" },
  { 0x9C, "unknown-0x9C" },
  { 0x9D, "unknown-0x9D" },
  { 0x9E, "unknown-0x9E" },
  { 0x9F, "unknown-0x9F" },
  { 0xA0, "unknown-0xA0" },
  { 0xA1, "unknown-0xA1" },
  { 0xA2, "unknown-0xA2" },
  { 0xA3, "unknown-0xA3" },
  { 0xA4, "unknown-0xA4" },
  { 0xA5, "unknown-0xA5" },
  { 0xA6, "unknown-0xA6" },
  { 0xA7, "unknown-0xA7" },
  { 0xA8, "unknown-0xA8" },
  { 0xA9, "unknown-0xA9" },
  { 0xAA, "unknown-0xAA" },
  { 0xAB, "unknown-0xAB" },
  { 0xAC, "unknown-0xAC" },
  { 0xAD, "unknown-0xAD" },
  { 0xAE, "unknown-0xAE" },
  { 0xAF, "unknown-0xAF" },
  { 0xB0, "unknown-0xB0" },
  { 0xB1, "unknown-0xB1" },
  { 0xB2, "unknown-0xB2" },
  { 0xB3, "unknown-0xB3" },
  { 0xB4, "unknown-0xB4" },
  { 0xB5, "unknown-0xB5" },
  { 0xB6, "unknown-0xB6" },
  { 0xB7, "unknown-0xB7" },
  { 0xB8, "unknown-0xB8" },
  { 0xB9, "unknown-0xB9" },
  { 0xBA, "unknown-0xBA" },
  { 0xBB, "unknown-0xBB" },
  { 0xBC, "unknown-0xBC" },
  { 0xBD, "unknown-0xBD" },
  { 0xBE, "unknown-0xBE" },
  { 0xBF, "unknown-0xBF" },
  { 0xC0, "unknown-0xC0" },
  { 0xC1, "unknown-0xC1" },
  { 0xC2, "unknown-0xC2" },
  { 0xC3, "unknown-0xC3" },
  { 0xC4, "unknown-0xC4" },
  { 0xC5, "unknown-0xC5" },
  { 0xC6, "unknown-0xC6" },
  { 0xC7, "unknown-0xC7" },
  { 0xC8, "unknown-0xC8" },
  { 0xC9, "unknown-0xC9" },
  { 0xCA, "unknown-0xCA" },
  { 0xCB, "unknown-0xCB" },
  { 0xCC, "unknown-0xCC" },
  { 0xCD, "unknown-0xCD" },
  { 0xCE, "unknown-0xCE" },
  { 0xCF, "unknown-0xCF" },
  { 0xD0, "unknown-0xD0" },
  { 0xD1, "unknown-0xD1" },
  { 0xD2, "unknown-0xD2" },
  { 0xD3, "unknown-0xD3" },
  { 0xD4, "unknown-0xD4" },
  { 0xD5, "unknown-0xD5" },
  { 0xD6, "unknown-0xD6" },
  { 0xD7, "unknown-0xD7" },
  { 0xD8, "unknown-0xD8" },
  { 0xD9, "unknown-0xD9" },
  { 0xDA, "unknown-0xDA" },
  { 0xDB, "unknown-0xDB" },
  { 0xDC, "unknown-0xDC" },
  { 0xDD, "unknown-0xDD" },
  { 0xDE, "unknown-0xDE" },
  { 0xDF, "unknown-0xDF" },
  { 0xE0, "unknown-0xE0" },
  { 0xE1, "unknown-0xE1" },
  { 0xE2, "unknown-0xE2" },
  { 0xE3, "unknown-0xE3" },
  { 0xE4, "unknown-0xE4" },
  { 0xE5, "unknown-0xE5" },
  { 0xE6, "unknown-0xE6" },
  { 0xE7, "unknown-0xE7" },
  { 0xE8, "unknown-0xE8" },
  { 0xE9, "unknown-0xE9" },
  { 0xEA, "unknown-0xEA" },
  { 0xEB, "unknown-0xEB" },
  { 0xEC, "unknown-0xEC" },
  { 0xED, "unknown-0xED" },
  { 0xEE, "unknown-0xEE" },
  { 0xEF, "unknown-0xEF" },
  { 0xF0, "unknown-0xF0" },
  { 0xF1, "unknown-0xF1" },
  { 0xF2, "unknown-0xF2" },
  { 0xF3, "unknown-0xF3" },
  { 0xF4, "unknown-0xF4" },
  { 0xF5, "unknown-0xF5" },
  { 0xF6, "unknown-0xF6" },
  { 0xF7, "unknown-0xF7" },
  { 0xF8, "unknown-0xF8" },
  { 0xF9, "unknown-0xF9" },
  { 0xFA, "unknown-0xFA" },
  { 0xFB, "unknown-0xFB" },
  { 0xFC, "unknown-0xFC" },
  { 0xFD, "unknown-0xFD" },
  { 0xFE, "unknown-0xFE" },
  { 0xFF, "unknown-0xFF" },
  { 0x00, NULL },
};
static const char *decode_smb2_name(guint8 cmd)
{
  return(smb2_cmd_vals[cmd].strptr);
}




static void
dissect_smb2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int offset=0;
	int cmd, response;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMB2");
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, proto_smb2, tvb, offset,
			-1, FALSE);
		tree = proto_item_add_subtree(item, ett_smb2);
	}

	/* Decode the header */
	/* SMB2 marker */
	proto_tree_add_text(tree, tvb, offset, 4, "Server Component: SMB2");
	offset += 4;  /* Skip the marker */

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 8, FALSE);
	offset += 8;

	/* CMD either 1 or two bytes*/
	cmd=tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_cmd, tvb, offset, 1, FALSE);
	offset += 1;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 3, FALSE);
	offset += 3;

	/* flags */
	response=tvb_get_guint8(tvb, offset)&SMB2_FLAGS_RESPONSE;
	proto_tree_add_item(tree, hf_smb2_flags_response, tvb, offset, 1, FALSE);
	offset += 1;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 7, FALSE);
	offset += 7;

	/* Multiplex ID either 1 2 or 4 bytes*/
	proto_tree_add_item(tree, hf_smb2_mpxid, tvb, offset, 1, FALSE);
	offset += 1;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 11, FALSE);
	offset += 11;

	/* Tree ID either 1 2 or 4 bytes*/
	proto_tree_add_item(tree, hf_smb2_tid, tvb, offset, 1, FALSE);
	offset += 1;

	if (check_col(pinfo->cinfo, COL_INFO)){
	  col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s",
			decode_smb2_name(cmd),
			response?"Response":"Request");
	}

	/* Decode the payload */
	/* ... */
}

static gboolean
dissect_smb2_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	/* must check that this really is a smb2 packet */
	if (!tvb_bytes_exist(tvb, 0, 4))
		return FALSE;

	if( (tvb_get_guint8(tvb, 0) != 0xfe)
	    || (tvb_get_guint8(tvb, 1) != 'S')
	    || (tvb_get_guint8(tvb, 2) != 'M')
	    || (tvb_get_guint8(tvb, 3) != 'B') ){
		return FALSE;
	}

	dissect_smb2(tvb, pinfo, parent_tree);
	return TRUE;
}

void
proto_register_smb2(void)
{
	static hf_register_info hf[] = {
	{ &hf_smb2_cmd,
		{ "Command", "smb2.cmd", FT_UINT8, BASE_DEC,
		VALS(smb2_cmd_vals), 0, "SMB2 Command Opcode", HFILL }},
	{ &hf_smb2_mpxid,
		{ "Multiplex Id", "smb2.mpxid", FT_UINT8, BASE_DEC,
		NULL, 0, "SMB2 Multiplex Id", HFILL }},
	{ &hf_smb2_tid,
		{ "Tree Id", "smb2.tid", FT_UINT8, BASE_DEC,
		NULL, 0, "SMB2 Tree Id", HFILL }},
	{ &hf_smb2_flags_response,
		{ "Response", "smb2.flags.response", FT_BOOLEAN, 8,
		TFS(&tfs_flags_response), SMB2_FLAGS_RESPONSE, "Whether this is an SMB2 Request or Response", HFILL }},
	{ &hf_smb2_unknown,
		{ "unknown", "smb2.unknown", FT_BYTES, BASE_HEX,
		NULL, 0, "Unknown bytes", HFILL }},
	};

	static gint *ett[] = {
		&ett_smb2,
	};

	proto_smb2 = proto_register_protocol("SMB2 (Server Message Block Protocol version 2)",
	    "SMB2", "smb2");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_smb2, hf, array_length(hf));
}

void
proto_reg_handoff_smb2(void)
{
	heur_dissector_add("netbios", dissect_smb2_heur, proto_smb2);
}
