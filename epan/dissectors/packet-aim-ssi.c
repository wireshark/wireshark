/* packet-aim-ssi.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC SSI
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
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
#include <epan/strutil.h>

#include "packet-aim.h"

#define FAMILY_SSI        0x0013


#define FAMILY_SSI_TYPE_BUDDY         0x0000
#define FAMILY_SSI_TYPE_GROUP         0x0001
#define FAMILY_SSI_TYPE_PERMIT        0x0002
#define FAMILY_SSI_TYPE_DENY          0x0003
#define FAMILY_SSI_TYPE_PDINFO        0x0004
#define FAMILY_SSI_TYPE_PRESENCEPREFS 0x0005
#define FAMILY_SSI_TYPE_ICONINFO      0x0014

static const value_string aim_fnac_family_ssi_types[] = {
	{ FAMILY_SSI_TYPE_BUDDY, "Buddy" },
	{ FAMILY_SSI_TYPE_GROUP, "Group" },
	{ FAMILY_SSI_TYPE_PERMIT, "Permit" },
	{ FAMILY_SSI_TYPE_DENY, "Deny" },
	{ FAMILY_SSI_TYPE_PDINFO, "PDINFO" },
	{ FAMILY_SSI_TYPE_PRESENCEPREFS, "Presence Preferences" },
	{ FAMILY_SSI_TYPE_ICONINFO, "Icon Info" },
	{ 0, NULL }
};

#define SSI_RIGHTSINFO_TLV_MAX_ITEMS	0x0004

static const aim_tlv aim_ssi_rightsinfo_tlvs[] = {
	{ SSI_RIGHTSINFO_TLV_MAX_ITEMS, "Maximums For Items", dissect_aim_tlv_value_bytes },
	{ 0, NULL, NULL },
};

/* Initialize the protocol and registered fields */
static int proto_aim_ssi = -1;
static int hf_aim_fnac_subtype_ssi_version = -1;
static int hf_aim_fnac_subtype_ssi_numitems = -1;
static int hf_aim_fnac_subtype_ssi_last_change_time = -1;
static int hf_aim_fnac_subtype_ssi_buddyname_len = -1;
static int hf_aim_fnac_subtype_ssi_buddyname_len8 = -1;
static int hf_aim_fnac_subtype_ssi_buddyname = -1;
static int hf_aim_fnac_subtype_ssi_gid = -1;
static int hf_aim_fnac_subtype_ssi_bid = -1;
static int hf_aim_fnac_subtype_ssi_type = -1;
static int hf_aim_fnac_subtype_ssi_tlvlen = -1;
static int hf_aim_fnac_subtype_ssi_data = -1;
static int hf_aim_fnac_subtype_ssi_reason_str_len = -1;
static int hf_aim_fnac_subtype_ssi_reason_str = -1;
static int hf_aim_fnac_subtype_ssi_grant_auth_unkn = -1;
static int hf_aim_fnac_subtype_ssi_allow_auth = -1;

/* Initialize the subtree pointers */
static gint ett_aim_ssi = -1;
static gint ett_ssi = -1;

/** Calculate size of SSI entry
 * Size of SSI entry can be calculated as:
 *   sizeof(buddy name length field) = sizeof(guint16) = 2
 * + sizeof(buddy name string) = buddy name length field = N
 * + sizeof(group ID) = sizeof(guint16) = 2
 * + sizeof(buddy ID) = sizeof(guint16) = 2
 * + sizeof(buddy type) = sizeof(guint16) = 2
 * + sizeof(TLV length) = sizeof(guint16) = 2
 * + sizeof(TLVs) = TLV length = M
 * = 2 + N + 2 * 4 + M
 */
static int calc_ssi_entry_size(tvbuff_t *tvb, int offset)
{
	gint ssi_entry_size = 2 + tvb_get_ntohs(tvb, offset) + 2 * 3;
	ssi_entry_size += tvb_get_ntohs(tvb, offset + ssi_entry_size) + 2;
	return ssi_entry_size;
}

static int dissect_ssi_item(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *ssi_entry)
{
	guint16 buddyname_length = 0;
	int endoffset;
	guint16 tlv_len = 0;

	/* Buddy Name Length */
	buddyname_length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_buddyname_len, tvb, offset, 2, FALSE);
	offset += 2;

	/* Buddy Name */
	if (buddyname_length > 0) {
		proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_buddyname, tvb, offset, buddyname_length, FALSE);
		offset += buddyname_length;
	}

	/* Buddy group ID */
	proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_gid, tvb, offset, 2, FALSE);
	offset += 2;

	/* Buddy ID */
	proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_bid, tvb, offset, 2, FALSE);
	offset += 2;

	/* Buddy Type */
	proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_type, tvb, offset, 2, FALSE);
	offset += 2;

	/* Size of the following TLV in bytes (as opposed to the number of
	   TLV objects in the chain) */
	tlv_len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_tlvlen, tvb, offset, 2, FALSE);
	offset += 2;

	endoffset = offset;
	/* For now, we just dump the TLV contents as-is, since there is not a
	   TLV dissection utility that works based on total chain length */
	while(endoffset < offset+tlv_len) {
		endoffset = dissect_aim_tlv(tvb, pinfo, endoffset, ssi_entry, aim_client_tlvs);
	}
	return endoffset;
}

static int dissect_ssi_ssi_item(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ssi_entry)
{
	return dissect_ssi_item(tvb, pinfo, 0, ssi_entry);
}

static int dissect_ssi_ssi_items(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	gint ssi_entry_size;
	proto_item *ti;
	proto_tree *ssi_entry = NULL;
	int size = tvb_length(tvb);
	while (size > offset)
	{
		ssi_entry_size = calc_ssi_entry_size(tvb, offset);
		ti = proto_tree_add_text(tree, tvb, offset, ssi_entry_size, "SSI Entry");
		ssi_entry = proto_item_add_subtree(ti, ett_aim_ssi);
		offset = dissect_ssi_item(tvb, pinfo, offset, ssi_entry);
	}
	return offset;
}

static int dissect_aim_ssi_rightsinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ssi_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, ssi_tree, aim_ssi_rightsinfo_tlvs);
}

static int dissect_aim_ssi_was_added(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ssi_tree)
{
	return dissect_aim_buddyname(tvb, pinfo, 0, ssi_tree);
}

static int dissect_aim_snac_ssi_time_and_items_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;

	/* get timestamp */
	nstime_t tmptime;
	tmptime.secs = tvb_get_ntohl(tvb, offset);
	tmptime.nsecs = 0;
	proto_tree_add_time(tree, hf_aim_fnac_subtype_ssi_last_change_time, tvb, offset, 4, &tmptime);
	offset += 4;

	/* get number of SSI items */
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_numitems, tvb, offset, 2, FALSE);
	offset += 2;

	return offset;
}

static int dissect_aim_snac_ssi_list(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	proto_item *ti;
	proto_tree *ssi_entry = NULL;
	guint16 num_items, i;
	nstime_t tmptime;
	gint ssi_entry_size;

	/* SSI Version */
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_version, tvb, offset, 1, FALSE);
	offset += 1;

	/* Number of items */
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_numitems, tvb, offset, 2, FALSE);
	num_items = tvb_get_ntohs(tvb, offset);
	offset += 2;

	for(i = 0; i < num_items; i++) {
		ssi_entry_size = calc_ssi_entry_size(tvb, offset);
		ti = proto_tree_add_text(tree, tvb, offset, ssi_entry_size, "SSI Entry %u", i);
		ssi_entry = proto_item_add_subtree(ti, ett_aim_ssi);
		offset = dissect_ssi_item(tvb, pinfo, offset, ssi_entry);
	}
	tmptime.secs = tvb_get_ntohl(tvb, offset);
	tmptime.nsecs = 0;
	proto_tree_add_time(tree, hf_aim_fnac_subtype_ssi_last_change_time, tvb, offset, 4, &tmptime);

	return offset;
}

static int dissect_aim_snac_ssi_auth_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	guint16 reason_length;
	/*guint16 unknown;*/

	/* get buddy length (1 byte) */
	guint8 buddyname_length = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_buddyname_len8, tvb, offset, 1, FALSE);
	offset += 1;

	/* show buddy name */
	if (buddyname_length > 0) {
		proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_buddyname, tvb, offset, buddyname_length, FALSE);
		offset += buddyname_length;
	}
	/* get reason message length (2 bytes) */
	reason_length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_reason_str_len, tvb, offset, 2, FALSE);
	offset += 2;

	/* show reason message if present */
	if (reason_length > 0) {
		proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_reason_str, tvb, offset, reason_length, FALSE);
		offset += reason_length;
	}

	/* unknown (always 0x0000 ???) */
	/*unknown = tvb_get_ntohs(tvb, offset);*/
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_grant_auth_unkn, tvb, offset, 2, FALSE);
	offset += 2;

	return offset;
}

static int dissect_aim_snac_ssi_auth_reply(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	guint16 reason_length;

	/* get buddy length (1 byte) */
	guint8 buddyname_length = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_buddyname_len8, tvb, offset, 1, FALSE);
	offset += 1;

	/* show buddy name */
	if (buddyname_length > 0) {
		proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_buddyname, tvb, offset, buddyname_length, FALSE);
		offset += buddyname_length;
	}

	/* accept/reject authorization flag */
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_allow_auth, tvb, offset, 1, FALSE);
	offset += 1;

	/* get reason message length (2 bytes) */
	reason_length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_reason_str_len, tvb, offset, 2, FALSE);
	offset += 2;

	/* show reason message if present */
	if (reason_length > 0) {
		proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_reason_str, tvb, offset, reason_length, FALSE);
		offset += reason_length;
	}

	return offset;
}


static const aim_subtype aim_fnac_family_ssi[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Request Rights", NULL },
	{ 0x0003, "Rights Info", dissect_aim_ssi_rightsinfo },
	{ 0x0004, "Request List (first time)", NULL },
	{ 0x0005, "Request List", dissect_aim_snac_ssi_time_and_items_num },
	{ 0x0006, "List", dissect_aim_snac_ssi_list },
	{ 0x0007, "Activate", NULL },
	{ 0x0008, "Add Buddy", dissect_ssi_ssi_item },
	{ 0x0009, "Modify Buddy", dissect_ssi_ssi_items },
	{ 0x000a, "Delete Buddy", dissect_ssi_ssi_item },
	{ 0x000e, "Server Ack", dissect_aim_ssi_result },
	{ 0x000f, "No List", dissect_aim_snac_ssi_time_and_items_num },
	{ 0x0011, "Edit Start", NULL },
	{ 0x0012, "Edit Stop", NULL },
	{ 0x0014, "Grant Future Authorization to Buddy", dissect_aim_snac_ssi_auth_request },
	{ 0x0015, "Future Authorization Granted", dissect_aim_snac_ssi_auth_request },
	{ 0x0018, "Send Authentication Request", dissect_aim_snac_ssi_auth_request },
	{ 0x0019, "Authentication Request", dissect_aim_snac_ssi_auth_request },
	{ 0x001a, "Send Authentication Reply", dissect_aim_snac_ssi_auth_reply },
	{ 0x001b, "Authentication Reply", dissect_aim_snac_ssi_auth_reply },
	{ 0x001c, "Remote User Added Client To List", dissect_aim_ssi_was_added },
	{ 0, NULL, NULL }
};


/* Register the protocol with Wireshark */
void
proto_register_aim_ssi(void)
{
	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_aim_fnac_subtype_ssi_version,
			{ "SSI Version", "aim_ssi.fnac.version", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_numitems,
			{ "SSI Object count", "aim_ssi.fnac.numitems", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_last_change_time,
			{ "SSI Last Change Time", "aim_ssi.fnac.last_change_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_buddyname_len,
			{ "SSI Buddy Name length", "aim_ssi.fnac.buddyname_len", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_buddyname,
			{ "Buddy Name", "aim_ssi.fnac.buddyname", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_gid,
			{ "SSI Buddy Group ID", "aim_ssi.fnac.gid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_bid,
			{ "SSI Buddy ID", "aim_ssi.fnac.bid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_type,
			{ "SSI Buddy type", "aim_ssi.fnac.type", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_ssi_types), 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_tlvlen,
			{ "SSI TLV Len", "aim_ssi.fnac.tlvlen", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_data,
			{ "SSI Buddy Data", "aim_ssi.fnac.data", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_buddyname_len8,
			{ "SSI Buddy Name length", "aim_ssi.fnac.buddyname_len8", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_reason_str_len,
			{ "Reason Message length", "aim_ssi.fnac.reason_len", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_reason_str,
			{ "Reason Message", "aim_ssi.fnac.reason", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_grant_auth_unkn,
			{ "Unknown", "aim_ssi.fnac.auth_unkn", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_fnac_subtype_ssi_allow_auth,
			{ "Allow flag", "aim_ssi.fnac.allow_auth_flag", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_aim_ssi,
		&ett_ssi,
	};

	/* Register the protocol name and description */
	proto_aim_ssi = proto_register_protocol("AIM Server Side Info", "AIM SSI", "aim_ssi");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_aim_ssi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_aim_ssi(void)
{
	aim_init_family(proto_aim_ssi, ett_aim_ssi, FAMILY_SSI, aim_fnac_family_ssi);
}
