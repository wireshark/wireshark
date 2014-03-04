/* packet-aim-location.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Location
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
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

#include "packet-aim.h"

void proto_register_aim_location(void);
void proto_reg_handoff_aim_location(void);

/* SNAC families */
#define FAMILY_LOCATION   0x0002

#define AIM_LOCATION_RIGHTS_TLV_MAX_PROFILE_LENGTH 	0x0001
#define AIM_LOCATION_RIGHTS_TLV_MAX_CAPABILITIES 	0x0002

static const aim_tlv aim_location_rights_tlvs[] = {
	{ AIM_LOCATION_RIGHTS_TLV_MAX_PROFILE_LENGTH, "Max Profile Length", dissect_aim_tlv_value_uint16 },
	{ AIM_LOCATION_RIGHTS_TLV_MAX_CAPABILITIES, "Max capabilities", dissect_aim_tlv_value_uint16 },
	{ 0, NULL, NULL }
};

#define AIM_LOCATE_TAG_TLV_SIG_TYPE			0x0001
#define AIM_LOCATE_TAG_TLV_SIG_DATA			0x0002
#define AIM_LOCATE_TAG_TLV_UNAVAILABLE_TYPE		0x0003
#define AIM_LOCATE_TAG_TLV_UNAVAILABLE_DATA		0x0004
#define AIM_LOCATE_TAG_TLV_CAPABILITIES			0x0005
#define AIM_LOCATE_TAG_TLV_SIG_TIME			0x000A
#define AIM_LOCATE_TAG_TLV_UNAVAILABLE_TIME		0x000B
#define AIM_LOCATE_TAG_TLV_SUPPORT_HOST_SIG		0x000C
#define AIM_LOCATE_TAG_TLV_HTML_INFO_TYPE		0x000D
#define AIM_LOCATE_TAG_TLV_HTML_INFO_DATA		0x000E

static const aim_tlv aim_locate_tags_tlvs[] = {
	{ AIM_LOCATE_TAG_TLV_SIG_TYPE,	       "Signature MIME Type"	      , dissect_aim_tlv_value_string },
	{ AIM_LOCATE_TAG_TLV_SIG_DATA,	       "Signature Data"		      , dissect_aim_tlv_value_string },
	{ AIM_LOCATE_TAG_TLV_UNAVAILABLE_TYPE, "Away Message MIME Type"	      , dissect_aim_tlv_value_string },
	{ AIM_LOCATE_TAG_TLV_UNAVAILABLE_DATA, "Away Message Data"	      , dissect_aim_tlv_value_string },
	{ AIM_LOCATE_TAG_TLV_CAPABILITIES,     "Client Capabilities"	      , dissect_aim_tlv_value_client_capabilities },
	{ AIM_LOCATE_TAG_TLV_SIG_TIME,	       "Signature Time"		      , dissect_aim_tlv_value_time },
	{ AIM_LOCATE_TAG_TLV_UNAVAILABLE_TIME, "Away Message Time"	      , dissect_aim_tlv_value_time },
	{ AIM_LOCATE_TAG_TLV_SUPPORT_HOST_SIG, "Enable Server Based Profiles" , dissect_aim_tlv_value_uint8 },
	{ AIM_LOCATE_TAG_TLV_HTML_INFO_TYPE,   "Host Based Buddy MIME Type"   , dissect_aim_tlv_value_string },
	{ AIM_LOCATE_TAG_TLV_HTML_INFO_DATA,   "Host Bases Buddy Data"	      , dissect_aim_tlv_value_string },
	{ 0, NULL, NULL }
};

#define FAMILY_LOCATION_USERINFO_INFOTYPE_GENERALINFO  0x0001
#define FAMILY_LOCATION_USERINFO_INFOTYPE_AWAYMSG      0x0003
#define FAMILY_LOCATION_USERINFO_INFOTYPE_CAPS         0x0005

static const value_string aim_snac_location_request_user_info_infotypes[] = {
	{ FAMILY_LOCATION_USERINFO_INFOTYPE_GENERALINFO, "Request General Info" },
	{ FAMILY_LOCATION_USERINFO_INFOTYPE_AWAYMSG,	 "Request Away Message" },
	{ FAMILY_LOCATION_USERINFO_INFOTYPE_CAPS,	 "Request Capabilities" },
	{ 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_aim_location = -1;
static int hf_aim_snac_location_request_user_info_infotype = -1;
static int hf_aim_userinfo_warninglevel = -1;
static int hf_aim_buddyname_len = -1;
static int hf_aim_buddyname = -1;

/* Initialize the subtree pointers */
static gint ett_aim_location    = -1;

static int dissect_aim_location_rightsinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *loc_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, loc_tree, aim_location_rights_tlvs);
}

static int dissect_aim_location_setuserinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *loc_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, loc_tree, aim_locate_tags_tlvs);
}

static int dissect_aim_location_watcher_notification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *loc_tree)
{
	int offset = 0;
	while (tvb_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_buddyname(tvb, pinfo, offset, loc_tree);
	}
	return offset;
}

static int dissect_aim_location_user_info_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *loc_tree)
{
	return dissect_aim_buddyname(tvb, pinfo, 4, loc_tree);
}

static int dissect_aim_snac_location_request_user_information(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int    offset		= 0;
	guint8 buddyname_length = 0;

	/* Info Type */
	proto_tree_add_item(tree, hf_aim_snac_location_request_user_info_infotype,
						tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Buddy Name length */
	buddyname_length = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_aim_buddyname_len, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Buddy name */
	proto_tree_add_item(tree, hf_aim_buddyname, tvb, offset, buddyname_length, ENC_UTF_8|ENC_NA);
	offset += buddyname_length;

	return offset;
}

static int dissect_aim_snac_location_user_information(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int    offset		= 0;
	guint8 buddyname_length = 0;

	/* Buddy Name length */
	buddyname_length = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_aim_buddyname_len, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Buddy name */
	proto_tree_add_item(tree, hf_aim_buddyname, tvb, offset, buddyname_length, ENC_UTF_8|ENC_NA);
	offset += buddyname_length;

	/* Warning level */
	proto_tree_add_item(tree, hf_aim_userinfo_warninglevel, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	offset = dissect_aim_tlv_list(tvb, pinfo, offset, tree, aim_onlinebuddy_tlvs);

	return dissect_aim_tlv_sequence(tvb, pinfo, offset, tree, aim_locate_tags_tlvs);
}

static const aim_subtype aim_fnac_family_location[] = {
	{ 0x0001, "Error"		 , dissect_aim_snac_error },
	{ 0x0002, "Request Rights"       , NULL },
	{ 0x0003, "Rights Info"		 , dissect_aim_location_rightsinfo },
	{ 0x0004, "Set User Info"	 , dissect_aim_location_setuserinfo },
	{ 0x0005, "Request User Info"	 , dissect_aim_snac_location_request_user_information },
	{ 0x0006, "User Info"		 , dissect_aim_snac_location_user_information },
	{ 0x0007, "Watcher Subrequest"   , NULL },
	{ 0x0008, "Watcher Notification" , dissect_aim_location_watcher_notification },
	{ 0x0015, "User Info Query"	 , dissect_aim_location_user_info_query },
	{ 0, NULL, NULL }
};



void
proto_register_aim_location(void)
{

	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_aim_buddyname_len,
		  { "Buddyname len", "aim_location.buddynamelen", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_buddyname,
		  { "Buddy Name", "aim_location.buddyname", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_userinfo_warninglevel,
		  { "Warning Level", "aim_location.userinfo.warninglevel", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_aim_snac_location_request_user_info_infotype,
		  { "Infotype", "aim_location.snac.request_user_info.infotype", FT_UINT16, BASE_HEX, VALS(aim_snac_location_request_user_info_infotypes), 0x0,
				NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_aim_location,
	};

	/* Register the protocol name and description */
	proto_aim_location = proto_register_protocol("AIM Location", "AIM Location", "aim_location");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_aim_location, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_location(void)
{
	aim_init_family(proto_aim_location, ett_aim_location, FAMILY_LOCATION, aim_fnac_family_location);
}
