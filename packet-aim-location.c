/* packet-aim-location.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Location
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
 *
 * $Id: packet-aim-location.c,v 1.4 2004/04/26 18:21:09 obiot Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-aim.h"

/* SNAC families */
#define FAMILY_LOCATION   0x0002

/* Family Location Services */
#define FAMILY_LOCATION_ERROR         0x0001
#define FAMILY_LOCATION_REQRIGHTS     0x0002
#define FAMILY_LOCATION_RIGHTSINFO    0x0003
#define FAMILY_LOCATION_SETUSERINFO   0x0004
#define FAMILY_LOCATION_REQUSERINFO   0x0005
#define FAMILY_LOCATION_USERINFO      0x0006
#define FAMILY_LOCATION_WATCHERSUBREQ 0x0007
#define FAMILY_LOCATION_WATCHERNOT    0x0008
#define FAMILY_LOCATION_DEFAULT       0xffff

static const value_string aim_fnac_family_location[] = {
  { FAMILY_LOCATION_ERROR, "Error" },
  { FAMILY_LOCATION_REQRIGHTS, "Request Rights" },
  { FAMILY_LOCATION_RIGHTSINFO, "Rights Info" },
  { FAMILY_LOCATION_SETUSERINFO, "Set User Info" },
  { FAMILY_LOCATION_REQUSERINFO, "Request User Info" },
  { FAMILY_LOCATION_USERINFO, "User Info" },
  { FAMILY_LOCATION_WATCHERSUBREQ, "Watcher Subrequest" },
  { FAMILY_LOCATION_WATCHERNOT, "Watcher Notification" },
  { FAMILY_LOCATION_DEFAULT, "Location Default" },
  { 0, NULL }
};

#define FAMILY_LOCATION_USERINFO_INFOENCODING  0x0001
#define FAMILY_LOCATION_USERINFO_INFOMSG       0x0002
#define FAMILY_LOCATION_USERINFO_AWAYENCODING  0x0003
#define FAMILY_LOCATION_USERINFO_AWAYMSG       0x0004
#define FAMILY_LOCATION_USERINFO_CAPS          0x0005

static const aim_tlv msg_tlv[] = {
  { FAMILY_LOCATION_USERINFO_INFOENCODING, "Info Msg Encoding", dissect_aim_tlv_value_string},
  { FAMILY_LOCATION_USERINFO_INFOMSG, "Info Message", dissect_aim_tlv_value_string },
  { FAMILY_LOCATION_USERINFO_AWAYENCODING, "Away Msg Encoding", dissect_aim_tlv_value_string },
  { FAMILY_LOCATION_USERINFO_AWAYMSG, "Away Message", dissect_aim_tlv_value_string },
  { FAMILY_LOCATION_USERINFO_CAPS, "Capabilities", dissect_aim_tlv_value_bytes },
  { 0, "Unknown", 0 }
};

#define AIM_LOCATION_RIGHTS_TLV_MAX_PROFILE_LENGTH 	0x0001
#define AIM_LOCATION_RIGHTS_TLV_MAX_CAPABILITIES 	0x0002
#define AIM_LOCATION_RIGHTS_TLV_CLIENT_CAPABILITIES 0x0005

static const aim_tlv location_rights_tlvs[] = {
  { AIM_LOCATION_RIGHTS_TLV_MAX_PROFILE_LENGTH, "Max Profile Length", dissect_aim_tlv_value_uint16 },
  { AIM_LOCATION_RIGHTS_TLV_MAX_CAPABILITIES, "Max capabilities", dissect_aim_tlv_value_uint16 },
  { AIM_LOCATION_RIGHTS_TLV_CLIENT_CAPABILITIES, "Client capabilities", dissect_aim_tlv_value_client_capabilities },
  { 0, "Unknown", NULL }
};

#define FAMILY_LOCATION_USERINFO_INFOTYPE_GENERALINFO  0x0001
#define FAMILY_LOCATION_USERINFO_INFOTYPE_AWAYMSG      0x0003
#define FAMILY_LOCATION_USERINFO_INFOTYPE_CAPS         0x0005

static const value_string aim_snac_location_request_user_info_infotypes[] = {
  { FAMILY_LOCATION_USERINFO_INFOTYPE_GENERALINFO, "Request General Info" },
  { FAMILY_LOCATION_USERINFO_INFOTYPE_AWAYMSG, "Request Away Message" },
  { FAMILY_LOCATION_USERINFO_INFOTYPE_CAPS, "Request Capabilities" },
  { 0, NULL }
};

static int dissect_aim_snac_location_request_user_information(tvbuff_t *tvb, int offset, proto_tree *tree);
static int dissect_aim_snac_location_user_information(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);

/* Initialize the protocol and registered fields */
static int proto_aim_location = -1;
static int hf_aim_snac_location_request_user_info_infotype = -1;
static int hf_aim_userinfo_warninglevel = -1;
static int hf_aim_buddyname_len = -1;
static int hf_aim_buddyname = -1;

/* Initialize the subtree pointers */
static gint ett_aim_location    = -1;

static int dissect_aim_location(tvbuff_t *tvb, packet_info *pinfo, 
				      proto_tree *tree )
{
	struct aiminfo *aiminfo = pinfo->private_data;
	int offset = 0;
	 proto_item *ti = NULL;
    proto_tree *loc_tree = NULL;

    if(tree) {
        ti = proto_tree_add_text(tree, tvb, 0, -1,"AIM Location Service");
        loc_tree = proto_item_add_subtree(ti, ett_aim_location);
    }

  switch(aiminfo->subtype)
    {
	case FAMILY_LOCATION_ERROR:
      return dissect_aim_snac_error(tvb, pinfo, offset, loc_tree);
    case FAMILY_LOCATION_REQUSERINFO:
      return dissect_aim_snac_location_request_user_information(tvb, offset, loc_tree);
    case FAMILY_LOCATION_USERINFO:
      return dissect_aim_snac_location_user_information(tvb, pinfo, offset, loc_tree);
	case FAMILY_LOCATION_REQRIGHTS:
	  /* No data */
	  return 0;
	case FAMILY_LOCATION_RIGHTSINFO:
	   while(tvb_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_tlv(tvb, pinfo, offset, loc_tree, location_rights_tlvs);
	  }
	  return 0;
	case FAMILY_LOCATION_SETUSERINFO:
	  while(tvb_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_tlv(tvb, pinfo, offset, loc_tree, location_rights_tlvs);
	  }
	  return 0;
	case FAMILY_LOCATION_WATCHERSUBREQ:
	  /* FIXME */
	  return 0;
	case FAMILY_LOCATION_WATCHERNOT:
	  while(tvb_length_remaining(tvb, offset) > 0) {
		  offset = dissect_aim_buddyname(tvb, pinfo, offset, loc_tree);
	  }
	  return offset;
	default:
	  return 0;
    }
}

static int dissect_aim_snac_location_request_user_information(tvbuff_t *tvb, 
							  int offset,
							  proto_tree *tree)
{
  guint8 buddyname_length = 0;

  /* Info Type */
  proto_tree_add_item(tree, hf_aim_snac_location_request_user_info_infotype, 
		      tvb, offset, 2, FALSE);
  offset += 2;

  /* Buddy Name length */
  buddyname_length = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_aim_buddyname_len, tvb, offset, 1, FALSE);
  offset += 1;
  
  /* Buddy name */
  proto_tree_add_item(tree, hf_aim_buddyname, tvb, offset, buddyname_length, FALSE);
  offset += buddyname_length;

  return offset;
}

static int dissect_aim_snac_location_user_information(tvbuff_t *tvb, 
						       packet_info *pinfo _U_, 
						  int offset, proto_tree *tree)
{
  guint8 buddyname_length = 0;

  /* Buddy Name length */
  buddyname_length = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_aim_buddyname_len, tvb, offset, 1, FALSE);
  offset += 1;
  
  /* Buddy name */
  proto_tree_add_item(tree, hf_aim_buddyname, tvb, offset, buddyname_length, FALSE);
  offset += buddyname_length;

  /* Warning level */
  proto_tree_add_item(tree, hf_aim_userinfo_warninglevel, tvb, offset, 2, FALSE);
  offset += 2;

  offset = dissect_aim_tlv_list(tvb, pinfo, offset, tree, onlinebuddy_tlvs);

  while(tvb_length_remaining(tvb, offset) > 0) {
	  offset = dissect_aim_tlv(tvb, pinfo, offset, tree, msg_tlv);
  }

  return offset;
}

void
proto_register_aim_location(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_aim_buddyname_len,
      { "Buddyname len", "aim.buddynamelen", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_buddyname,
      { "Buddy Name", "aim.buddyname", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_userinfo_warninglevel,
      { "Warning Level", "aim.userinfo.warninglevel", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
    },
    { &hf_aim_snac_location_request_user_info_infotype,
      { "Infotype", "aim.snac.location.request_user_info.infotype", FT_UINT16, BASE_HEX, VALS(aim_snac_location_request_user_info_infotypes), 0x0,
	"", HFILL }
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
  dissector_handle_t aim_handle;
  aim_handle = new_create_dissector_handle(dissect_aim_location, proto_aim_location);
  dissector_add("aim.family", FAMILY_LOCATION, aim_handle);
  aim_init_family(FAMILY_LOCATION, "Location", aim_fnac_family_location);
}
