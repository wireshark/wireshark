/* packet-aim-buddylist.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Buddylist
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 *
 * $Id: packet-aim-buddylist.c,v 1.4 2004/06/16 07:51:21 guy Exp $
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
#include "prefs.h"

#define FAMILY_BUDDYLIST  0x0003

/* Family Buddy List */
#define FAMILY_BUDDYLIST_ERROR        0x0001
#define FAMILY_BUDDYLIST_REQRIGHTS    0x0002
#define FAMILY_BUDDYLIST_RIGHTSINFO   0x0003
#define FAMILY_BUDDYLIST_ADDBUDDY     0x0004
#define FAMILY_BUDDYLIST_REMBUDDY     0x0005
#define FAMILY_BUDDYLIST_WATCHERS_REQ 0x0006
#define FAMILY_BUDDYLIST_WATCHERS_REP 0x0007
#define FAMILY_BUDDYLIST_REJECT       0x000a
#define FAMILY_BUDDYLIST_ONCOMING     0x000b
#define FAMILY_BUDDYLIST_OFFGOING     0x000c
#define FAMILY_BUDDYLIST_DEFAULT      0xffff

static const value_string aim_fnac_family_buddylist[] = {
  { FAMILY_BUDDYLIST_ERROR, "Error" },
  { FAMILY_BUDDYLIST_REQRIGHTS, "Request Rights" },
  { FAMILY_BUDDYLIST_RIGHTSINFO, "Rights Info" },
  { FAMILY_BUDDYLIST_ADDBUDDY, "Add Buddy" },
  { FAMILY_BUDDYLIST_REMBUDDY, "Remove Buddy" },
  { FAMILY_BUDDYLIST_REJECT, "Reject Buddy" }, 
  { FAMILY_BUDDYLIST_ONCOMING, "Oncoming Buddy" },
  { FAMILY_BUDDYLIST_OFFGOING, "Offgoing Buddy" },
  { FAMILY_BUDDYLIST_DEFAULT, "Buddy Default" },
  { 0, NULL }
};

#define AIM_BUDDYLIST_TLV_MAX_CONTACT_ENTRIES 		0x0001
#define AIM_BUDDYLIST_TLV_MAX_WATCHER_ENTRIES 		0x0002
#define AIM_BUDDYLIST_TLV_MAX_ONLINE_NOTIFICATIONS 	0x0003

const aim_tlv buddylist_tlvs[] = {
	{ AIM_BUDDYLIST_TLV_MAX_CONTACT_ENTRIES, "Max number of contact list entries", dissect_aim_tlv_value_uint16 },
	{ AIM_BUDDYLIST_TLV_MAX_WATCHER_ENTRIES, "Max number of watcher list entries", dissect_aim_tlv_value_uint16 },
	{ AIM_BUDDYLIST_TLV_MAX_ONLINE_NOTIFICATIONS, "Max online notifications", dissect_aim_tlv_value_uint16 },
	{0, NULL, NULL }
};


/* Initialize the protocol and registered fields */
static int proto_aim_buddylist = -1;
static int hf_aim_buddyname_len = -1;
static int hf_aim_buddyname = -1;
static int hf_aim_userinfo_warninglevel = -1;
static int hf_aim_userinfo_tlvcount = -1;

/* Initialize the subtree pointers */
static gint ett_aim_buddylist = -1;

static int dissect_aim_snac_buddylist(tvbuff_t *tvb, packet_info *pinfo, 
				       proto_tree *tree)
{
  guint8 buddyname_length = 0;
  char buddyname[MAX_BUDDYNAME_LENGTH + 1];
  guint16 tlv_count = 0;
  struct aiminfo *aiminfo = pinfo->private_data;
  int offset = 0;
  proto_item *ti;
  proto_tree *buddy_tree = NULL;

  if(tree) {
	  ti = proto_tree_add_text(tree, tvb, 0, -1, "Buddy List Service");
	  buddy_tree = proto_item_add_subtree(ti, ett_aim_buddylist);   
  }


  switch(aiminfo->subtype)
    {
	case FAMILY_BUDDYLIST_REQRIGHTS:
	case FAMILY_BUDDYLIST_WATCHERS_REQ:
		/* No data */
		return 0;
	case FAMILY_BUDDYLIST_REMBUDDY:
	case FAMILY_BUDDYLIST_ADDBUDDY:
	case FAMILY_BUDDYLIST_WATCHERS_REP:
		while(tvb_length_remaining(tvb, offset) > 0) {
			offset = dissect_aim_buddyname( tvb, pinfo, offset, buddy_tree);
		}
		return offset;
	case FAMILY_BUDDYLIST_ERROR:
      return dissect_aim_snac_error(tvb, pinfo, offset, buddy_tree);
	case FAMILY_BUDDYLIST_RIGHTSINFO:
		while(tvb_length_remaining(tvb, offset) > 0) {
			offset = dissect_aim_tlv( tvb, pinfo, offset, buddy_tree, buddylist_tlvs);
		}
		return offset;
	case FAMILY_BUDDYLIST_REJECT:
		return dissect_aim_buddyname(tvb, pinfo, offset, buddy_tree);
    case FAMILY_BUDDYLIST_ONCOMING:
      buddyname_length = aim_get_buddyname( buddyname, tvb, offset, offset + 1 );

      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "Oncoming Buddy");
	col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
	                format_text(buddyname, buddyname_length));
      }
      
      if (buddy_tree) {
	proto_tree_add_text(buddy_tree, tvb, offset + 1, buddyname_length, 
			    "Screen Name: %s",
			    format_text(buddyname, buddyname_length));
      }
      offset += buddyname_length + 1;

      /* Warning level */
      proto_tree_add_item(buddy_tree, hf_aim_userinfo_warninglevel, tvb, offset, 
			  2, FALSE);
      offset += 2;
      
      /* TLV Count */
      tlv_count = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(buddy_tree, hf_aim_userinfo_tlvcount, tvb, offset, 
			  2, FALSE);
      offset += 2;

      while (tvb_length_remaining(tvb, offset) > 0) {
	offset = dissect_aim_tlv(tvb, pinfo, offset, buddy_tree, onlinebuddy_tlvs);
      }

      return offset;
      
    case FAMILY_BUDDYLIST_OFFGOING:
      buddyname_length = aim_get_buddyname( buddyname, tvb, offset, offset + 1 );
      
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "Offgoing Buddy");
	col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
	                format_text(buddyname, buddyname_length));
      }
      
      if (buddy_tree) {
	proto_tree_add_text(buddy_tree, tvb, offset + 1, buddyname_length, 
			    "Screen Name: %s",
			    format_text(buddyname, buddyname_length));
      }
      offset += buddyname_length + 1;

      /* Warning level */
      proto_tree_add_item(buddy_tree, hf_aim_userinfo_warninglevel, tvb, offset, 
			  2, FALSE);
      offset += 2;

	  return dissect_aim_tlv_list(tvb, pinfo, offset, buddy_tree, onlinebuddy_tlvs);
	default:
	  return 0;
    }
}


/* Register the protocol with Ethereal */
void
proto_register_aim_buddylist(void)
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
    { &hf_aim_userinfo_tlvcount,
      { "TLV Count", "aim.userinfo.tlvcount", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
    },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_buddylist,
  };

/* Register the protocol name and description */
  proto_aim_buddylist = proto_register_protocol("AIM Buddylist Service", "AIM Buddylist", "aim_buddylist");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_aim_buddylist, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_buddylist(void)
{
  dissector_handle_t aim_handle;

  aim_handle = new_create_dissector_handle(dissect_aim_snac_buddylist, proto_aim_buddylist);
  dissector_add("aim.family", FAMILY_BUDDYLIST, aim_handle);
  aim_init_family(FAMILY_BUDDYLIST, "Buddylist", aim_fnac_family_buddylist);
}
