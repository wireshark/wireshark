/* packet-aim-ssi.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC SSI
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
 *
 * $Id: packet-aim-ssi.c,v 1.1 2004/03/23 06:21:17 guy Exp $
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

#define FAMILY_SSI        0x0013

/* Family Server-Stored Buddy Lists */
#define FAMILY_SSI_ERROR              0x0001
#define FAMILY_SSI_REQRIGHTS          0x0002
#define FAMILY_SSI_RIGHTSINFO         0x0003
#define FAMILY_SSI_REQLIST_FIRSTTIME  0x0004
#define FAMILY_SSI_REQLIST            0x0005
#define FAMILY_SSI_LIST               0x0006
#define FAMILY_SSI_ACTIVATE           0x0007
#define FAMILY_SSI_ADD                0x0008
#define FAMILY_SSI_MOD                0x0009
#define FAMILY_SSI_DEL                0x000a
#define FAMILY_SSI_SRVACK             0x000e
#define FAMILY_SSI_NOLIST             0x000f
#define FAMILY_SSI_EDITSTART          0x0011
#define FAMILY_SSI_EDITSTOP           0x0012
#define FAMILY_SSI_GRANT_FUTURE_AUTH  0x0014
#define FAMILY_SSI_FUTUR_AUTH_GRANTED 0x0015
#define FAMILY_SSI_SEND_AUTH_REQ      0x0018
#define FAMILY_SSI_AUTH_REQ           0x0019
#define FAMILY_SSI_SEND_AUTH_REPLY    0x001a
#define FAMILY_SSI_AUTH_REPLY         0x001b
#define FAMILY_SSI_WAS_ADDED          0x001c

static const value_string aim_fnac_family_ssi[] = {
  { FAMILY_SSI_ERROR, "Error" },
  { FAMILY_SSI_REQRIGHTS, "Request Rights" },
  { FAMILY_SSI_RIGHTSINFO, "Rights Info" },
  { FAMILY_SSI_REQLIST_FIRSTTIME, "Request List (first time)" },
  { FAMILY_SSI_REQLIST, "Request List" },
  { FAMILY_SSI_LIST, "List" },
  { FAMILY_SSI_ACTIVATE, "Activate" },
  { FAMILY_SSI_ADD, "Add Buddy" },
  { FAMILY_SSI_MOD, "Modify Buddy" },
  { FAMILY_SSI_DEL, "Delete Buddy" },
  { FAMILY_SSI_SRVACK, "Server Ack" },
  { FAMILY_SSI_NOLIST, "No List" },
  { FAMILY_SSI_EDITSTART, "Edit Start" },
  { FAMILY_SSI_EDITSTOP, "Edit Stop" },
  { FAMILY_SSI_GRANT_FUTURE_AUTH, "Grant Future Authorization to Client" },
  { FAMILY_SSI_FUTUR_AUTH_GRANTED, "Future Authorization Granted" },
  { FAMILY_SSI_SEND_AUTH_REQ, "Send Authentication Request" },
  { FAMILY_SSI_AUTH_REQ, "Authentication Request" },
  { FAMILY_SSI_SEND_AUTH_REPLY, "Send Authentication Reply" },
  { FAMILY_SSI_AUTH_REPLY, "Authentication Reply" },
  { FAMILY_SSI_WAS_ADDED, "Remote User Added Client To List" },
  { 0, NULL }
};

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

static int dissect_aim_snac_ssi_list(tvbuff_t *tvb, packet_info *pinfo _U_, 
				      int offset, proto_tree *tree, guint16 subtype _U_);

/* Initialize the protocol and registered fields */
static int proto_aim_ssi = -1;
static int hf_aim_fnac_subtype_ssi_version = -1;
static int hf_aim_fnac_subtype_ssi_numitems = -1;
static int hf_aim_fnac_subtype_ssi_buddyname_len = -1;
static int hf_aim_fnac_subtype_ssi_buddyname = -1;
static int hf_aim_fnac_subtype_ssi_gid = -1;
static int hf_aim_fnac_subtype_ssi_bid = -1;
static int hf_aim_fnac_subtype_ssi_type = -1;
static int hf_aim_fnac_subtype_ssi_tlvlen = -1;
static int hf_aim_fnac_subtype_ssi_data = -1;

/* Initialize the subtree pointers */
static gint ett_aim_ssi      = -1;
static gint ett_ssi      = -1;

static int dissect_aim_snac_ssi(tvbuff_t *tvb, packet_info *pinfo _U_, 
				 proto_tree *tree)
{
	struct aiminfo *aiminfo = pinfo->private_data;
	int offset = 0;
    proto_item *ti = NULL;
    proto_tree *ssi_tree = NULL;
                                                                                
    if(tree) {
		ti = proto_tree_add_text(tree, tvb, 0, -1,"AIM Service Side Information Service");
        ssi_tree = proto_item_add_subtree(ti, ett_ssi);
    }

  switch(aiminfo->subtype)
    {    
	case FAMILY_SSI_ERROR:
      return dissect_aim_snac_error(tvb, pinfo, offset, ssi_tree);
    case FAMILY_SSI_LIST:
	  return dissect_aim_snac_ssi_list(tvb, pinfo, offset, ssi_tree, aiminfo->subtype);
	  /* FIXME */
    default:
	  return 0;
    }
}

static int dissect_aim_snac_ssi_list(tvbuff_t *tvb, packet_info *pinfo _U_, 
				      int offset, proto_tree *tree, 
				      guint16 subtype _U_)
{
  guint16 buddyname_length = 0;
  guint16 tlv_len = 0;
  int endoffset;
  proto_item *ti;
  proto_tree *ssi_entry = NULL;

  /* SSI Version */
  proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_version, tvb, offset, 1,
		      FALSE);
  offset += 1;
  
  /* Number of items */
  proto_tree_add_item(tree, hf_aim_fnac_subtype_ssi_numitems, tvb, offset, 2,
		      FALSE);
  offset += 2;
  
  while (tvb_length_remaining(tvb, offset) > 4) {
	
    ti = proto_tree_add_text(tree, tvb, offset, tvb_get_ntohs(tvb, offset+10)+10, "SSI Entry");
    ssi_entry = proto_item_add_subtree(ti, ett_aim_ssi);
    
    /* Buddy Name Length */
    buddyname_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_buddyname_len, 
			tvb, offset, 2, FALSE);
    offset += 2;
    
    /* Buddy Name */
    if (buddyname_length > 0) {
      proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_buddyname, tvb, 
			  offset, buddyname_length, FALSE);
      offset += buddyname_length;
    }
    
    /* Buddy group ID */
    proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_gid, tvb, offset, 
			2, FALSE);
    offset += 2;
    
    /* Buddy ID */
    proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_bid, tvb, offset, 
			2, FALSE);
    offset += 2;
    
    /* Buddy Type */
    proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_type, tvb, offset,
			2, FALSE);
    offset += 2;
    
    /* Size of the following TLV in bytes (as opposed to the number of 
       TLV objects in the chain) */
    tlv_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ssi_entry, hf_aim_fnac_subtype_ssi_tlvlen, tvb, 
			offset, 2, FALSE);
    offset += 2;
    
	endoffset = offset;
    /* For now, we just dump the TLV contents as-is, since there is not a
       TLV dissection utility that works based on total chain length */
	while(endoffset < offset+tlv_len) {
      	endoffset = dissect_aim_tlv(tvb, pinfo, endoffset, ssi_entry);
    }
	offset = endoffset;
  }
  return offset;
}

/* Register the protocol with Ethereal */
void
proto_register_aim_ssi(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_aim_fnac_subtype_ssi_version,
      { "SSI Version", "aim.fnac.ssi.version", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_numitems,
      { "SSI Object count", "aim.fnac.ssi.numitems", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_buddyname_len,
      { "SSI Buddy Name length", "aim.fnac.ssi.buddyname_len", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_buddyname,
      { "Buddy Name", "aim.fnac.ssi.buddyname", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_gid,
      { "SSI Buddy Group ID", "aim.fnac.ssi.gid", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_bid,
      { "SSI Buddy ID", "aim.fnac.ssi.bid", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_type,
      { "SSI Buddy type", "aim.fnac.ssi.type", FT_UINT16, BASE_HEX, VALS(aim_fnac_family_ssi_types), 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_tlvlen,
      { "SSI TLV Len", "aim.fnac.ssi.tlvlen", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
    },
    { &hf_aim_fnac_subtype_ssi_data,
      { "SSI Buddy Data", "aim.fnac.ssi.data", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }
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

void
proto_reg_handoff_aim_ssi(void)
{
  dissector_handle_t aim_handle;

  aim_handle = new_create_dissector_handle(dissect_aim_snac_ssi, proto_aim_ssi);
  dissector_add("aim.family", FAMILY_SSI, aim_handle);
  aim_init_family(FAMILY_SSI, "SSI", aim_fnac_family_ssi);
}
