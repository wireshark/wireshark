/* packet-aim-bos.c
 * Routines for AIM (OSCAR) dissection, SNAC BOS
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 *
 * $Id: packet-aim-bos.c,v 1.3 2004/04/26 18:21:09 obiot Exp $
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

#define FAMILY_BOS        0x0009

/* Family BOS (Misc) */
#define FAMILY_BOS_ERROR              0x0001
#define FAMILY_BOS_RIGHTSQUERY        0x0002
#define FAMILY_BOS_RIGHTS             0x0003
#define FAMILY_BOS_SET_GROUP_PERM     0x0004
#define FAMILY_BOS_ADD_TO_VISIBLE     0x0005
#define FAMILY_BOS_DEL_FROM_VISIBLE   0x0006
#define FAMILY_BOS_ADD_TO_INVISIBLE   0x0007
#define FAMILY_BOS_DEL_FROM_INVISIBLE 0x0008
#define FAMILY_BOS_DEFAULT            0xffff

static const value_string aim_fnac_family_bos[] = {
  { FAMILY_BOS_ERROR, "Error" },
  { FAMILY_BOS_RIGHTSQUERY, "Rights Query" },
  { FAMILY_BOS_RIGHTS, "Rights" },
  { FAMILY_BOS_SET_GROUP_PERM, "Set Group Permissions Mask" },
  { FAMILY_BOS_ADD_TO_VISIBLE, "Add To Visible List" },
  { FAMILY_BOS_DEL_FROM_VISIBLE, "Delete From Visible List" },
  { FAMILY_BOS_ADD_TO_INVISIBLE, "Add To Invisible List" },
  { FAMILY_BOS_DEL_FROM_INVISIBLE, "Delete From Invisible List" },
  { FAMILY_BOS_DEFAULT, "BOS Default" },
  { 0, NULL }
};

#define CLASS_UNCONFIRMED 			 0x0001
#define CLASS_ADMINISTRATOR			 0x0002
#define CLASS_AOL				     0x0004
#define CLASS_COMMERCIAL			 0x0008
#define CLASS_FREE				     0x0010
#define CLASS_AWAY				     0x0020
#define CLASS_ICQ				     0x0040
#define CLASS_WIRELESS		         0x0080
#define CLASS_UNKNOWN100		     0x0100
#define CLASS_UNKNOWN200		     0x0200
#define CLASS_UNKNOWN400		     0x0400
#define CLASS_UNKNOWN800		     0x0800

#define AIM_PRIVACY_TLV_MAX_VISIB_LIST_SIZE		0x001
#define AIM_PRIVACY_TLV_MAX_INVISIB_LIST_SIZE	0x002

static const aim_tlv privacy_tlvs[] = {
	{ AIM_PRIVACY_TLV_MAX_VISIB_LIST_SIZE, "Max visible list size", dissect_aim_tlv_value_uint16 },
	{ AIM_PRIVACY_TLV_MAX_INVISIB_LIST_SIZE, "Max invisible list size", dissect_aim_tlv_value_uint16 },
	{ 0, "Unknown", NULL },
};

/* Initialize the protocol and registered fields */
static int proto_aim_bos = -1;
static int hf_aim_bos_data = -1;
static int hf_aim_bos_class = -1;

/* Initialize the subtree pointers */
static gint ett_aim_bos      = -1;

static int dissect_aim_bos(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	struct aiminfo *aiminfo = pinfo->private_data;
	int offset = 0;
	proto_item *ti;
	proto_tree *bos_tree = NULL;

	if(tree) {
        ti = proto_tree_add_text(tree, tvb, 0, -1,"AIM Privacy Management Service");
        bos_tree = proto_item_add_subtree(ti, ett_aim_bos);
	}

	switch(aiminfo->subtype) {
		case FAMILY_BOS_ERROR:
			return dissect_aim_snac_error(tvb, pinfo, offset, bos_tree);
		case FAMILY_BOS_RIGHTSQUERY:
			/* No data */
			return 0;
		case FAMILY_BOS_SET_GROUP_PERM:
		    ti = proto_tree_add_uint(bos_tree, hf_aim_bos_class, tvb, offset, 4, FALSE); 
			return dissect_aim_userclass(tvb, offset, bos_tree);
		case FAMILY_BOS_RIGHTS:
			while(tvb_length_remaining(tvb, offset) > 0) {
				offset = dissect_aim_tlv(tvb, pinfo, offset, bos_tree, privacy_tlvs);
			}
			return offset;
		case FAMILY_BOS_ADD_TO_VISIBLE:
		case FAMILY_BOS_DEL_FROM_VISIBLE:
	  	case FAMILY_BOS_ADD_TO_INVISIBLE:
	  	case FAMILY_BOS_DEL_FROM_INVISIBLE:
			while(tvb_length_remaining(tvb, offset) > 0) {
				offset = dissect_aim_buddyname(tvb, pinfo, offset, bos_tree);
			}
			return offset;
			
		default:
			return 0;
	}
}

/* Register the protocol with Ethereal */
void
proto_register_aim_bos(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_aim_bos_data,
      { "Data", "aim.data", FT_BYTES, BASE_HEX, NULL, 0x0, "", HFILL }
    },
	{ &hf_aim_bos_class,
	   { "User class", "aim.bos.userclass", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL },
	},
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_bos,
  };

/* Register the protocol name and description */
  proto_aim_bos = proto_register_protocol("AIM Privacy Management Service", "AIM BOS", "aim_bos");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_aim_bos, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_bos(void)
{
  dissector_handle_t aim_handle;

  aim_handle = new_create_dissector_handle(dissect_aim_bos, proto_aim_bos);
  dissector_add("aim.family", FAMILY_BOS, aim_handle);
  aim_init_family(FAMILY_BOS, "Privacy Management Service", aim_fnac_family_bos);
}
