/* packet-aim-bos.c
 * Routines for AIM (OSCAR) dissection, SNAC BOS
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 *
 * $Id: packet-aim-bos.c,v 1.1 2004/03/23 06:21:16 guy Exp $
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


/* Initialize the protocol and registered fields */
static int proto_aim_bos = -1;
static int hf_aim_bos_data = -1;
static int hf_aim_bos_class = -1;
static int hf_aim_bos_class_unconfirmed = -1;
static int hf_aim_bos_class_administrator = -1;
static int hf_aim_bos_class_aol = -1;
static int hf_aim_bos_class_commercial = -1;
static int hf_aim_bos_class_free = -1;
static int hf_aim_bos_class_away = -1;
static int hf_aim_bos_class_icq = -1;
static int hf_aim_bos_class_wireless = -1;
static int hf_aim_bos_class_unknown100 = -1;
static int hf_aim_bos_class_unknown200 = -1;
static int hf_aim_bos_class_unknown400 = -1;
static int hf_aim_bos_class_unknown800 = -1;

/* Initialize the subtree pointers */
static gint ett_aim_bos      = -1;
static gint ett_aim_bos_userclass      = -1;

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
			{
          		guint32 flags = tvb_get_ntoh24(tvb, offset);           
				proto_tree *entry;
			  	ti = proto_tree_add_uint(bos_tree, hf_aim_bos_class, tvb, offset, 4, flags);
			  	entry = proto_item_add_subtree(ti, ett_aim_bos_userclass);
proto_tree_add_boolean(entry, hf_aim_bos_class_unconfirmed, tvb, offset, 4, flags);
proto_tree_add_boolean(entry, hf_aim_bos_class_administrator, tvb, offset, 4, flags);
proto_tree_add_boolean(entry, hf_aim_bos_class_aol, tvb, offset, 4, flags);
proto_tree_add_boolean(entry, hf_aim_bos_class_commercial, tvb, offset, 4, flags);
proto_tree_add_boolean(entry, hf_aim_bos_class_free, tvb, offset, 4, flags);
proto_tree_add_boolean(entry, hf_aim_bos_class_away, tvb, offset, 4, flags);
proto_tree_add_boolean(entry, hf_aim_bos_class_icq, tvb, offset, 4, flags);
proto_tree_add_boolean(entry, hf_aim_bos_class_wireless, tvb, offset, 4, flags);
proto_tree_add_boolean(entry, hf_aim_bos_class_unknown100, tvb, offset, 4, flags);
proto_tree_add_boolean(entry, hf_aim_bos_class_unknown200, tvb, offset, 4, flags);
proto_tree_add_boolean(entry, hf_aim_bos_class_unknown400, tvb, offset, 4, flags);
proto_tree_add_boolean(entry, hf_aim_bos_class_unknown800, tvb, offset, 4, flags);
			}
			return 4;
		case FAMILY_BOS_RIGHTS:
		case FAMILY_BOS_ADD_TO_VISIBLE:
		case FAMILY_BOS_DEL_FROM_VISIBLE:
	  	case FAMILY_BOS_ADD_TO_INVISIBLE:
	  	case FAMILY_BOS_DEL_FROM_INVISIBLE:
			/* FIXME */
			return 0;
			
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
	{ &hf_aim_bos_class_unconfirmed,
	  { "AOL Unconfirmed user flag", "aim.bos.userclass.unconfirmed", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_UNCONFIRMED, "", HFILL },
	},
	{ &hf_aim_bos_class_administrator,
	  { "AOL Administrator flag", "aim.bos.userclass.administrator", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_ADMINISTRATOR, "", HFILL },
	},
	{ &hf_aim_bos_class_aol,
	  { "AOL Staff User Flag", "aim.bos.userclass.staff", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_AOL, "", HFILL },
	}, 
	{ &hf_aim_bos_class_commercial,
	  { "AOL commercial account flag", "aim.bos.userclass.commercial", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_COMMERCIAL, "", HFILL },
	},
	{ &hf_aim_bos_class_free,
	   { "ICQ non-commercial account flag", "aim.bos.userclass.noncommercial", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_FREE, "", HFILL },
	},
	{ &hf_aim_bos_class_away,
	   { "AOL away status flag", "aim.bos.userclass.away", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_AWAY, "", HFILL },
	},
	{ &hf_aim_bos_class_icq,
	   { "ICQ user sign", "aim.bos.userclass.icq", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_ICQ, "", HFILL },
	},
	{ &hf_aim_bos_class_wireless,
	   { "AOL wireless user", "aim.bos.userclass.wireless", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_WIRELESS, "", HFILL },
	},
	{ &hf_aim_bos_class_unknown100,
		{ "Unknown bit", "aim.bos.userclass.unknown100", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_UNKNOWN100, "", HFILL },
	},
	{ &hf_aim_bos_class_unknown200,
		{ "Unknown bit", "aim.bos.userclass.unknown200", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_UNKNOWN200, "", HFILL },
	},
	{ &hf_aim_bos_class_unknown400,
		{ "Unknown bit", "aim.bos.userclass.unknown400", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_UNKNOWN400, "", HFILL },
	},
	{ &hf_aim_bos_class_unknown800,
		{ "Unknown bit", "aim.bos.userclass.unknown800", FT_BOOLEAN, 32, TFS(&flags_set_truth), CLASS_UNKNOWN800, "", HFILL },
	},
	
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_bos,
	&ett_aim_bos_userclass
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
