/* packet-aim-userlookup.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Userlookup
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 *
 * $Id$
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

#define FAMILY_USERLOOKUP 0x000A

/* Family User Lookup */
#define FAMILY_USERLOOKUP_ERROR        0x0001
#define FAMILY_USERLOOKUP_SEARCHEMAIL  0x0002
#define FAMILY_USERLOOKUP_SEARCHRESULT 0x0003
#define FAMILY_USERLOOKUP_DEFAULT      0xffff

static const value_string aim_fnac_family_userlookup[] = {
  { FAMILY_USERLOOKUP_ERROR, "Error" },
  { FAMILY_USERLOOKUP_SEARCHEMAIL, "Search for user by email address" },
  { FAMILY_USERLOOKUP_SEARCHRESULT, "Search results" },
  { FAMILY_USERLOOKUP_DEFAULT, "Userlookup Default" },
  { 0, NULL }
};

/* Initialize the protocol and registered fields */
static int hf_aim_userlookup_email = -1;
static int proto_aim_userlookup = -1;

/* Initialize the subtree pointers */
static gint ett_aim_userlookup = -1;

static int dissect_aim_snac_userlookup(tvbuff_t *tvb _U_, packet_info *pinfo, 
					proto_tree *tree _U_)
{
	struct aiminfo *aiminfo = pinfo->private_data;
	int offset = 0;
	
    proto_item *ti = NULL;
    proto_tree *lookup_tree = NULL;
                                                                                
    if(tree) {
        ti = proto_tree_add_text(tree, tvb, 0, -1,"AIM Lookup Service");
		lookup_tree = proto_item_add_subtree(ti, ett_aim_userlookup);
    }


	switch(aiminfo->subtype) {
	case FAMILY_USERLOOKUP_ERROR:
      return dissect_aim_snac_error(tvb, pinfo, offset, tree);
	case FAMILY_USERLOOKUP_SEARCHEMAIL:
	  proto_tree_add_item(lookup_tree, hf_aim_userlookup_email, tvb, 0, tvb_length(tvb), FALSE);
	  return tvb_length(tvb);
	case FAMILY_USERLOOKUP_SEARCHRESULT:
        while(tvb_length_remaining(tvb, offset) > 0) {
            offset = dissect_aim_tlv(tvb, pinfo, offset, lookup_tree, client_tlvs);
        }
		return offset;
	}

	return 0;
}

/* Register the protocol with Ethereal */
void
proto_register_aim_userlookup(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
	  { &hf_aim_userlookup_email,
		  { "Email address looked for", "aim.userlookup.email", FT_STRING, BASE_NONE, NULL, 0, "Email address", HFILL }
	  },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_userlookup,
  };
/* Register the protocol name and description */
  proto_aim_userlookup = proto_register_protocol("AIM User Lookup", "AIM User Lookup", "aim_lookup");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_aim_userlookup, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_userlookup(void)
{
  dissector_handle_t aim_handle;
  aim_handle = new_create_dissector_handle(dissect_aim_snac_userlookup, proto_aim_userlookup);
  dissector_add("aim.family", FAMILY_USERLOOKUP, aim_handle);
  aim_init_family(FAMILY_USERLOOKUP, "User Lookup", aim_fnac_family_userlookup);
}
