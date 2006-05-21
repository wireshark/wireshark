/* packet-aim-userlookup.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Userlookup
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-aim.h"

#define FAMILY_USERLOOKUP 0x000A

/* Initialize the protocol and registered fields */
static int hf_aim_userlookup_email = -1;
static int proto_aim_userlookup = -1;

/* Initialize the subtree pointers */
static gint ett_aim_userlookup = -1;

static int dissect_aim_userlookup_search(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *lookup_tree)
{
	  proto_tree_add_item(lookup_tree, hf_aim_userlookup_email, tvb, 0, tvb_length(tvb), FALSE);
	  return tvb_length(tvb);
}


static int dissect_aim_userlookup_result(tvbuff_t *tvb, packet_info *pinfo, proto_tree *lookup_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, lookup_tree, client_tlvs);
}

static const aim_subtype aim_fnac_family_userlookup[] = {
  { 0x0001, "Error", dissect_aim_snac_error },
  { 0x0002, "Search for user by email address", dissect_aim_userlookup_search },
  { 0x0003, "Search results", dissect_aim_userlookup_result },
  { 0, NULL, NULL }
};

/* Register the protocol with Wireshark */
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
  aim_init_family(proto_aim_userlookup, ett_aim_userlookup, FAMILY_USERLOOKUP, aim_fnac_family_userlookup);
}
