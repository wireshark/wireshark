/* packet-aim-directory.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Directory
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 *
 * $Id: packet-aim-directory.c,v 1.4 2004/04/26 18:21:09 obiot Exp $
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

#define FAMILY_DIRECTORY  0x000F

#define FAMILY_DIRECTORY_ERROR			    0x0001
#define FAMILY_DIRECTORY_SEARCH_USER_REQ	0x0002
#define FAMILY_DIRECTORY_SEARCH_USER_REPL   0x0003
#define FAMILY_DIRECTORY_INTERESTS_LIST_REQ 0x0004
#define FAMILY_DIRECTORY_INTERESTS_LIST_REP 0x0005

static const value_string aim_fnac_family_directory[] = {
	{ FAMILY_DIRECTORY_ERROR, "Error" },
	{ FAMILY_DIRECTORY_SEARCH_USER_REQ, "Client search for user request" },
	{ FAMILY_DIRECTORY_SEARCH_USER_REPL, "Server reply for search request (found users)" },
	{ FAMILY_DIRECTORY_INTERESTS_LIST_REQ, "Request interests list from server" },
	{ FAMILY_DIRECTORY_INTERESTS_LIST_REP, "Interests list" },
	{ 0, NULL },
};

static int proto_aim_directory = -1;
static int ett_aim_directory = -1;

static int dissect_aim_directory(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct aiminfo *aiminfo = pinfo->private_data;
	proto_item *ti;
	int offset = 0;
	proto_tree *directory_tree = NULL;

    if(tree) {
    	ti = proto_tree_add_text(tree, tvb, 0, -1, "Directory Service");
    	directory_tree = proto_item_add_subtree(ti, ett_aim_directory);
   	}

	switch(aiminfo->subtype) {
	case FAMILY_DIRECTORY_ERROR:
		return dissect_aim_snac_error(tvb, pinfo, 0, directory_tree);
	case FAMILY_DIRECTORY_INTERESTS_LIST_REQ:
		return 0;
	case FAMILY_DIRECTORY_SEARCH_USER_REQ:
		/* FIXME */
		return 0;
	case FAMILY_DIRECTORY_SEARCH_USER_REPL:
		while (tvb_length_remaining(tvb, offset) > 0) {
			offset = dissect_aim_tlv(tvb, pinfo, offset, tree, client_tlvs);
		}
		return offset;
	case FAMILY_DIRECTORY_INTERESTS_LIST_REP:
		/* FIXME */
		return 0;
	}
	return 0;
}

/* Register the protocol with Ethereal */
void
proto_register_aim_directory(void)
{

/* Setup list of header fields */
/*FIXME
  static hf_register_info hf[] = {
  };*/

/* Setup protocol subtree array */
  static gint *ett[] = {
	  &ett_aim_directory
  };
/* Register the protocol name and description */
  proto_aim_directory = proto_register_protocol("AIM Directory Search", "AIM Directory", "aim_dir");

/* Required function calls to register the header fields and subtrees used */
/*FIXME
  proto_register_field_array(proto_aim_directory, hf, array_length(hf));*/
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_directory(void)
{
  dissector_handle_t aim_handle;
  aim_handle = new_create_dissector_handle(dissect_aim_directory, proto_aim_directory);
  dissector_add("aim.family", FAMILY_DIRECTORY, aim_handle); 
  aim_init_family(FAMILY_DIRECTORY, "Directory", aim_fnac_family_directory);
}
