/* packet-aim-directory.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Directory
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

#define FAMILY_DIRECTORY  0x000F

static int proto_aim_directory = -1;
static int ett_aim_directory = -1;

static int dissect_aim_directory_user_repl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	while (tvb_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_tlv(tvb, pinfo, offset, tree, client_tlvs);
	}
	return offset;
}

static const aim_subtype aim_fnac_family_directory[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Client search for user request", NULL },
	{ 0x0003, "Server reply for search request (found users)", dissect_aim_directory_user_repl },
	{ 0x0004, "Request interests list from server", NULL },
	{ 0x0005, "Interests list", NULL },
	{ 0, NULL, NULL },
};


/* Register the protocol with Wireshark */
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
  aim_init_family(proto_aim_directory, ett_aim_directory, FAMILY_DIRECTORY, aim_fnac_family_directory);
}
