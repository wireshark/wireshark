/* packet-aim-sst.c
 * Routines for AIM (OSCAR) dissection, SNAC Server Stored Themes
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

#define FAMILY_SST    0x0010

/* Family Advertising */
#define FAMILY_SST_ERROR          		0x0001
#define FAMILY_SST_UPLOAD_ICON_REQ	  	0x0002
#define FAMILY_SST_UPLOAD_ICON_REPL	  	0x0003
#define FAMILY_SST_DOWNLOAD_ICON_REQ	0x0004
#define FAMILY_SST_DOWNLOAD_ICON_REPL	0x0005

static const value_string aim_fnac_family_sst[] = {
  { FAMILY_SST_ERROR, "Error" },
  { FAMILY_SST_UPLOAD_ICON_REQ, "Upload Buddy Icon Request" },
  { FAMILY_SST_UPLOAD_ICON_REPL, "Upload Buddy Icon Reply" },
  { FAMILY_SST_DOWNLOAD_ICON_REQ, "Download Buddy Icon Request" },
  { FAMILY_SST_DOWNLOAD_ICON_REPL, "Download Buddy Icon Reply" },
  { 0, NULL }
};


/* Initialize the protocol and registered fields */
static int proto_aim_sst = -1;

/* Initialize the subtree pointers */
static gint ett_aim_sst      = -1;

static int dissect_aim_sst(tvbuff_t *tvb _U_, 
				     packet_info *pinfo _U_, 
				     proto_tree *tree _U_)
{
	struct aiminfo *aiminfo = pinfo->private_data;
	int offset = 0;

	switch(aiminfo->subtype) {
		case FAMILY_SST_ERROR:
		return dissect_aim_snac_error(tvb, pinfo, offset, tree);
		default:
		return 0;
	}

	return 0;
}

/* Register the protocol with Ethereal */
void
proto_register_aim_sst(void)
{

/* Setup list of header fields */
/*FIXME
  static hf_register_info hf[] = {
  };*/

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_sst,
  };

/* Register the protocol name and description */
  proto_aim_sst = proto_register_protocol("AIM Server Side Themes", "AIM SST", "aim_sst");

/* Required function calls to register the header fields and subtrees used */
/*FIXME
  proto_register_field_array(proto_aim_sst, hf, array_length(hf));*/
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_sst(void)
{
  dissector_handle_t aim_handle;
  aim_handle = new_create_dissector_handle(dissect_aim_sst, proto_aim_sst);
  dissector_add("aim.family", FAMILY_SST, aim_handle);
  aim_init_family(FAMILY_SST, "Server Stored Themes", aim_fnac_family_sst);
}
