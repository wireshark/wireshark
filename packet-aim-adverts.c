/* packet-aim-adverts.c
 * Routines for AIM (OSCAR) dissection, SNAC Advertisements
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 *
 * $Id: packet-aim-adverts.c,v 1.1 2004/03/23 06:21:16 guy Exp $
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

#define FAMILY_ADVERTS    0x0005

/* Family Advertising */
#define FAMILY_ADVERTS_ERROR          0x0001
#define FAMILY_ADVERTS_REQUEST        0x0002
#define FAMILY_ADVERTS_DATA           0x0003
#define FAMILY_ADVERTS_DEFAULT        0xffff

static const value_string aim_fnac_family_adverts[] = {
  { FAMILY_ADVERTS_ERROR, "Error" },
  { FAMILY_ADVERTS_REQUEST, "Request" },
  { FAMILY_ADVERTS_DATA, "Data (GIF)" },
  { FAMILY_ADVERTS_DEFAULT, "Adverts Default" },
  { 0, NULL }
};


/* Initialize the protocol and registered fields */
static int proto_aim_adverts = -1;

/* Initialize the subtree pointers */
static gint ett_aim_adverts      = -1;

static int dissect_aim_adverts(tvbuff_t *tvb _U_, 
				     packet_info *pinfo _U_, 
				     proto_tree *tree _U_)
{
	struct aiminfo *aiminfo = pinfo->private_data;
	int offset = 0;

	switch(aiminfo->subtype) {
		case FAMILY_ADVERTS_ERROR:
		return dissect_aim_snac_error(tvb, pinfo, offset, tree);
		break;
		case FAMILY_ADVERTS_REQUEST:
		case FAMILY_ADVERTS_DATA:
		/* FIXME */
		return 0;
	}

	return 0;
}

/* Register the protocol with Ethereal */
void
proto_register_aim_adverts(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_adverts,
  };

/* Register the protocol name and description */
  proto_aim_adverts = proto_register_protocol("AIM Advertisements", "AIM Advertisements", "aim_adverts");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_aim_adverts, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_adverts(void)
{
  dissector_handle_t aim_handle;
  aim_handle = new_create_dissector_handle(dissect_aim_adverts, proto_aim_adverts);
  dissector_add("aim.family", FAMILY_ADVERTS, aim_handle);
  aim_init_family(FAMILY_ADVERTS, "Advertisements", aim_fnac_family_adverts);
}
