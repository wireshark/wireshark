/* packet-aim-email.c
 * Routines for AIM (OSCAR) dissection, SNAC Email
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

#define FAMILY_EMAIL    0x0018

/* Family Advertising */
#define FAMILY_EMAIL_STATUS_REQ			0x0006
#define FAMILY_EMAIL_STATUS_REPL		0x0007
#define FAMILY_EMAIL_ACTIVATE			0x0016

static const value_string aim_fnac_family_email[] = {
  { FAMILY_EMAIL_STATUS_REQ, "Email Status Request" },
  { FAMILY_EMAIL_STATUS_REPL, "Email Status Reply" },
  { FAMILY_EMAIL_ACTIVATE, "Activate Email" },
  { 0, NULL }
};


/* Initialize the protocol and registered fields */
static int proto_aim_email = -1;

/* Initialize the subtree pointers */
static gint ett_aim_email      = -1;

static int dissect_aim_email(tvbuff_t *tvb _U_, 
				     packet_info *pinfo _U_, 
				     proto_tree *tree _U_)
{
	struct aiminfo *aiminfo = pinfo->private_data;

	switch(aiminfo->subtype) {
	default:
			/* FIXME */
		return 0;
	}

	return 0;
}

/* Register the protocol with Ethereal */
void
proto_register_aim_email(void)
{

/* Setup list of header fields */
/*FIXME
  static hf_register_info hf[] = {
  };*/

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_email,
  };

/* Register the protocol name and description */
  proto_aim_email = proto_register_protocol("AIM E-mail", "AIM Email", "aim_email");

/* Required function calls to register the header fields and subtrees used */
/*FIXME
  proto_register_field_array(proto_aim_email, hf, array_length(hf));*/
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_email(void)
{
  dissector_handle_t aim_handle;
  aim_handle = new_create_dissector_handle(dissect_aim_email, proto_aim_email);
  dissector_add("aim.family", FAMILY_EMAIL, aim_handle);
  aim_init_family(FAMILY_EMAIL, "E-mail", aim_fnac_family_email);
}
