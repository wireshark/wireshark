/* packet-aim-icq.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC ICQ
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 *
 * $Id: packet-aim-icq.c,v 1.2 2004/03/23 18:36:05 guy Exp $
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

#define FAMILY_ICQ        0x0015

/* Family ICQ */
#define FAMILY_ICQ_ERROR              0x0001
#define FAMILY_ICQ_LOGINREQUEST       0x0002
#define FAMILY_ICQ_LOGINRESPONSE      0x0003
#define FAMILY_ICQ_AUTHREQUEST        0x0006
#define FAMILY_ICQ_AUTHRESPONSE       0x0007

static const value_string aim_fnac_family_icq[] = {
  { FAMILY_ICQ_ERROR, "Error" },
  { FAMILY_ICQ_LOGINREQUEST, "Login Request" },
  { FAMILY_ICQ_LOGINRESPONSE, "Login Response" },
  { FAMILY_ICQ_AUTHREQUEST, "Auth Request" },
  { FAMILY_ICQ_AUTHRESPONSE, "Auth Response" },
  { 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_aim_icq = -1;

/* Initialize the subtree pointers */
static gint ett_aim_icq      = -1;

static int dissect_aim_icq(tvbuff_t *tvb, packet_info *pinfo, 
				    proto_tree *tree)
{
   struct aiminfo *aiminfo = pinfo->private_data;
   int offset = 0;
   switch(aiminfo->subtype) {
   case FAMILY_ICQ_ERROR:
	   return dissect_aim_snac_error(tvb, pinfo, offset, tree);
   case FAMILY_ICQ_LOGINREQUEST:
   case FAMILY_ICQ_LOGINRESPONSE:
   case FAMILY_ICQ_AUTHREQUEST:
	case FAMILY_ICQ_AUTHRESPONSE:
	   /* FIXME */
	default:
	   return 0;
   }
}

/* Register the protocol with Ethereal */
void
proto_register_aim_icq(void)
{

/* Setup list of header fields */
/*FIXME
  static hf_register_info hf[] = {
  };*/

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_icq,
  };

/* Register the protocol name and description */
  proto_aim_icq = proto_register_protocol("AIM ICQ", "AIM ICQ", "aim_icq");

/* Required function calls to register the header fields and subtrees used */
/*FIXME
  proto_register_field_array(proto_aim_icq, hf, array_length(hf));*/
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_icq(void)
{
  dissector_handle_t aim_handle;

  aim_handle = new_create_dissector_handle(dissect_aim_icq, proto_aim_icq);
  dissector_add("aim.family", FAMILY_ICQ, aim_handle);
  aim_init_family(FAMILY_ICQ, "ICQ", aim_fnac_family_icq);
}
