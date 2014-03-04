/* packet-aim-email.c
 * Routines for AIM (OSCAR) dissection, SNAC Email
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>

#include "packet-aim.h"

void proto_register_aim_email(void);
void proto_reg_handoff_aim_email(void);

#define FAMILY_EMAIL    0x0018

static const aim_subtype aim_fnac_family_email[] = {
  { 0x0006, "Email Status Request", NULL },
  { 0x0007, "Email Status Reply", NULL },
  { 0x0016, "Activate Email", NULL },
  { 0, NULL, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_aim_email = -1;

/* Initialize the subtree pointers */
static gint ett_aim_email      = -1;

/* Register the protocol with Wireshark */
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
  aim_init_family(proto_aim_email, ett_aim_email, FAMILY_EMAIL, aim_fnac_family_email);
}
