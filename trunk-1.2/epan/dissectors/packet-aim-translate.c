/* packet-aim-translate.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Translate
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

#define FAMILY_TRANSLATE  0x000C

static int proto_aim_translate = -1;

/* Initialize the subtree pointers */
static gint ett_aim_translate = -1;

static const aim_subtype aim_fnac_family_translate[] = {
  { 0x0001, "Error", dissect_aim_snac_error },
  { 0x0002, "Translate Request", NULL },
  { 0x0003, "Translate Reply", NULL },
  { 0, NULL, NULL }
};

/* Register the protocol with Wireshark */
void
proto_register_aim_translate(void)
{

/* Setup list of header fields */
/*FIXME
  static hf_register_info hf[] = {
  };*/

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_translate,
  };
/* Register the protocol name and description */
  proto_aim_translate = proto_register_protocol("AIM Translate", "AIM Translate", "aim_translate");

/* Required function calls to register the header fields and subtrees used */
/*FIXME
  proto_register_field_array(proto_aim_translate, hf, array_length(hf));*/
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_translate(void)
{
  aim_init_family(proto_aim_translate, ett_aim_translate, FAMILY_TRANSLATE, aim_fnac_family_translate);
}
