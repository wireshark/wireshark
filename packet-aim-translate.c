/* packet-aim-translate.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Translate
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 *
 * $Id: packet-aim-translate.c,v 1.3 2004/03/24 06:36:32 ulfl Exp $
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

#define FAMILY_TRANSLATE  0x000C

/* Family Translation */
#define FAMILY_TRANSLATE_ERROR        0x0001
#define FAMILY_TRANSLATE_REQ          0x0002
#define FAMILY_TRANSLATE_REPL         0x0003
#define FAMILY_TRANSLATE_DEFAULT      0xffff

static const value_string aim_fnac_family_translate[] = {
  { FAMILY_TRANSLATE_ERROR, "Error" },
  { FAMILY_TRANSLATE_REQ, "Translate Request" },
  { FAMILY_TRANSLATE_REPL, "Translate Reply" },
  { FAMILY_TRANSLATE_DEFAULT, "Translate Default" },
  { 0, NULL }
};

static int proto_aim_translate = -1;

/* Initialize the subtree pointers */
static gint ett_aim_translate = -1;

/* Register the protocol with Ethereal */
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
  /*dissector_handle_t aim_handle;*/
/*FIXME  aim_handle = new_create_dissector_handle(dissect_aim, proto_aim);
  dissector_add("tcp.port", TCP_PORT_AIM, aim_handle);*/
  aim_init_family(FAMILY_TRANSLATE, "Translate", aim_fnac_family_translate);
}
