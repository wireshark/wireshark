/* packet-aim.c
 * Routines for AIM Instant Messenger (OSCAR) dissection
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

/* SNAC families */
#define FAMILY_OFT        0xfffe

static int proto_aim_oft = -1;


/* Register the protocol with Ethereal */
void
proto_register_aim_oft(void)
{

/* Setup list of header fields */
/*  static hf_register_info hf[] = {
  };*/

/* Setup protocol subtree array */
/*  static gint *ett[] = {
  };*/

/* Register the protocol name and description */
  proto_aim_oft = proto_register_protocol("AIM OFT", "AIM OFT", "aim_oft");

/* Required function calls to register the header fields and subtrees used */
/*  proto_register_field_array(proto_aim_oft, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));*/
}

void
proto_reg_handoff_aim_oft(void)
{
/*  dissector_handle_t aim_handle;*/

  /* FIXME 
  aim_handle = new_create_dissector_handle(dissect_aim, proto_aim);
  dissector_add("tcp.port", TCP_PORT_AIM, aim_handle);*/
}
