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


/* Initialize the protocol and registered fields */
static int proto_aim_sst = -1;

/* Initialize the subtree pointers */
static gint ett_aim_sst      = -1;

static const aim_subtype aim_fnac_family_sst[] = {
  { 0x0001, "Error", dissect_aim_snac_error },
  { 0x0002, "Upload Buddy Icon Request", NULL },
  { 0x0003, "Upload Buddy Icon Reply", NULL },
  { 0x0004, "Download Buddy Icon Request", NULL },
  { 0x0005, "Download Buddy Icon Reply", NULL },
  { 0, NULL, NULL }
};


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
  aim_init_family(proto_aim_sst, ett_aim_sst, FAMILY_SST, aim_fnac_family_sst);
}
