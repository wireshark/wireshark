/* packet-aim.c
 * Routines for AIM Instant Messenger (OSCAR) dissection
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 *
 * $Id: packet-aim-chatnav.c,v 1.1 2004/03/23 06:21:16 guy Exp $
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

#define FAMILY_CHAT_NAV   0x000D

/* Family Chat Navigation */
#define FAMILY_CHATNAV_ERROR          0x0001
#define FAMILY_CHATNAV_LIMITS_REQ     0x0002
#define FAMILY_CHATNAV_EXCHANGE_REQ   0x0003
#define FAMILY_CHATNAV_ROOM_INFO_REQ  0x0004
#define FAMILY_CHATNAV_ROOMIF_EXT_REQ 0x0005
#define FAMILY_CHATNAV_MEMBERLIST_REQ 0x0006
#define FAMILY_CHATNAV_SEARCH_ROOM    0x0007
#define FAMILY_CHATNAV_CREATE_ROOM    0x0008
#define FAMILY_CHATNAV_INFO_REPLY     0x0009
#define FAMILY_CHATNAV_DEFAULT        0xffff

static const value_string aim_fnac_family_chatnav[] = {
  { FAMILY_CHATNAV_ERROR, "Error" },
  { FAMILY_CHATNAV_LIMITS_REQ, "Request Limits" },
  { FAMILY_CHATNAV_EXCHANGE_REQ, "Request Exchange" },
  { FAMILY_CHATNAV_ROOM_INFO_REQ, "Request Room Information" },
  { FAMILY_CHATNAV_ROOMIF_EXT_REQ, "Request Extended Room Information" },
  { FAMILY_CHATNAV_MEMBERLIST_REQ, "Request Member List" },
  { FAMILY_CHATNAV_SEARCH_ROOM, "Search Room" },
  { FAMILY_CHATNAV_CREATE_ROOM, "Create" },
  { FAMILY_CHATNAV_INFO_REPLY, "Info" },
  { FAMILY_CHATNAV_DEFAULT, "ChatNav Default" },
  { 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_aim_chatnav = -1;

int ett_aim_chatnav = -1;

/* Register the protocol with Ethereal */
void
proto_register_aim_chatnav(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_chatnav,
  };
/* Register the protocol name and description */
  proto_aim_chatnav = proto_register_protocol("AIM Chat Navigation", "AIM ChatNav", "aim_chatnav");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_aim_chatnav, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_chatnav(void)
{
  dissector_handle_t aim_handle;

  /* FIXME: dissect
   * aim_handle = new_create_dissector_handle(dissect_aim_chatnav, proto_aim_chatnav);
   * dissector_add("aim.family", FAMILY_CHAT_NAV, aim_handle);
   */
  aim_init_family(FAMILY_CHAT_NAV, "Chat Navigation", aim_fnac_family_chatnav);
}
