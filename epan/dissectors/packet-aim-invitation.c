/* packet-aim-invitation.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Invitation
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

#define FAMILY_INVITATION 0x0006

/* Family Invitation */
#define FAMILY_INVITATION_ERROR       0x0001
#define FAMILY_INVITATION_FRIEND_REQ  0x0002
#define FAMILY_INVITATION_FRIEND_REPL 0x0003
#define FAMILY_INVITATION_DEFAULT     0xffff

static const value_string aim_fnac_family_invitation[] = {
  { FAMILY_INVITATION_ERROR, "Error" },
  { FAMILY_INVITATION_FRIEND_REQ, "Invite a friend to join AIM" },
  { FAMILY_INVITATION_FRIEND_REPL, "Invitation Ack" },
  { FAMILY_INVITATION_DEFAULT, "Invitation Default" },
  { 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_aim_invitation = -1;

static int ett_aim_invitation = -1;

static int dissect_aim_invitation(tvbuff_t *tvb, packet_info *pinfo,
                       proto_tree *tree)
{
  int offset = 0;
  struct aiminfo *aiminfo = pinfo->private_data;
  proto_item *ti = NULL;
  proto_tree *invite_tree = NULL;
                                                                                
  if(tree) {
	ti = proto_tree_add_text(tree, tvb, 0, -1,"AIM Invite Service");
    invite_tree = proto_item_add_subtree(ti, ett_aim_invitation);
  }

  switch(aiminfo->subtype) {
 	case FAMILY_INVITATION_ERROR:
      return dissect_aim_snac_error(tvb, pinfo, offset, invite_tree);
    case FAMILY_INVITATION_FRIEND_REQ:
       while(tvb_length_remaining(tvb, offset) > 0) {
          offset = dissect_aim_tlv(tvb, pinfo, offset, invite_tree, onlinebuddy_tlvs);
	   }
	   return 0;
    case FAMILY_INVITATION_FRIEND_REPL:
		return 0;
  }

  return 0;
}
                                                                                
/* Register the protocol with Ethereal */
void
proto_register_aim_invitation(void)
{

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_invitation,
  };

/* Register the protocol name and description */
  proto_aim_invitation = proto_register_protocol("AIM Invitation Service", "AIM Invitation", "aim_invitation");

/* Required function calls to register the header fields and subtrees used */
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_invitation(void)
{
  dissector_handle_t aim_handle;
  
  aim_handle = new_create_dissector_handle(dissect_aim_invitation, proto_aim_invitation);
  dissector_add("aim.family", FAMILY_INVITATION, aim_handle);
  aim_init_family(FAMILY_INVITATION, "Invitation", aim_fnac_family_invitation);
}
