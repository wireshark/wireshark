/* packet-aim-invitation.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Invitation
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

#include <epan/packet.h>

#include "packet-aim.h"

void proto_register_aim_invitation(void);
void proto_reg_handoff_aim_invitation(void);

#define FAMILY_INVITATION 0x0006

/* Initialize the protocol and registered fields */
static int proto_aim_invitation = -1;

static int ett_aim_invitation = -1;

static int dissect_aim_invitation_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *invite_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, invite_tree, aim_onlinebuddy_tlvs);
}

static const aim_subtype aim_fnac_family_invitation[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Invite a friend to join AIM", dissect_aim_invitation_req },
	{ 0x0003, "Invitation Ack", NULL },
	{ 0, NULL, NULL }
};



/* Register the protocol with Wireshark */
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
	aim_init_family(proto_aim_invitation, ett_aim_invitation, FAMILY_INVITATION, aim_fnac_family_invitation);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
