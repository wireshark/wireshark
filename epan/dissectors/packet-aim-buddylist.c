/* packet-aim-buddylist.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Buddylist
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

#define FAMILY_BUDDYLIST  0x0003


#define AIM_BUDDYLIST_TLV_MAX_CONTACT_ENTRIES 		0x0001
#define AIM_BUDDYLIST_TLV_MAX_WATCHER_ENTRIES 		0x0002
#define AIM_BUDDYLIST_TLV_MAX_ONLINE_NOTIFICATIONS 	0x0003

const aim_tlv buddylist_tlvs[] = {
	{ AIM_BUDDYLIST_TLV_MAX_CONTACT_ENTRIES, "Max number of contact list entries", dissect_aim_tlv_value_uint16 },
	{ AIM_BUDDYLIST_TLV_MAX_WATCHER_ENTRIES, "Max number of watcher list entries", dissect_aim_tlv_value_uint16 },
	{ AIM_BUDDYLIST_TLV_MAX_ONLINE_NOTIFICATIONS, "Max online notifications", dissect_aim_tlv_value_uint16 },
	{0, NULL, NULL }
};


/* Initialize the protocol and registered fields */
static int proto_aim_buddylist = -1;
static int hf_aim_userinfo_warninglevel = -1;

/* Initialize the subtree pointers */
static gint ett_aim_buddylist = -1;

static int dissect_aim_buddylist_buddylist(tvbuff_t *tvb, packet_info *pinfo, proto_tree *buddy_tree)
{
	int offset = 0;
	while(tvb_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_buddyname( tvb, pinfo, offset, buddy_tree);
	}
	return offset;
}

static int dissect_aim_buddylist_rights_repl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *buddy_tree) 
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, buddy_tree, buddylist_tlvs);
}

static int dissect_aim_buddylist_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *buddy_tree)
{
	return dissect_aim_buddyname(tvb, pinfo, 0, buddy_tree);
}

static int dissect_aim_buddylist_oncoming(tvbuff_t *tvb, packet_info *pinfo, proto_tree *buddy_tree)
{
	char buddyname[MAX_BUDDYNAME_LENGTH+1];
	int offset = 0;
	int buddyname_length = aim_get_buddyname( buddyname, tvb, offset, offset + 1 );

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "Oncoming Buddy");
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
						format_text(buddyname, buddyname_length));
	}

	offset += dissect_aim_buddyname(tvb, pinfo, offset, buddy_tree);

	/* Warning level */
	proto_tree_add_item(buddy_tree, hf_aim_userinfo_warninglevel, tvb, offset, 
						2, FALSE);
	offset += 2;

	offset = dissect_aim_tlv_list(tvb, pinfo, offset, buddy_tree, onlinebuddy_tlvs);

	return offset;
}

static int dissect_aim_buddylist_offgoing(tvbuff_t *tvb, packet_info *pinfo, proto_tree *buddy_tree) 
{

	char buddyname[MAX_BUDDYNAME_LENGTH+1];
	int offset = 0;
	int buddyname_length = aim_get_buddyname( buddyname, tvb, offset, offset + 1 );

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "Offgoing Buddy");
		col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
						format_text(buddyname, buddyname_length));
	}

	offset += dissect_aim_buddyname(tvb, pinfo, offset, buddy_tree);

	/* Warning level */
	proto_tree_add_item(buddy_tree, hf_aim_userinfo_warninglevel, tvb, offset, 
						2, FALSE);
	offset += 2;

	return dissect_aim_tlv_list(tvb, pinfo, offset, buddy_tree, onlinebuddy_tlvs);
}

static const aim_subtype aim_fnac_family_buddylist[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Rights Request", NULL },
	{ 0x0003, "Rights Reply", dissect_aim_buddylist_rights_repl },
	{ 0x0004, "Add Buddy", dissect_aim_buddylist_buddylist },
	{ 0x0005, "Remove Buddy", dissect_aim_buddylist_buddylist },
	{ 0x0006, "Watchers List Request", NULL },
	{ 0x0007, "Watchers List Reply", dissect_aim_buddylist_buddylist },
	{ 0x000a, "Reject Buddy", dissect_aim_buddylist_reject }, 
	{ 0x000b, "Oncoming Buddy", dissect_aim_buddylist_oncoming },
	{ 0x000c, "Offgoing Buddy", dissect_aim_buddylist_offgoing },
	{ 0, NULL, NULL }
};

/* Register the protocol with Wireshark */
void
proto_register_aim_buddylist(void)
{

	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_aim_userinfo_warninglevel,
			{ "Warning Level", "aim.userinfo.warninglevel", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_aim_buddylist,
	};

	/* Register the protocol name and description */
	proto_aim_buddylist = proto_register_protocol("AIM Buddylist Service", "AIM Buddylist", "aim_buddylist");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_aim_buddylist, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_buddylist(void)
{
	aim_init_family(proto_aim_buddylist, ett_aim_buddylist, FAMILY_BUDDYLIST, aim_fnac_family_buddylist);
}
