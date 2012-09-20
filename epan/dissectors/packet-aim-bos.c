/* packet-aim-bos.c
 * Routines for AIM (OSCAR) dissection, SNAC BOS
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-aim.h"

#define FAMILY_BOS        0x0009

/* Family BOS (Misc) */

#define CLASS_UNCONFIRMED 			 0x0001
#define CLASS_ADMINISTRATOR			 0x0002
#define CLASS_AOL				     0x0004
#define CLASS_COMMERCIAL			 0x0008
#define CLASS_FREE				     0x0010
#define CLASS_AWAY				     0x0020
#define CLASS_ICQ				     0x0040
#define CLASS_WIRELESS		         0x0080
#define CLASS_UNKNOWN100		     0x0100
#define CLASS_UNKNOWN200		     0x0200
#define CLASS_UNKNOWN400		     0x0400
#define CLASS_UNKNOWN800		     0x0800

#define AIM_PRIVACY_TLV_MAX_VISIB_LIST_SIZE		0x001
#define AIM_PRIVACY_TLV_MAX_INVISIB_LIST_SIZE	0x002

static const aim_tlv aim_privacy_tlvs[] = {
	{ AIM_PRIVACY_TLV_MAX_VISIB_LIST_SIZE, "Max visible list size", dissect_aim_tlv_value_uint16 },
	{ AIM_PRIVACY_TLV_MAX_INVISIB_LIST_SIZE, "Max invisible list size", dissect_aim_tlv_value_uint16 },
	{ 0, NULL, NULL },
};

/* Initialize the protocol and registered fields */
static int proto_aim_bos = -1;
static int hf_aim_bos_data = -1;
static int hf_aim_bos_class = -1;

/* Initialize the subtree pointers */
static gint ett_aim_bos      = -1;

static int dissect_aim_bos_set_group_perm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *bos_tree) 
{
	int offset = 0;
	guint32 userclass = tvb_get_ntohl(tvb, offset);
	proto_item *ti = proto_tree_add_uint(bos_tree, hf_aim_bos_class, tvb, offset, 4, userclass); 
	return dissect_aim_userclass(tvb, offset, 4, ti, userclass);
}

static int dissect_aim_bos_rights(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bos_tree) 
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, bos_tree, aim_privacy_tlvs);
}

static int dissect_aim_bos_buddyname(tvbuff_t *tvb, packet_info *pinfo, proto_tree *bos_tree) 
{
	int offset = 0;
	while(tvb_reported_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_buddyname(tvb, pinfo, offset, bos_tree);
	}
	return offset;
}

/* Register the protocol with Wireshark */
void
proto_register_aim_bos(void)
{

	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_aim_bos_data,
			{ "Data", "aim_bos.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_bos_class,
			{ "User class", "aim_bos.userclass", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_aim_bos,
	};

	/* Register the protocol name and description */
	proto_aim_bos = proto_register_protocol("AIM Privacy Management Service", "AIM BOS", "aim_bos");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_aim_bos, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

static const aim_subtype aim_fnac_family_bos[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Rights Query", NULL },
	{ 0x0003, "Rights" , dissect_aim_bos_rights },
	{ 0x0004, "Set Group Permissions Mask", dissect_aim_bos_set_group_perm },
	{ 0x0005, "Add To Visible List", dissect_aim_bos_buddyname },
	{ 0x0006, "Delete From Visible List", dissect_aim_bos_buddyname },
	{ 0x0007, "Add To Invisible List", dissect_aim_bos_buddyname },
	{ 0x0008, "Delete From Invisible List", dissect_aim_bos_buddyname },
	{ 0, NULL, NULL }
};

void
proto_reg_handoff_aim_bos(void)
{
	aim_init_family(proto_aim_bos, ett_aim_bos, FAMILY_BOS, aim_fnac_family_bos);
}
