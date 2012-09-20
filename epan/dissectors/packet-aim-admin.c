/* packet-aim-admin.c
 * Routines for AIM (OSCAR) dissection, Administration Service
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

#define FAMILY_ADMIN      0x0007

#define CONFIRM_STATUS_EMAIL_SENT 		 0x00
#define CONFIRM_STATUS_ALREADY_CONFIRMED 0x1E
#define CONFIRM_STATUS_SERVER_ERROR	     0x23

static const value_string confirm_statusses[] = {
	{ CONFIRM_STATUS_EMAIL_SENT, "A confirmation email has been sent" },
	{ CONFIRM_STATUS_ALREADY_CONFIRMED, "Account was already confirmed" },
	{ CONFIRM_STATUS_SERVER_ERROR, "Server couldn't start confirmation process" },
	{ 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_aim_admin = -1;
static int hf_admin_acctinfo_code = -1;
static int hf_admin_acctinfo_permissions = -1;
static int hf_admin_confirm_status = -1;

/* Initialize the subtree pointers */
static gint ett_aim_admin          = -1;

static int dissect_aim_admin_accnt_info_req(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *admin_tree)
{
	proto_tree_add_item(admin_tree, hf_admin_acctinfo_code, tvb, 0, 2, tvb_get_ntohs(tvb, 0));
	proto_tree_add_text(admin_tree, tvb, 2, 2, "Unknown");
	return 4;
}

static int dissect_aim_admin_accnt_info_repl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *admin_tree)
{
	int offset = 0;
	proto_tree_add_uint(admin_tree, hf_admin_acctinfo_permissions, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
	return dissect_aim_tlv_list(tvb, pinfo, offset, admin_tree, aim_client_tlvs);
}

static int dissect_aim_admin_info_change_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *admin_tree)
{
	return dissect_aim_tlv_sequence(tvb, pinfo, 0, admin_tree, aim_client_tlvs);
}

static int dissect_aim_admin_cfrm_repl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *admin_tree)
{
	int offset = 0;
	proto_tree_add_uint(admin_tree, hf_admin_confirm_status, tvb, offset, 2, tvb_get_ntohs(tvb, offset)); offset+=2;
	return dissect_aim_tlv_sequence(tvb, pinfo, offset, admin_tree, aim_client_tlvs);
}

static const aim_subtype aim_fnac_family_admin[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Request Account Information", dissect_aim_admin_accnt_info_req },
	{ 0x0003, "Requested Account Information", dissect_aim_admin_accnt_info_repl },
	{ 0x0004, "Infochange Request", dissect_aim_admin_info_change_req },
	{ 0x0005, "Infochange Reply", dissect_aim_admin_accnt_info_repl },
	{ 0x0006, "Account Confirm Request", NULL },
	{ 0x0007, "Account Confirm Reply", dissect_aim_admin_cfrm_repl},
	{ 0, NULL, NULL }
};

/* Register the protocol with Wireshark */
void
proto_register_aim_admin(void)
{

/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_admin_acctinfo_code,
		  { "Account Information Request Code", "aim_admin.acctinfo.code", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_admin_acctinfo_permissions,
		  { "Account Permissions", "aim_admin.acctinfo.permissions", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
		},
		{ &hf_admin_confirm_status,
		  { "Confirmation status", "aim_admin.confirm_status", FT_UINT16, BASE_HEX, VALS(confirm_statusses), 0x0, NULL, HFILL },
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_aim_admin,
	};

/* Register the protocol name and description */
	proto_aim_admin = proto_register_protocol("AIM Administrative", "AIM Administration", "aim_admin");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_aim_admin, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_admin(void)
{
	aim_init_family(proto_aim_admin, ett_aim_admin, FAMILY_ADMIN, aim_fnac_family_admin);
}
