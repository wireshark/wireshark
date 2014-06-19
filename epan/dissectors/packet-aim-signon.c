/* packet-aim-signon.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Signon
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
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

void proto_register_aim_signon(void);
void proto_reg_handoff_aim_signon(void);

#define FAMILY_SIGNON     0x0017


/* Initialize the protocol and registered fields */
static int proto_aim_signon = -1;
static int hf_aim_infotype = -1;
static int hf_aim_signon_challenge_len = -1;
static int hf_aim_signon_challenge = -1;


/* Initialize the subtree pointers */
static gint ett_aim_signon   = -1;

static int dissect_aim_snac_signon_logon(tvbuff_t *tvb, packet_info *pinfo,
					  proto_tree *tree)
{
	int offset = 0;
	while (tvb_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_tlv(tvb, pinfo, offset, tree, aim_client_tlvs);
	}
	return offset;
}

static int dissect_aim_snac_signon_logon_reply(tvbuff_t *tvb,
					       packet_info *pinfo,
					       proto_tree *tree)
{
	int offset = 0;
	while (tvb_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_tlv(tvb, pinfo, offset, tree, aim_client_tlvs);
	}
	return offset;
}

static int dissect_aim_snac_signon_signon(tvbuff_t *tvb, packet_info *pinfo,
					  proto_tree *tree)
{
	guint8 buddyname_length = 0;
	int offset = 0;
	guint8 *buddyname;

	/* Info Type */
	proto_tree_add_item(tree, hf_aim_infotype, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Unknown */
	offset += 1;

	/* Buddy Name */
	buddyname_length = aim_get_buddyname( &buddyname, tvb, offset );

	col_append_fstr(pinfo->cinfo, COL_INFO, " Username: %s",
			format_text(buddyname, buddyname_length));

	if(tree) {
		offset+=dissect_aim_buddyname(tvb, pinfo, offset, tree);
	}

	return offset;
}

static int dissect_aim_snac_signon_signon_reply(tvbuff_t *tvb,
						packet_info *pinfo _U_,
						proto_tree *tree)
{
	int offset = 0;
	guint16 challenge_length = 0;

	/* Logon Challenge Length */
	challenge_length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_aim_signon_challenge_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Challenge */
	proto_tree_add_item(tree, hf_aim_signon_challenge, tvb, offset, challenge_length, ENC_UTF_8|ENC_NA);
	offset += challenge_length;
	return offset;
}

static int dissect_aim_tlv_value_registration(proto_item *ti _U_, guint16 value_id _U_, tvbuff_t *tvb _U_, packet_info *pinfo _U_)
{
	/* FIXME */
	return 0;
}

#define REG_TLV_REGISTRATION_INFO 	0x0001

static const aim_tlv aim_registration_tlvs[] = {
	{ REG_TLV_REGISTRATION_INFO, "Registration Info", dissect_aim_tlv_value_registration },
	{ 0, NULL, NULL },
};

static int dissect_aim_snac_register (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	return dissect_aim_tlv(tvb, pinfo, 0, tree, aim_registration_tlvs);
}

static const aim_subtype aim_fnac_family_signon[] = {
	{ 0x0001, "Error", dissect_aim_snac_error },
	{ 0x0002, "Logon", dissect_aim_snac_signon_logon },
	{ 0x0003, "Logon Reply", dissect_aim_snac_signon_logon_reply },
	{ 0x0004, "Request UIN", dissect_aim_snac_register },
	{ 0x0005, "New UIN response", dissect_aim_snac_register },
	{ 0x0006, "Sign-on", dissect_aim_snac_signon_signon },
	{ 0x0007, "Sign-on Reply", dissect_aim_snac_signon_signon_reply },
	{ 0x000a, "Server SecureID Request", NULL },
	{ 0x000b, "Client SecureID Reply", NULL },
	{ 0, NULL, NULL }
};


/* Register the protocol with Wireshark */
void
proto_register_aim_signon(void)
{

	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_aim_infotype,
		  { "Infotype", "aim_signon.infotype", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_signon_challenge_len,
		  { "Signon challenge length", "aim_signon.challengelen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_aim_signon_challenge,
		  { "Signon challenge", "aim_signon.challenge", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_aim_signon,
	};

	/* Register the protocol name and description */
	proto_aim_signon = proto_register_protocol("AIM Signon", "AIM Signon", "aim_signon");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_aim_signon, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_signon(void)
{
	aim_init_family(proto_aim_signon, ett_aim_signon, FAMILY_SIGNON, aim_fnac_family_signon);
}
