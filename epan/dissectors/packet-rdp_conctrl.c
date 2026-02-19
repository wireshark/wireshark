/* packet-rdp_conctrl.c
 * Routines for the CONCTRL RDP channel
 * Copyright 2025, David Fort <contact@hardening-consulting.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>

void proto_register_rdp_conctrl(void);
void proto_reg_handoff_rdp_conctrl(void);

static int proto_rdp_conctrl;

static int hf_conctrl_orderType;
static int hf_conctrl_realmSz;
static int hf_conctrl_realm;
static int hf_conctrl_loginSz;
static int hf_conctrl_login;

static int ett_rdp_conctrl;

static int
dissect_rdp_conctrl(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *parent_tree _U_, void *data _U_)
{
	int offset = 0;
	//bool packetToServer = rdp_isServerAddressTarget(pinfo);

	parent_tree = proto_tree_get_root(parent_tree);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CONCTRL");

	proto_item *item = proto_tree_add_item(parent_tree, proto_rdp_conctrl, tvb, 0, 0, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_rdp_conctrl);

	uint32_t cmdId;
	proto_tree_add_item_ret_uint(tree, hf_conctrl_orderType, tvb, offset, 2, ENC_LITTLE_ENDIAN, &cmdId);
	offset += 2;

	switch (cmdId) {
	case 1:
		/* client capa ? */
	case 2:
		/* server capa ? */
		break;
	case 8:
		/* close */
		break;
	case 0x10: {
		/* session info on the server */
		offset += 12;

		uint32_t realmLen;
		proto_tree_add_item_ret_uint(tree, hf_conctrl_realmSz, tvb, offset, 4, ENC_LITTLE_ENDIAN, &realmLen);
		offset += 4;

		uint32_t loginLen;
		proto_tree_add_item_ret_uint(tree, hf_conctrl_loginSz, tvb, offset, 4, ENC_LITTLE_ENDIAN, &loginLen);
		offset += 4;

		proto_tree_add_item(tree, hf_conctrl_realm, tvb, offset, realmLen, ENC_UTF_16|ENC_LITTLE_ENDIAN);
		offset += realmLen;

		proto_tree_add_item(tree, hf_conctrl_login, tvb, offset, loginLen, ENC_UTF_16|ENC_LITTLE_ENDIAN);
		//offset += realmLen;
		break;
	}
	}

	return offset;
}

void proto_register_rdp_conctrl(void) {
	static hf_register_info hf[] = {
		{ &hf_conctrl_orderType,
		  { "OrderType", "rdp_conctrl.ordertype",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_conctrl_realmSz,
		  { "Realm size", "rdp_conctrl.realmsize",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_conctrl_realm,
		  { "Realm", "rdp_conctrl.realm",
			FT_STRINGZ, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_conctrl_loginSz,
		  { "Login size", "rdp_conctrl.loginsize",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_conctrl_login,
		  { "Login", "rdp_conctrl.login",
			FT_STRINGZ, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_rdp_conctrl,
	};


	proto_rdp_conctrl = proto_register_protocol("RDP Conctrl virtual channel Protocol", "CONCTRL", "rdp_conctrl");

	/* Register fields and subtrees */
	proto_register_field_array(proto_rdp_conctrl, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("rdp_conctrl", dissect_rdp_conctrl, proto_rdp_conctrl);
}

void proto_reg_handoff_rdp_conctrl(void) {
}
