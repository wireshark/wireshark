/* packet-ans.c
 * Routines for Intel ANS probe dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2003 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The following information was graciously provided by Intel:
 * Offset    Size (bytes)    Contents
 * 0         6               Destination Broadcast probes: {FF,FF,FF,FF,FF,FF}
 *                           Multicast probes: {01,AA,00,00,00,00}
 * 6         6               Source Matches the CurrentMACAddress of the
 *                           adapter sending the probe.
 * 8         2               Type Network order is 0x886D, Intel's reserved
 *                           packet type.
 * 10 (0)    2               ApplicationID Network order is 0x0001, identifies
 *                           it as fault tolerance probe.
 * 12 (2)    2               RevID Network order, identifies the revision id
 *                           of Teaming software.
 * 16 (4)    4               ProbeSequenceNumber Ascending sequence number
 *                           that identifies the current probing cycle.
 * 20 (8)    2               SenderID Unique ID within a team identifying
 *                           the member that originally sent the probe.
 * 22 (10)   6               TeamID Unique ID identifying the team in charge
 *                           of this probe.
 * 28        Padding         Reserved
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/etypes.h>

void proto_register_ans(void);
void proto_reg_handoff_ans(void);

static dissector_handle_t ans_handle;

/* Initialize the protocol and registered fields */
static int proto_ans;

static int hf_ans_app_id;
static int hf_ans_rev_id;
static int hf_ans_seq_num;
static int hf_ans_sender_id;
static int hf_ans_team_id;

/* Initialize the subtree pointers */
static int ett_ans;

/* Code to actually dissect the packets */
static int
dissect_ans(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item  *ti;
	proto_tree  *ans_tree;
	uint16_t     sender_id;
	uint32_t     seq_num;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Intel ANS probe");

	seq_num = tvb_get_ntohl(tvb, 4);
	sender_id = tvb_get_ntohs(tvb, 8);

	col_add_fstr(pinfo->cinfo, COL_INFO, "Sequence: %u, Sender ID %u, Team ID %s",
		seq_num, sender_id, tvb_ether_to_str(pinfo->pool, tvb, 10));

	ti = proto_tree_add_item(tree, proto_ans, tvb, 0, -1, ENC_NA);
	ans_tree = proto_item_add_subtree(ti, ett_ans);

	proto_tree_add_item(ans_tree, hf_ans_app_id, tvb, 0, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(ans_tree, hf_ans_rev_id, tvb, 2, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(ans_tree, hf_ans_seq_num, tvb, 4, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(ans_tree, hf_ans_sender_id, tvb, 8, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(ans_tree, hf_ans_team_id, tvb, 10, 6, ENC_NA);

	return tvb_captured_length(tvb);
}


void
proto_register_ans(void)
{
	static hf_register_info hf[] = {
		{ &hf_ans_app_id,
			{ "Application ID", "ans.app_id",
				FT_UINT16, BASE_HEX, NULL, 0,
				"Intel ANS Application ID", HFILL }
		},
		{ &hf_ans_rev_id,
			{ "Revision ID", "ans.rev_id",
				FT_UINT16, BASE_HEX, NULL, 0,
				"Intel ANS Revision ID", HFILL }
		},
		{ &hf_ans_seq_num,
			{ "Sequence Number", "ans.seq_num",
				FT_UINT32, BASE_DEC, NULL, 0,
				"Intel ANS Sequence Number", HFILL }
		},
		{ &hf_ans_sender_id,
			{ "Sender ID", "ans.sender_id",
				FT_UINT16, BASE_DEC, NULL, 0,
				"Intel ANS Sender ID", HFILL }
		},
		{ &hf_ans_team_id,
			{ "Team ID", "ans.team_id",
				FT_ETHER, BASE_NONE, NULL, 0,
				"Intel ANS Team ID", HFILL }
		},
	};

	static int *ett[] = {
		&ett_ans,
	};

	proto_ans = proto_register_protocol("Intel ANS probe", "ANS", "ans");
	proto_register_field_array(proto_ans, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	ans_handle = register_dissector("ans", dissect_ans, proto_ans);
}


void
proto_reg_handoff_ans(void)
{
	dissector_add_uint("ethertype", ETHERTYPE_INTEL_ANS, ans_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
