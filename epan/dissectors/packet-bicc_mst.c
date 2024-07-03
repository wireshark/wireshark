/* packet-bicc_mst.c
 * (Incomplete) Dissector for the 3GPP TS 29.205 BICC MST (Mobile Service Transport)
 *
 * This currently only dissects a single MST IE, which is required by the BSSMAP
 * dissector in order to decode the LCLS (Local Call Local Switch)
 * GCR (Global Call Reference)
 *
 * Copyright 2019 by Harald Welte <laforge@gnumonks.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/expert.h>

#include "packet-bicc_mst.h"

void proto_register_bicc_mst(void);

static int proto_bicc_mst;

static int hf_lcls_gcr_network_id_len;
static int hf_lcls_gcr_network_id;
static int hf_lcls_gcr_node_id_len;
static int hf_lcls_gcr_node_id;
static int hf_lcls_gcr_call_ref_id_len;
static int hf_lcls_gcr_call_ref_id;

static int ett_lcls_gcr;

unsigned
dissect_bicc_mst_lcls_gcr(tvbuff_t *tvb, proto_tree *tree, uint32_t offset, unsigned len)
{
	unsigned net_id_len, node_id_len, call_ref_id_len;
	uint32_t curr_offset = offset;
	proto_tree *subtree;
	proto_item *ti;

	ti = proto_tree_add_protocol_format(tree, proto_bicc_mst, tvb, offset, len, "BICC MST GCR");
	subtree = proto_item_add_subtree(ti, ett_lcls_gcr);

	proto_tree_add_item_ret_uint(subtree, hf_lcls_gcr_network_id_len, tvb, curr_offset++, 1, ENC_NA, &net_id_len);
	proto_tree_add_item(subtree, hf_lcls_gcr_network_id, tvb, curr_offset, net_id_len, ENC_NA);
	curr_offset += net_id_len;

	proto_tree_add_item_ret_uint(subtree, hf_lcls_gcr_node_id_len, tvb, curr_offset++, 1, ENC_NA, &node_id_len);
	proto_tree_add_item(subtree, hf_lcls_gcr_node_id, tvb, curr_offset, node_id_len, ENC_NA);
	curr_offset += node_id_len;

	proto_tree_add_item_ret_uint(subtree, hf_lcls_gcr_call_ref_id_len, tvb, curr_offset++, 1, ENC_NA, &call_ref_id_len);
	proto_tree_add_item(subtree, hf_lcls_gcr_call_ref_id, tvb, curr_offset, call_ref_id_len, ENC_NA);
	curr_offset += call_ref_id_len;

	return curr_offset - offset;
}

void
proto_register_bicc_mst(void)
{
	static hf_register_info hf[] = {
		{ &hf_lcls_gcr_network_id_len, { "Length of LCLS GCR Network ID",
		  "bicc_mst.lcls_gcr.network_id_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_lcls_gcr_network_id, { "LCLS GCR Network ID",
		  "bicc_mst.lcls_gcr.network_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_lcls_gcr_node_id_len, { "Length of LCLS GCR Node ID",
		  "bicc_mst.lcls_gcr.node_id_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_lcls_gcr_node_id, { "LCLS GCR Network ID",
		  "bicc_mst.lcls_gcr.network_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_lcls_gcr_call_ref_id_len, { "Length of LCLS GCR Call Ref ID",
		  "bicc_mst.lcls_gcr.call_ref_id_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_lcls_gcr_call_ref_id, { "LCLS GCR Call Ref ID",
		  "bicc_mst.lcls_gcr.call_ref_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_lcls_gcr,
	};

	proto_bicc_mst = proto_register_protocol("3GPP BICC MST", "BICC-MST", "bicc_mst");
	proto_register_field_array(proto_bicc_mst, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
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
