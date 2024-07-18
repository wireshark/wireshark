/* packet-hbbak.c
 * Routines for ethertype 0x8988 Paloalto heartbeat backup traffic via mgmt
 *
 * Copyright 2020 Joerg Mayer (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* 2do:
 * - Find out the meaning of the 6 bytes header: timestamp?
 * - Handle trailer bytes correctly
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>

void proto_reg_handoff_hbbak(void);
void proto_register_hbbak(void);

#define PROTO_SHORT_NAME "PA-HB-Bak"
#define PROTO_LONG_NAME "Palo Alto Heartbeat Backup"

#define HBBAK_SIZE 8

static int proto_hbbak;
static int hf_hbbak_unknown1;
static int hf_hbbak_etype_outer;
static int hf_hbbak_trailer;

static int ett_hbbak;

static dissector_handle_t hbbak_handle;
static dissector_handle_t ethertype_handle;

static int
dissect_hbbak(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree *ti, *hbbak_tree;
	int offset = 0;
	uint16_t eth_type_outer;
	ethertype_data_t ethertype_data;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
	col_clear(pinfo->cinfo, COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, PROTO_LONG_NAME);

	hbbak_tree = NULL;
	ti = proto_tree_add_item(tree, proto_hbbak, tvb, offset, HBBAK_SIZE, ENC_NA);
	hbbak_tree = proto_item_add_subtree(ti, ett_hbbak);

	proto_tree_add_item(hbbak_tree, hf_hbbak_unknown1, tvb, offset, 6, ENC_NA);
	offset += 6;
	eth_type_outer = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint(hbbak_tree, hf_hbbak_etype_outer, tvb,
			    offset, 2, eth_type_outer);

	ethertype_data.etype = eth_type_outer;
	ethertype_data.payload_offset = HBBAK_SIZE;
	ethertype_data.fh_tree = hbbak_tree;
	ethertype_data.trailer_id = hf_hbbak_trailer;
	ethertype_data.fcs_len = 0;

	call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);

	return tvb_captured_length(tvb);
}

void
proto_register_hbbak(void)
{
	static hf_register_info hf[] = {
		{ &hf_hbbak_unknown1,
		{ "Unknown1", "hbbak.unknown1", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_hbbak_etype_outer,
		{ "Type", "hbbak.etype", FT_UINT16, BASE_HEX, VALS(etype_vals),
			0x0, NULL, HFILL }},

		{ &hf_hbbak_trailer,
		{ "Trailer", "hbbak.trailer", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

	};

	static int *ett[] = {
		&ett_hbbak,
	};

	proto_hbbak = proto_register_protocol(PROTO_LONG_NAME, PROTO_LONG_NAME, "hbbak");
	proto_register_field_array(proto_hbbak, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	hbbak_handle = register_dissector("hbbak", dissect_hbbak, proto_hbbak);
}

void
proto_reg_handoff_hbbak(void)
{

	ethertype_handle = find_dissector_add_dependency("ethertype", proto_hbbak);

	dissector_add_uint("ethertype", ETHERTYPE_PA_HBBACKUP, hbbak_handle);
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
