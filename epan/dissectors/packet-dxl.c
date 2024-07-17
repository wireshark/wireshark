/* packet-dxl.c
 *
 * Routines for DXL dissection
 * Github projects:
 *  https://github.com/opendxl
 *
 * Copyright 2018, Dario Lombardo <lomato@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/tvbuff.h>
#include <epan/expert.h>

void proto_register_dxl(void);
void proto_reg_handoff_dxl(void);

static int proto_dxl;

static int hf_dxl_version;
static int hf_dxl_type;

static int ett_dxl;

static expert_field ei_dxl_unsupported;

static dissector_handle_t msgpack_handle;

#define DXL_REQUEST 0
#define DXL_RESPONSE 1
#define DXL_EVENT 2
#define DXL_ERROR 3

static const value_string dxl_message_types[] = {
	{ DXL_REQUEST, "Request" },
	{ DXL_RESPONSE, "Response" },
	{ DXL_EVENT, "Event" },
	{ DXL_ERROR, "Error" },
	{ 0, NULL }
};

static void dissect_dxl_event(tvbuff_t* tvb, packet_info* pinfo, proto_tree* dxl_tree, int* offset)
{
	tvbuff_t* tvb_msgpack;

	tvb_msgpack = tvb_new_subset_remaining(tvb, *offset);
	*offset = call_dissector_with_data(msgpack_handle, tvb_msgpack, pinfo, dxl_tree, "Message ID");

	tvb_msgpack = tvb_new_subset_remaining(tvb_msgpack, *offset);
	*offset = call_dissector_with_data(msgpack_handle, tvb_msgpack, pinfo, dxl_tree, "Client ID");

	tvb_msgpack = tvb_new_subset_remaining(tvb_msgpack, *offset);
	*offset = call_dissector_with_data(msgpack_handle, tvb_msgpack, pinfo, dxl_tree, "Source Broker ID");

	tvb_msgpack = tvb_new_subset_remaining(tvb_msgpack, *offset);
	*offset = call_dissector_with_data(msgpack_handle, tvb_msgpack, pinfo, dxl_tree, "Broker IDs");

	tvb_msgpack = tvb_new_subset_remaining(tvb_msgpack, *offset);
	*offset = call_dissector_with_data(msgpack_handle, tvb_msgpack, pinfo, dxl_tree, "Client IDs");

	tvb_msgpack = tvb_new_subset_remaining(tvb_msgpack, *offset);
	*offset = call_dissector_with_data(msgpack_handle, tvb_msgpack, pinfo, dxl_tree, "Payload");

	tvb_msgpack = tvb_new_subset_remaining(tvb_msgpack, *offset);
	*offset = call_dissector_with_data(msgpack_handle, tvb_msgpack, pinfo, dxl_tree, "Reply to topic");

	tvb_msgpack = tvb_new_subset_remaining(tvb_msgpack, *offset);
	*offset = call_dissector_with_data(msgpack_handle, tvb_msgpack, pinfo, dxl_tree, "Service ID");
}

static int dissect_dxl(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
	int offset = 0;
	proto_item* ti;
	proto_tree* dxl_tree;
	uint8_t type;

	ti = proto_tree_add_item(tree, proto_dxl, tvb, 0, -1, ENC_NA);
	dxl_tree = proto_item_add_subtree(ti, ett_dxl);

	proto_tree_add_item(dxl_tree, hf_dxl_version, tvb, offset, 1, ENC_NA);
	offset += 1;

	type = tvb_get_uint8(tvb, offset);

	proto_tree_add_item(dxl_tree, hf_dxl_type, tvb, offset, 1, ENC_NA);
	offset += 1;

	switch (type) {
		case DXL_REQUEST:
		case DXL_RESPONSE:
		case DXL_ERROR:
			expert_add_info_format(pinfo, tree, &ei_dxl_unsupported, "Type 0x%x is unsupported", type);
			break;
		case DXL_EVENT:
			dissect_dxl_event(tvb, pinfo, dxl_tree, &offset);
			break;
	}

	return offset;
}

void proto_reg_handoff_dxl(void)
{
	msgpack_handle = find_dissector("msgpack");
}

void proto_register_dxl(void)
{
	expert_module_t* expert_dxl;

	static hf_register_info hf[] = {
		{ &hf_dxl_version,
			{ "Version", "dxl.version", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_dxl_type,
			{ "Type", "dxl.type", FT_UINT8, BASE_HEX, VALS(dxl_message_types), 0x00, NULL, HFILL }
		}
	};

	static int* ett[] = {
		&ett_dxl
	};

	proto_dxl = proto_register_protocol("Data Exchange Layer", "DXL", "dxl");
	register_dissector("dxl", dissect_dxl, proto_dxl);

	proto_register_field_array(proto_dxl, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	static ei_register_info ei[] = {
		{ &ei_dxl_unsupported, { "dxl.type.unsupported", PI_UNDECODED, PI_WARN, "Unsupported DXL message", EXPFILL }}
	};

	expert_dxl = expert_register_protocol(proto_dxl);
	expert_register_field_array(expert_dxl, ei, array_length(ei));
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
