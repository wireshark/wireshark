/* packet-drb.c
 *
 * Routines for Ruby Marshal Object
 *
 * Copyright 2018, Dario Lombardo (lomato@gmail.com)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <file-rbm.h>

static int proto_drb = -1;

static int hf_drb_len = -1;

static gint ett_drb = -1;
static gint ett_ref = -1;

void proto_register_drb(void);
void proto_reg_handoff_drb(void);

static void dissect_drb_object(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset, const gchar* label)
{
	guint32 len;
	proto_tree* obj_tree;
	gchar* type;
	gchar* value;

	len = tvb_get_guint32(tvb, *offset, ENC_BIG_ENDIAN);
	obj_tree = proto_tree_add_subtree(tree, tvb, *offset, 4 + len, ett_ref, NULL, label);
	proto_tree_add_item(obj_tree, hf_drb_len, tvb, *offset, 4, ENC_NA);
	*offset += 4;
	dissect_rbm_inline(tvb, pinfo, obj_tree, offset, &type, &value);
	if (type)
		proto_item_append_text(obj_tree, "Type: %s", type);
	if (value)
		proto_item_append_text(obj_tree, "Value: %s", value);
}

static void dissect_drb_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
	col_append_str(pinfo->cinfo, COL_INFO, " (response)");
	dissect_drb_object(tvb, pinfo, tree, offset, "Success");
	dissect_drb_object(tvb, pinfo, tree, offset, "Response");
}

static void dissect_drb_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, gint* offset)
{
	gint32 nargs;
	gint32 i;
	gint len;
	gchar* loop_label;

	col_append_str(pinfo->cinfo, COL_INFO, " (request)");
	dissect_drb_object(tvb, pinfo, tree, offset, "Ref");
	dissect_drb_object(tvb, pinfo, tree, offset, "Msg ID");
	get_rbm_integer(tvb, *offset + 4 + 3, &nargs, &len);
	dissect_drb_object(tvb, pinfo, tree, offset, "Arg length");
	for (i = 0; i < nargs; i++) {
		loop_label = wmem_strdup_printf(wmem_packet_scope(), "Arg %d", i + 1);
		dissect_drb_object(tvb, pinfo, tree, offset, loop_label);
	}
	dissect_drb_object(tvb, pinfo, tree, offset, "Block");
}

static int dissect_drb(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
	int offset = 0;
	proto_tree* ti;
	proto_tree* drb_tree;
	guint8 type;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DRb");
	col_clear(pinfo->cinfo, COL_INFO);
	col_set_str(pinfo->cinfo, COL_INFO, "Distributed Ruby");

	ti = proto_tree_add_item(tree, proto_drb, tvb, 0, -1, ENC_NA);
	drb_tree = proto_item_add_subtree(ti, ett_drb);

	type = tvb_get_guint8(tvb, 6);
	if (type == 'T' || type == 'F') {
		dissect_drb_response(tvb, pinfo, drb_tree, &offset);
	} else {
		dissect_drb_request(tvb, pinfo, drb_tree, &offset);
	}

	return offset;
}

void proto_register_drb(void)
{
	static hf_register_info hf[] = {
		{ &hf_drb_len,
			{ "Length", "drb.length", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint* ett[] = {
		&ett_drb,
		&ett_ref
	};

	proto_drb = proto_register_protocol("Distributed Ruby", "DRb", "drb");

	proto_register_field_array(proto_drb, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_drb(void)
{
	dissector_handle_t drb_handle;

	drb_handle = create_dissector_handle(dissect_drb, proto_drb);
	dissector_add_for_decode_as_with_preference("tcp.port", drb_handle);
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
