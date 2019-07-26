/* packet-cvspserver.c
 * Routines for CVS password server packet dissection
 * Copyright 2018, Jaap Keuter <jaap.keuter@xs4all.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#define CVSPSERVER_PORT_TCP 2401

void proto_register_cvspserver(void);
void proto_reg_handoff_cvspserver(void);

static int proto_cvspserver = -1;

static int hf_cvspserver_data = -1;

static gint ett_cvspserver = -1;

static int
dissect_cvspserver(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* dissector_data _U_)
{
	proto_tree* cvspserver_tree;
	proto_item* ti;
	gint length;
	gint next_offset, offset;
	guint lines = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CVSPSERVER");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_cvspserver, tvb, 0, -1, ENC_NA);
	cvspserver_tree = proto_item_add_subtree(ti, ett_cvspserver);

	for (offset = 0; tvb_offset_exists(tvb, offset); offset = next_offset)
	{
		length = tvb_find_line_end_unquoted(tvb, offset, -1, &next_offset);
		proto_tree_add_item(cvspserver_tree, hf_cvspserver_data, tvb, offset, length, ENC_UTF_8|ENC_NA);
		lines++;
	}

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s %u",
	             (pinfo->srcport == pinfo->match_uint) ? "Response lines:" : "Request lines :",
	             lines);

	proto_item_append_text(ti, " %s",
	                       (pinfo->srcport == pinfo->match_uint) ? "Response" : "Request");

	return tvb_captured_length(tvb);
}

void
proto_register_cvspserver(void)
{
	static hf_register_info hf[] = {
		{ &hf_cvspserver_data, {
			"Data", "cvspserver.data", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }}
		};

	static gint *ett[] = {
		&ett_cvspserver
	};

	proto_cvspserver = proto_register_protocol("CVS pserver", "cvspserver", "cvspserver");
	proto_register_field_array(proto_cvspserver, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_cvspserver(void)
{
	dissector_handle_t cvspserver_handle;

	cvspserver_handle = create_dissector_handle(dissect_cvspserver, proto_cvspserver);
	dissector_add_uint_with_preference("tcp.port", CVSPSERVER_PORT_TCP, cvspserver_handle);
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
