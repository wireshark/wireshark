/* packet-gift.c
 * Routines for giFT Internet File Transfer dissection
 * Copyright 2000, Jon Oberheide <jon@oberheide.org>
 *
 * See http://www.giftproject.org/
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>

void proto_register_gift(void);
void proto_reg_handoff_gift(void);

static dissector_handle_t gift_handle;

#define TCP_PORT_GIFT 1213 /* Not IANA registered */

static int proto_gift;
static int hf_gift_response;
static int hf_gift_request;
static int hf_gift_response_cmd;
static int hf_gift_response_arg;
static int hf_gift_request_cmd;
static int hf_gift_request_arg;

static int ett_gift;
static int ett_gift_cmd;

static int
dissect_gift(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item	*ti, *hidden_item;
	proto_tree	*gift_tree, *cmd_tree;
	bool	is_request;
	int             offset = 0;
	const unsigned char    *line;
	int             next_offset;
	int             linelen;
	int             tokenlen;
	const unsigned char    *next_token;

	/* set "Protocol" column text */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "giFT");

	/* determine whether it is a request to or response from the server */
	if (pinfo->match_uint == pinfo->destport)
		is_request = true;
	else
		is_request = false;

	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, false);
	line = tvb_get_ptr(tvb, offset, linelen);

	/* set "Info" column text */
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
			     is_request ? "Request" : "Response",
			     format_text(pinfo->pool, line, linelen));

	/* if tree != NULL, build protocol tree */
	if (tree) {
		ti = proto_tree_add_item(tree, proto_gift, tvb, 0, -1, ENC_NA);
		gift_tree = proto_item_add_subtree(ti, ett_gift);

		if (is_request) {
			hidden_item = proto_tree_add_boolean(gift_tree, hf_gift_request, tvb, 0, 0, true);
		} else {
			hidden_item = proto_tree_add_boolean(gift_tree, hf_gift_response, tvb, 0, 0, true);
		}
		proto_item_set_hidden(hidden_item);

		ti = proto_tree_add_format_text(gift_tree, tvb, offset, next_offset - offset);
		cmd_tree = proto_item_add_subtree(ti, ett_gift_cmd);

		tokenlen = get_token_len(line, line + linelen, &next_token);
		if (tokenlen != 0) {
			if (is_request) {
				proto_tree_add_string(cmd_tree, hf_gift_request_cmd, tvb, offset,
						    tokenlen, format_text(pinfo->pool, line, tokenlen));
			} else {
				proto_tree_add_string(cmd_tree, hf_gift_response_cmd, tvb, offset,
						    tokenlen, format_text(pinfo->pool, line, tokenlen));
			}
			offset += (int) (next_token - line);
			linelen -= (int) (next_token - line);
			line = next_token;
		}

		if (linelen != 0) {
			if (is_request) {
				proto_tree_add_string(cmd_tree, hf_gift_request_arg, tvb, offset,
						    linelen, format_text(pinfo->pool, line, linelen));
			} else {
				proto_tree_add_string(cmd_tree, hf_gift_response_arg, tvb, offset,
						    linelen, format_text(pinfo->pool, line, linelen));
			}
		}
	}
	return tvb_captured_length(tvb);
}

void
proto_register_gift(void)
{
	static hf_register_info hf[] = {
		{ &hf_gift_response,
			{ "Response", "gift.response", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "true if giFT response", HFILL }
		},
		{ &hf_gift_request,
			{ "Request", "gift.request", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "true if giFT request", HFILL }
		},
		{ &hf_gift_response_cmd,
			{ "Response Command", "gift.response_cmd", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_gift_response_arg,
			{ "Response Arg", "gift.response_arg", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_gift_request_cmd,
			{ "Request Command", "gift.request_cmd", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_gift_request_arg,
			{ "Request Arg", "gift.request_arg", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_gift,
		&ett_gift_cmd,
	};

	proto_gift = proto_register_protocol("giFT Internet File Transfer",
					     "giFT", "gift");

	proto_register_field_array(proto_gift, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	gift_handle = register_dissector("gift", dissect_gift, proto_gift);
}

void
proto_reg_handoff_gift(void)
{
	dissector_add_uint_with_preference("tcp.port", TCP_PORT_GIFT, gift_handle);
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
