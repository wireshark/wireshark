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

void proto_register_gift(void);
void proto_reg_handoff_gift(void);

#define TCP_PORT_GIFT 1213

static int proto_gift = -1;
static int hf_gift_response = -1;
static int hf_gift_request = -1;

static gint ett_gift = -1;
static gint ett_gift_cmd = -1;

static void
dissect_gift(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*ti, *hidden_item;
	proto_tree	*gift_tree, *cmd_tree;
	gboolean	is_request;
	gint            offset = 0;
	const guchar    *line;
	gint            next_offset;
	int             linelen;
	int             tokenlen;
	const guchar    *next_token;

	/* set "Protocol" column text */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "giFT");

	/* determine whether it is a request to or response from the server */
	if (pinfo->match_uint == pinfo->destport)
		is_request = TRUE;
	else
		is_request = FALSE;

	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
	line = tvb_get_ptr(tvb, offset, linelen);

	/* set "Info" column text */
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
			     is_request ? "Request" : "Response",
			     format_text(line, linelen));

	/* if tree != NULL, build protocol tree */
	if (tree) {
		ti = proto_tree_add_item(tree, proto_gift, tvb, 0, -1, ENC_NA);
		gift_tree = proto_item_add_subtree(ti, ett_gift);

		if (is_request) {
			hidden_item = proto_tree_add_boolean(gift_tree, hf_gift_request, tvb, 0, 0, TRUE);
		} else {
			hidden_item = proto_tree_add_boolean(gift_tree, hf_gift_response, tvb, 0, 0, TRUE);
		}
		PROTO_ITEM_SET_HIDDEN(hidden_item);

		ti = proto_tree_add_format_text(gift_tree, tvb, offset, next_offset - offset);
		cmd_tree = proto_item_add_subtree(ti, ett_gift_cmd);

		tokenlen = get_token_len(line, line + linelen, &next_token);
		if (tokenlen != 0) {
			if (is_request) {
				proto_tree_add_text(cmd_tree, tvb, offset,
						    tokenlen, "Request Command: %s",
						    format_text(line, tokenlen));
			} else {
				proto_tree_add_text(cmd_tree, tvb, offset,
						    tokenlen, "Response Command: %s",
						    format_text(line, tokenlen));
			}
			offset += (gint) (next_token - line);
			linelen -= (int) (next_token - line);
			line = next_token;
		}

		if (linelen != 0) {
			if (is_request) {
				proto_tree_add_text(cmd_tree, tvb, offset,
						    linelen, "Request Arg: %s",
						    format_text(line, linelen));
			} else {
				proto_tree_add_text(cmd_tree, tvb, offset,
						    linelen, "Response Arg: %s",
						    format_text(line, linelen));
			}
		}
	}
}

void
proto_register_gift(void)
{
	static hf_register_info hf[] = {
		{ &hf_gift_response,
			{ "Response", "gift.response", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "TRUE if giFT response", HFILL }
		},
		{ &hf_gift_request,
			{ "Request", "gift.request", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "TRUE if giFT request", HFILL }
		}
	};

	static gint *ett[] = {
		&ett_gift,
		&ett_gift_cmd,
	};

	proto_gift = proto_register_protocol("giFT Internet File Transfer",
					     "giFT", "gift");

	proto_register_field_array(proto_gift, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_gift(void)
{
	dissector_handle_t gift_handle;

	gift_handle = create_dissector_handle(dissect_gift, proto_gift);
	dissector_add_uint("tcp.port", TCP_PORT_GIFT, gift_handle);
}
