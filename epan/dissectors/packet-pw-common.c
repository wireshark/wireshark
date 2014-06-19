/* packet-pw-common.c
 * Common functions and objects for PWE3 dissectors.
 * Copyright 2009, Artem Tamazov <artem.tamazov@tellabs.com>
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

#include <epan/packet.h>
#include "packet-pw-common.h"

void proto_register_pw_padding(void);
void proto_reg_handoff_pw_padding(void);

static const char string_ok[] = "Ok";

const value_string
pwc_vals_cw_l_bit[] = {
	{ 0x0,	string_ok },
	{ 0x1,	"Attachment Circuit Fault" },
	{ 0,	NULL }
};


const value_string
pwc_vals_cw_r_bit[] = {
	{ 0x0,	string_ok },
	{ 0x1,	"Packet Loss State" },
	{ 0,	NULL }
};

const value_string
pwc_vals_cw_frag[] = {
	{ 0x0,	"Unfragmented" },
	{ 0x1,	"First fragment" },
	{ 0x2,	"Last fragment" },
	{ 0x3,	"Intermediate fragment" },
	{ 0,	NULL }
};


void pwc_item_append_cw(proto_item* item, const guint32 cw, const gboolean append_text)
{
	if (item != NULL)
	{
		if (append_text)
		{
			proto_item_append_text(item, ", CW");
		}
		proto_item_append_text(item, ": 0x%.8" G_GINT32_MODIFIER "x", cw);
	}
	return;
}


void pwc_item_append_text_n_items(proto_item* item, const int n, const char * const item_text)
{
	if (item != NULL)
	{
		if (n >=0)
		{
			proto_item_append_text(item, ", %d %s%s", n, item_text, plurality(n,"","s"));
		}
	}
	return;
}


static gint proto_pw_padding = -1;
static gint ett = -1;
static int hf_padding_len = -1;
static dissector_handle_t dh_data;

static
void dissect_pw_padding(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
	/* do not touch columns */
	if (tree)
	{
		gint size;
		proto_item* item;
		size = tvb_reported_length_remaining(tvb, 0);
		item = proto_tree_add_item(tree, proto_pw_padding, tvb, 0, -1, ENC_NA);
		pwc_item_append_text_n_items(item,size,"byte");
		{
			proto_tree* tree_p;
			tree_p = proto_item_add_subtree(item, ett);
			call_dissector(dh_data, tvb, pinfo, tree_p);
			item = proto_tree_add_int(tree_p, hf_padding_len, tvb, 0, 0, size);
			PROTO_ITEM_SET_HIDDEN(item); /*allow filtering*/
		}
	}
	return;
}

void proto_register_pw_padding(void)
{
	static hf_register_info hfpadding[] = {
		{&hf_padding_len	,{"Length"			,"pw.padding.len"
					,FT_INT32	,BASE_DEC	,NULL		,0
					,NULL						,HFILL }}
	};
	static gint *ett_array[] = {
		&ett
	};
	proto_pw_padding = proto_register_protocol("Pseudowire Padding","PW Padding","pw.padding");
	proto_register_field_array(proto_pw_padding, hfpadding, array_length(hfpadding));
	proto_register_subtree_array(ett_array, array_length(ett_array));
	register_dissector("pw_padding", dissect_pw_padding, proto_pw_padding);
	return;
}


void proto_reg_handoff_pw_padding(void)
{
	dh_data = find_dissector("data");
	return;
}
