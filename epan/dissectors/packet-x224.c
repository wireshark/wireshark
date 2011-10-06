/* packet-x224.c
 *
 * Routine to dissect X.224
 * Copyright 2007, Ronnie Sahlberg
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include "packet-tpkt.h"
#include "packet-frame.h"
#include <epan/conversation.h>
#include <epan/emem.h>

/* X.224 header fields             */
static int proto_x224			= -1;
static int hf_x224_length		= -1;
static int hf_x224_code			= -1;
static int hf_x224_src_ref		= -1;
static int hf_x224_dst_ref		= -1;
static int hf_x224_class		= -1;
static int hf_x224_rdp_rt		= -1;
static int hf_x224_nr			= -1;
static int hf_x224_eot			= -1;



/* X.224 fields defining a sub tree */
static gint ett_x224           = -1;


/* find the dissector for T.125 */
static dissector_handle_t t125_handle;


typedef struct _x224_conv_info_t {
	guint8	class;
} x224_conv_info_t;


#define X224_CODE_CR		0xE
#define X224_CODE_CC		0xD
#define X224_CODE_DR		0x8
#define X224_CODE_DC		0xC
#define X224_CODE_DT		0xF
#define X224_CODE_ED		0x1
#define X224_CODE_AK		0x6
#define X224_CODE_EA		0x2
#define X224_CODE_RJ		0x5
#define X224_CODE_ER		0x7

static const value_string code_vals[] = {
	{X224_CODE_CR,		"Connection Request"},
	{X224_CODE_CC,		"Connection Confirm"},
	{X224_CODE_DR,		"Disconnect Request"},
	{X224_CODE_DC,		"Disconnect Confirm"},
	{X224_CODE_DT,		"Data"},
	{X224_CODE_ED,		"Expedited Data"},
	{X224_CODE_AK,		"Data Ack"},
	{X224_CODE_EA,		"Expedited Data Ack"},
	{X224_CODE_RJ,		"Reject"},
	{X224_CODE_ER,		"Error"},
	{0,NULL}
};

static const value_string class_option_vals[] = {
	{0,	"Class 0"},
	{1,	"Class 1"},
	{2,	"Class 2"},
	{3,	"Class 3"},
	{4,	"Class 4"},
	{0,NULL}
};

static int
dissect_x224_cr(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, x224_conv_info_t *x224_info _U_)
{
	/*guint8 class;*/
	gint len, next_offset;

	/*DST-REF is always 0 */
	offset+=2;

	/*SRC-REF*/
	proto_tree_add_item(tree, hf_x224_src_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;

	/* class options */
	/*class = tvb_get_guint8(tvb, offset);*/
	proto_tree_add_item(tree, hf_x224_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset+=1;

	if(tvb_length_remaining(tvb, offset) > 0) {
		len = tvb_find_line_end(tvb, offset, -1, &next_offset, TRUE);
		proto_tree_add_item(tree, hf_x224_rdp_rt, tvb, offset, len,
				    FALSE);
		offset = next_offset;
	}

	return offset;
}

static int
dissect_x224_cc(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, x224_conv_info_t *x224_info)
{
	guint8 class;

	/*DST-REF */
	proto_tree_add_item(tree, hf_x224_dst_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;

	/*SRC-REF*/
	proto_tree_add_item(tree, hf_x224_src_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;

	/* class options */
	class = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_x224_class, tvb, offset, 1, ENC_BIG_ENDIAN);
	x224_info->class = class;
	offset+=1;

	return offset;
}

static int
dissect_x224_dt(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, x224_conv_info_t *x224_info, proto_tree *parent_tree)
{
	proto_item *item = NULL;
	tvbuff_t *next_tvb;

	switch (x224_info->class >>4) {
	case 2:
	case 3:
	case 4:
		/*DST-REF */
		proto_tree_add_item(tree, hf_x224_dst_ref, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
		break;
	}

	item = proto_tree_add_uint(tree, hf_x224_class, tvb, 0, 0, x224_info->class);
	PROTO_ITEM_SET_GENERATED(item);


	/* EOT / NR */
	proto_tree_add_item(tree, hf_x224_eot, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_x224_nr, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset+=1;


	next_tvb = tvb_new_subset_remaining(tvb, offset);
	call_dissector(t125_handle, next_tvb, pinfo, parent_tree);

	return offset;
}

static void
dissect_x224(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_tree *tree = NULL;
	proto_item *item = NULL;
	int offset = 0 ;
	guint8 code, length;
	conversation_t *conversation;
	x224_conv_info_t *x224_info;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "X.224");
	col_clear(pinfo->cinfo, COL_INFO);

	length = tvb_get_guint8(tvb, offset);
	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, proto_x224, tvb, offset, length+1, FALSE);
		tree = proto_item_add_subtree(item, ett_x224);
	}


	/* length indicator */
	proto_tree_add_item(tree, hf_x224_length, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset+=1;

	/* code */
	code = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_x224_code, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset+=1;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s (0x%02x)",
			val_to_str(code>>4, code_vals, "Unknown code :%x"),
			code);
	}



	/*
	 * We need to track some state for this protocol on a per conversation
	 * basis so we can do neat things like request/response tracking
	 */
	conversation = find_or_create_conversation(pinfo);

	/*
	 * Do we already have a state structure for this conv
	 */
	x224_info = conversation_get_proto_data(conversation, proto_x224);
	if (!x224_info) {
		/* No.  Attach that information to the conversation, and add
		 * it to the list of information structures.
		 */
		x224_info = se_alloc(sizeof(x224_conv_info_t));
		x224_info->class=0;

		conversation_add_proto_data(conversation, proto_x224, x224_info);
       }

	switch (code>>4) {
	case X224_CODE_CR:
		offset = dissect_x224_cr(pinfo, tree, tvb, offset, x224_info);
		break;
	case X224_CODE_CC:
		offset = dissect_x224_cc(pinfo, tree, tvb, offset, x224_info);
		break;
	case X224_CODE_DR:
		/* XXX not implemented yet */
		break;
	case X224_CODE_DC:
		/* XXX not implemented yet */
		break;
	case X224_CODE_DT:
		offset = dissect_x224_dt(pinfo, tree, tvb, offset, x224_info, parent_tree);
		break;
	case X224_CODE_ED:
		/* XXX not implemented yet */
		break;
	case X224_CODE_AK:
		/* XXX not implemented yet */
		break;
	case X224_CODE_EA:
		/* XXX not implemented yet */
		break;
	case X224_CODE_RJ:
		/* XXX not implemented yet */
		break;
	case X224_CODE_ER:
		/* XXX not implemented yet */
		break;
	}
}

void
proto_register_x224(void)
{
	static hf_register_info hf[] =
	{
	{ &hf_x224_length, {
	"Length", "x224.length", FT_UINT8, BASE_DEC,
	NULL, 0, NULL, HFILL }},

	{ &hf_x224_code, {
	"Code", "x224.code", FT_UINT8, BASE_HEX,
	VALS(code_vals), 0xf0, NULL, HFILL }},

	{ &hf_x224_src_ref, {
	"SRC-REF", "x224.src_ref", FT_UINT16, BASE_HEX,
	NULL, 0, NULL, HFILL }},

	{ &hf_x224_dst_ref, {
	"DST-REF", "x224.dst_ref", FT_UINT16, BASE_HEX,
	NULL, 0, NULL, HFILL }},

	{ &hf_x224_class, {
	"Class", "x224.class", FT_UINT8, BASE_HEX,
	VALS(class_option_vals), 0xf0, NULL, HFILL }},

	{ &hf_x224_rdp_rt, {
	"RDP Routing Token", "x224.rdp_rt", FT_STRING, BASE_NONE, NULL, 0,
	"Used for Remote Desktop Protocol (RDP) load balancing", HFILL }},

	{ &hf_x224_nr, {
	"NR", "x224.nr", FT_UINT8, BASE_HEX,
	NULL, 0x7f, NULL, HFILL }},

	{ &hf_x224_eot, {
	"EOT", "x224.eot", FT_BOOLEAN, 8,
	NULL, 0x80, NULL, HFILL }},

	};

	static gint *ett[] =
	{
		&ett_x224,
	};

	proto_x224 = proto_register_protocol("ITU-T Rec X.224", "X.224", "x224");
	proto_register_field_array(proto_x224, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("x224", dissect_x224, proto_x224);

}

void
proto_reg_handoff_x224(void)
{
	t125_handle = find_dissector("t125");
}
