/* TODO mix direction bit into the chandle tree lookup   so we can handle when fragments sent in both directions simultaneously on the same chandle */

/* packet-btacl_acl.c
 * Routines for the Bluetooth ACL dissection
 * Copyright 2002, Christoph Scholz <scholz@cs.uni-bonn.de>
 *  From: http://affix.sourceforge.net/archive/ethereal_affix-3.patch
 *
 * Refactored for wireshark checkin
 *   Ronnie Sahlberg 2006
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/prefs.h>
#include <etypes.h>
#include <packet-hci_h4.h>
#include <packet-bthci_acl.h>

/* Initialize the protocol and registered fields */
static int proto_btacl = -1;
static int hf_btacl_chandle = -1;
static int hf_btacl_pb_flag = -1;
static int hf_btacl_bc_flag = -1;
static int hf_btacl_length = -1;
static int hf_btacl_data = -1;
static int hf_btacl_continuation_to = -1;
static int hf_btacl_reassembled_in = -1;

/* Initialize the subtree pointers */
static gint ett_btacl = -1;

static dissector_handle_t btl2cap_handle=NULL;

static gboolean acl_reassembly = TRUE;

typedef struct _multi_fragment_pdu_t {
	guint32 first_frame;
	guint32 last_frame;
	guint16 tot_len;
	char *reassembled;
	int cur_off;	/* counter used by reassembly */
} multi_fragment_pdu_t;

typedef struct _chandle_data_t {
	emem_tree_t *start_fragments;  /* indexed by pinfo->fd->num */
} chandle_data_t;

static emem_tree_t *chandle_tree=NULL;

static const value_string pb_flag_vals[] = {
	{1, "Continuing Fragment"},
	{2, "Start Fragment"},
	{0, NULL }
};

static const value_string bc_flag_vals[] = {
	{0, "Point-To-Point"},
	{1, "Active Broadcast"},
	{2, "Piconet Broadcast"},
	{0, NULL }
};



/* Code to actually dissect the packets */
static void 
dissect_btacl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti=NULL;
	proto_tree *btacl_tree=NULL;
	guint16 flags, length;
	gboolean fragmented;
	int offset=0;
	guint16 pb_flag, l2cap_length=0;
	tvbuff_t *next_tvb;
	bthci_acl_data_t *acl_data;
	chandle_data_t *chandle_data;

	if(check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_ACL");
	}

	if(tree){
		ti=proto_tree_add_item(tree, proto_btacl, tvb, offset, -1, FALSE);
		btacl_tree = proto_item_add_subtree(ti, ett_btacl);
	}

	flags=tvb_get_letohs(tvb, offset);
	pb_flag = (flags & 0x3000) >> 12;
	proto_tree_add_item(btacl_tree, hf_btacl_chandle, tvb, offset, 2, TRUE);
	proto_tree_add_item(btacl_tree, hf_btacl_pb_flag, tvb, offset, 2, TRUE);
	proto_tree_add_item(btacl_tree, hf_btacl_bc_flag, tvb, offset, 2, TRUE);
	offset+=2;

	acl_data=ep_alloc(sizeof(bthci_acl_data_t));
	acl_data->chandle=flags&0x0fff;
	pinfo->private_data=acl_data;

	/* find the chandle_data structure associated with this chandle */
	chandle_data=se_tree_lookup32(chandle_tree, acl_data->chandle);
	if(!chandle_data){
		chandle_data=se_alloc(sizeof(chandle_data_t));
		chandle_data->start_fragments=se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "bthci_acl fragment starts");
		se_tree_insert32(chandle_tree, acl_data->chandle, chandle_data);
	}

	length = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(btacl_tree, hf_btacl_length, tvb, offset, 2, TRUE);
	offset+=2;

	/* determine if packet is fragmented */
	switch(pb_flag){
	case 0x01:	/* Continuation fragment */
		fragmented = TRUE;
		break;
	case 0x02:	/* Start fragment */
		l2cap_length=tvb_get_letohs(tvb, offset);
		fragmented=((l2cap_length+4)!=length);	
		break;
	default:
		/* unknown pb_flag */
		fragmented = FALSE;
	}


	if((!fragmented)
	|| ((!acl_reassembly)&&(pb_flag==0x02)) ){
		/* call L2CAP dissector for PDUs that are not fragmented
		 * also for the first fragment if reassembly is disabled
		 */
		next_tvb=tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), length);
		if(btl2cap_handle){
			call_dissector(btl2cap_handle, next_tvb, pinfo, tree);
		}
		return;
	}

	if(fragmented && acl_reassembly){
		multi_fragment_pdu_t *mfp=NULL;

		if(pb_flag==0x02){ /* first fragment */
			if(!pinfo->fd->flags.visited){
				mfp=se_alloc(sizeof(multi_fragment_pdu_t));
				mfp->first_frame=pinfo->fd->num;
				mfp->last_frame=0;
				mfp->tot_len=l2cap_length+4;
				mfp->reassembled=se_alloc(l2cap_length+4);
				tvb_memcpy(tvb, mfp->reassembled, offset, tvb_length_remaining(tvb, offset));
				mfp->cur_off=tvb_length_remaining(tvb, offset);
				se_tree_insert32(chandle_data->start_fragments, pinfo->fd->num, mfp);
			} else {
				mfp=se_tree_lookup32(chandle_data->start_fragments, pinfo->fd->num);
			}
			if(mfp && mfp->last_frame){
				proto_item *item;
				item=proto_tree_add_uint(btacl_tree, hf_btacl_reassembled_in, tvb, 0, 0, mfp->last_frame);
				PROTO_ITEM_SET_GENERATED(item);
				if (check_col(pinfo->cinfo, COL_INFO)){
					col_append_fstr(pinfo->cinfo, COL_INFO, "[Reassembled in #%u] ", mfp->last_frame);
				}
			}
		}
		if(pb_flag==0x01){ /* continuation fragment */
			mfp=se_tree_lookup32_le(chandle_data->start_fragments, pinfo->fd->num);
			if(!pinfo->fd->flags.visited){
				if(mfp && !mfp->last_frame && (mfp->tot_len>=mfp->cur_off+tvb_length_remaining(tvb, offset))){
					tvb_memcpy(tvb, mfp->reassembled+mfp->cur_off, offset, tvb_length_remaining(tvb, offset));
					mfp->cur_off+=tvb_length_remaining(tvb, offset);
					if(mfp->cur_off==mfp->tot_len){
						mfp->last_frame=pinfo->fd->num;
					}
				}
			}
			if(mfp){
				proto_item *item;
				item=proto_tree_add_uint(btacl_tree, hf_btacl_continuation_to, tvb, 0, 0, mfp->first_frame);
				PROTO_ITEM_SET_GENERATED(item);
				if (check_col(pinfo->cinfo, COL_INFO)){
					col_append_fstr(pinfo->cinfo, COL_INFO, "[Continuation to #%u] ", mfp->first_frame);
				}
			}
			if(mfp && mfp->last_frame==pinfo->fd->num){
				next_tvb = tvb_new_real_data(mfp->reassembled, mfp->tot_len, mfp->tot_len);
				tvb_set_child_real_data_tvbuff(tvb, next_tvb);
				add_new_data_source(pinfo, next_tvb, "Reassembled BTHCI ACL");

				/* call L2CAP dissector */
				if(btl2cap_handle){
					call_dissector(btl2cap_handle, next_tvb, pinfo, tree);
				}
			}
		}
	}
}


void
proto_register_btacl(void)
{                 

	/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_btacl_chandle,
			{ "Connection Handle",           "btacl.chandle",
				FT_UINT16, BASE_HEX, NULL, 0x0FFF,          
				"Connection Handle", HFILL }
		},
		{ &hf_btacl_pb_flag,
			{ "PB Flag",           "btacl.pb_flag",
				FT_UINT16, BASE_DEC, VALS(pb_flag_vals), 0x3000,          
				"Packet Boundary Flag", HFILL }
		},
		{ &hf_btacl_bc_flag,
			{ "BC Flag",           "btacl.bc_flag",
				FT_UINT16, BASE_DEC, VALS(bc_flag_vals), 0xC000,          
				"Broadcast Flag", HFILL }
		},
		{ &hf_btacl_length,
			{ "Data Total Length",           "btacl.length",
				FT_UINT16, BASE_DEC, NULL, 0x0,          
				"Data Total Length", HFILL }
		},
		{ &hf_btacl_data,
			{ "Data",           "btacl.data",
				FT_NONE, BASE_NONE, NULL, 0x0,
				"Data", HFILL }
		},
		{ &hf_btacl_continuation_to,
			{ "This is a continuation to the PDU in frame",		"btacl.continuation_to", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"This is a continuation to the PDU in frame #", HFILL }},
		{ &hf_btacl_reassembled_in,
			{ "This PDU is reassembled in frame",		"btacl.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"This PDU is reassembled in frame #", HFILL }},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_btacl,
	};
	module_t *btacl_module;

	/* Register the protocol name and description */
	proto_btacl = proto_register_protocol("Bluetooth HCI ACL Packet", "HCI_ACL", "bthci_acl");
	register_dissector("bthci_acl", dissect_btacl, proto_btacl);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_btacl, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register configuration preferences */
	btacl_module = prefs_register_protocol(proto_btacl, NULL);
	prefs_register_bool_preference(btacl_module, "btacl_reassembly",
	    "Reassemble ACL Fragments",
	    "Whether the ACL dissector should reassemble fragmented PDUs",
	    &acl_reassembly);

	chandle_tree=se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "bthci_acl chandles");
}


void
proto_reg_handoff_btacl(void)
{
	dissector_handle_t bthci_acl_handle;

	bthci_acl_handle = find_dissector("bthci_acl");
	dissector_add("hci_h4.type", HCI_H4_TYPE_ACL, bthci_acl_handle);


	btl2cap_handle = find_dissector("btl2cap");
}


