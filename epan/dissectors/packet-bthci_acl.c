/* packet-btacl_acl.c
 * Routines for the Bluetooth ACL dissection
 * Copyright 2002, Christoph Scholz <scholz@cs.uni-bonn.de>
 *  From: http://affix.sourceforge.net/archive/ethereal_affix-3.patch
 *
 * Refactored for ethereal checkin
 *   Ronnie Sahlberg 2006
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include <etypes.h>
#include <packet-hci_h4.h>

/* Initialize the protocol and registered fields */
static int proto_btacl = -1;
static int hf_btacl_chandle = -1;
static int hf_btacl_pb_flag = -1;
static int hf_btacl_bc_flag = -1;
static int hf_btacl_length = -1;
static int hf_btacl_data = -1;

/* Initialize the subtree pointers */
static gint ett_btacl = -1;

dissector_handle_t btl2cap_handle=NULL;

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
	guint16 pb_flag, l2cap_length;
	tvbuff_t *next_tvb;

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


	length = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(btacl_tree, hf_btacl_length, tvb, offset, 2, TRUE);
	offset+=2;

	/* determine if packet is fragmented */
	switch(pb_flag){
	case 0x01:	/* Continuation fragment */
		fragmented = TRUE;
		break;
	case 0x02:	/* Start fragment */
		if(length < 2){
			fragmented=TRUE;
		} else {
			l2cap_length=tvb_get_letohs(tvb, offset);
			fragmented=((l2cap_length+4)!=length);
		}
		break;
	default:
		/* unknown pb_flag */
		fragmented = FALSE;
	}


	if(!fragmented){
		/* call L2CAP dissector */
		next_tvb=tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), length);
		if(btl2cap_handle){
			call_dissector(btl2cap_handle, next_tvb, pinfo, tree);
		}
		return;
	}


#ifdef REMOVED   offset==4 here
/* the code below should be rewritten from scratch once a doc explaining how fragmented bt packets work and example captures are collected.
*/
	guint16 chandle, handle;
	struct l2cap_packet *l2p;

	proto_tree_add_item(btacl_tree, hf_btacl_data, tvb, 4, -1, TRUE);

	if (pinfo->fd->flags.visited == 0) { /* This is the first pass */

		chandle = flags & 0x0FFF;

		/* same connection handle but differnet direction needs to be
		   distinguished, therefore we set the highest bit of the
		   handle for outgoing packets 
		 */
		if (pinfo->p2p_dir == P2P_DIR_RECV) {
			handle = chandle;
		} else {
			handle = chandle + 0x8000;
		}

		l2p = NULL;
		if (pb_flag == 2) { /* Start Fragment */
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_str(pinfo->cinfo, COL_INFO, " (Start Fragment)");

			if (get_l2p(handle)) { /* Error: There is still data for the same handle */
				fprintf(stderr, "Incomplete L2CAP packet detected: packet no. %d\n", pinfo->fd->num);
				del_l2p(handle, 1);
			}

			/* Start reassembly */
			if ((l2p = add_l2p(handle))) {
				l2p->pkt_len = 65540; /* Maybe we don't know the length now */
				/* So we have to set it to maximum */

				/* memcpy the data */
				tvb_memcpy(tvb, l2p->data, 4, length);
				l2p->rx_count = length;
			} else {
				fprintf(stderr, "no more handles!\n");
			}

		} else if (pb_flag == 1) { /* Continuing Fragment */
			if (!(l2p = get_l2p(handle))) { /* Error: Cont fragment without start */
				fprintf(stderr, "Cont. fragment without start detected!\n");
			} else {
				/* OK: Continue reassembly */
				/* memcpy the data */
				tvb_memcpy(tvb, l2p->data + l2p->rx_count, 4, length);
				l2p->rx_count += length;
			}
		}

		if (l2p) {
			if (l2p->rx_count > 1) /* We have collected enough bytes */
				l2p->pkt_len = (l2p->data[1] << 8) + l2p->data[0] + 4;

			if (l2p->rx_count > l2p->pkt_len) {
				fprintf(stderr, "Packet too long!\n");
				del_l2p(handle, 1);
				l2p = NULL;
			} else if (l2p->rx_count == l2p->pkt_len) {

				if (check_col(pinfo->cinfo, COL_INFO))
					col_append_str(pinfo->cinfo, COL_INFO, " (End Fragment)");

				del_l2p(handle, 0);
				/* save reassembled packet ???????? */
				p_add_proto_data(pinfo->fd, proto_btacl, l2p);
			} else { /* Packet is not complete */
				l2p = NULL;
				if (pb_flag == 1) {
					if (check_col(pinfo->cinfo, COL_INFO))
						col_append_str(pinfo->cinfo, COL_INFO, " (Continuation Fragment)");
				}
			}
		}
	} else { /* This is an additional pass */
		/* Is there a reassembled packet saved ? */
		l2p = p_get_proto_data(pinfo->fd, proto_btacl);
	}

	if (l2p) {
		next_tvb = tvb_new_real_data(l2p->data, l2p->pkt_len, l2p->pkt_len);
		//tvb_set_free_cb(next_tvb, g_free);
		tvb_set_child_real_data_tvbuff(tvb, next_tvb);
		add_new_data_source(pinfo, next_tvb, "Reassembled L2CAP");

		/* call L2CAP dissector */
		if(btl2cap_handle){
			call_dissector(btl2cap_handle, next_tvb, pinfo, tree);
		}
	}
#endif
#if 0
	/* decrypt successful, let's set up a new data tvb. */
	decr_tvb = tvb_new_real_data(tmp, len-8, len-8);
	tvb_set_free_cb(decr_tvb, g_free);
	tvb_set_child_real_data_tvbuff(tvb, decr_tvb);
#endif
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
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_btacl,
	};

	/* Register the protocol name and description */
	proto_btacl = proto_register_protocol("Bluetooth HCI ACL Packet", "HCI_ACL", "bthci_acl");
	register_dissector("bthci_acl", dissect_btacl, proto_btacl);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_btacl, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_btacl(void)
{
	dissector_handle_t bthci_acl_handle;

	bthci_acl_handle = find_dissector("bthci_acl");
	dissector_add("hci_h4.type", HCI_H4_TYPE_ACL, bthci_acl_handle);


	btl2cap_handle = find_dissector("btl2cap");
}


