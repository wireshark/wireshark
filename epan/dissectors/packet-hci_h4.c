/* packet-hci_h4.c
 * Routines for the HCI H4 dissection
 *
 * Copyright 2002, Christoph Scholz <scholz@cs.uni-bonn.de>
 *  From: http://affix.sourceforge.net/archive/ethereal_affix-3.patch
 *
 * Refactored for ethereal checkin
 *   Ronnie Sahlberg 2006
 *
 * $Id: packet-hci_h4.c,v 1.1 2002/11/10 20:47:21 kds Exp $
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
#include "config.h"
#endif

#include <epan/packet.h>

#include "packet-hci_h4.h"


static int proto_hci_h4 = -1;
static int hf_hci_h4_type = -1;
static int hf_hci_h4_direction = -1;

static gint ett_hci_h4 = -1;

static dissector_table_t hci_h4_table;
static dissector_handle_t data_handle;


static const value_string hci_h4_type_vals[] = {
	{HCI_H4_TYPE_CMD, "HCI Command"},
	{HCI_H4_TYPE_ACL, "ACL Data"},
	{HCI_H4_TYPE_SCO, "SCO Data"},
	{HCI_H4_TYPE_EVT, "HCI Event"},
	{0, NULL }
};
static const value_string hci_h4_direction_vals[] = {
	{0,	"Sent"},
	{1,	"Rcvd"},
	{0, NULL}
};

static void
dissect_hci_h4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 type;
	tvbuff_t *next_tvb;
	proto_item *ti=NULL;
	proto_tree *hci_h4_tree=NULL;

	if(check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI H4");
    
	if(check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	type = tvb_get_guint8(tvb, 0);
       
	if(tree){
		ti = proto_tree_add_item(tree, proto_hci_h4, tvb, 0, 1, FALSE);
		hci_h4_tree = proto_item_add_subtree(ti, ett_hci_h4);
	}

	if(check_col(pinfo->cinfo, COL_INFO)){
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",pinfo->p2p_dir==P2P_DIR_SENT?"Sent":"Rcvd",val_to_str(type, hci_h4_type_vals, "Unknown 0x%02x"));
	}
	ti=proto_tree_add_uint(hci_h4_tree, hf_hci_h4_direction, tvb, 0, 0, pinfo->p2p_dir);
	PROTO_ITEM_SET_GENERATED(ti);
	proto_item_append_text(hci_h4_tree, " %s %s", val_to_str(pinfo->p2p_dir, hci_h4_direction_vals, "0x%02x"), val_to_str(type, hci_h4_type_vals, "Unknown 0x%02x"));

	proto_tree_add_item(hci_h4_tree, hf_hci_h4_type,
		tvb, 0, 1, TRUE);

	next_tvb = tvb_new_subset(tvb, 1, -1, -1);
	if(!dissector_try_port(hci_h4_table, type, next_tvb, pinfo, tree)) {
/*
		if(check_col(pinfo->cinfo, COL_INFO)){
			col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown HCI H4 payload type 0x%02x", type);
		}
*/
		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
}


void
proto_register_hci_h4(void)
{                 
	static hf_register_info hf[] = {
	{ &hf_hci_h4_type,
		{ "HCI Packet Type",           "hci_h4.type",
		FT_UINT8, BASE_HEX, VALS(hci_h4_type_vals), 0x0,          
		"HCI Packet Type", HFILL }},

	{ &hf_hci_h4_direction,
		{ "Direction",           "hci_h4.direction",
		FT_UINT8, BASE_HEX, VALS(hci_h4_direction_vals), 0x0,          
		"HCI Packet Direction Sent/Rcvd", HFILL }},

	};

	static gint *ett[] = {
		&ett_hci_h4,
	};

	proto_hci_h4 = proto_register_protocol("HCI H4",
	    "HCI_H4", "hci_h4");

	register_dissector("hci_h4", dissect_hci_h4, proto_hci_h4);

	proto_register_field_array(proto_hci_h4, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	hci_h4_table = register_dissector_table("hci_h4.type",
		"HCI H4 pdu type", FT_UINT8, BASE_HEX);
}

void
proto_reg_handoff_hci_h4(void)
{
	dissector_handle_t hci_h4_handle;

	data_handle = find_dissector("data");
	hci_h4_handle = find_dissector("hci_h4");
	dissector_add("wtap_encap", WTAP_ENCAP_BLUETOOTH_H4, hci_h4_handle);
}


