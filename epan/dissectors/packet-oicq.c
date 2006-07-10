/* packet-oicq.c
 * Routines for OICQ - IM software,popular in China - packet dissection
 * (c) Copyright DuBingyao <dubingyao@gmail.com>
 *
 * $Id$
 *
 * OICQ is an IM software,which is popular in China. And,
 * OICQ has more than 10 millions users at present.
 * The Protocol showed in this file, is found by investigating OICQ's 
 * Packets  as a black box.
 *
 * The OICQ client software is always changing,and the protocol of 
 * communication is also.
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

/*
        Protocol Flag:     8bit unsigned
        Sender Flag:       16bit unsigned
        Command Number:    16bit unsigned
        Sequence Number:   16bit unsigned
        OICQ  Number:      32bit unsigned
        Data:              Variable Length data
        
 *
 */

/* By default, but can be completely different */
#define UDP_PORT_OICQ	8000

static int proto_oicq = -1;

static int hf_oicq_flag = -1;
static int hf_oicq_version = -1;
static int hf_oicq_command = -1;
static int hf_oicq_seq = -1;
static int hf_oicq_qqid = -1;
static int hf_oicq_data = -1;


static gint ett_oicq = -1;

static const value_string oicq_flag_vals[] = {
	{ 0x02,	"Oicq packet" },
	{ 0,			NULL }
};

static const value_string oicq_command_vals[] = {
	{ 0x0001,	"Log out" },
	{ 0x0002,	"Heart Message" },
	{ 0x0004,	"Update User information" },
	{ 0x0005,	"Search user" },
	{ 0x0006,	"Get User informationBroadcast" },
	{ 0x0009,	"Add friend no auth" },
	{ 0x000a,	"Delete user" },
	{ 0x000b,	"Add friend by auth" },
	{ 0x000d,	"Set status" },
	{ 0x0012,	"Confirmation of receiving message from server" },
	{ 0x0016,	"Send message" },
	{ 0x0017,	"Receive message" },
	{ 0x0018,	"Retrieve information" },
	{ 0x001a,	"Reserved " },
	{ 0x001c,	"Delete Me" },
	{ 0x001d,	"Request KEY" },
	{ 0x0021,	"Cell Phone" },
	{ 0x0022,	"Log in" },
	{ 0x0026,	"Get friend list" },
	{ 0x0027,	"Get friend online" },
	{ 0x0029,	"Cell PHONE" },
	{ 0x0030,	"Operation on group" },
	{ 0x0031,	"Log in test" },
	{ 0x003c,	"Group name operation" },
	{ 0x003d,	"Upload group friend" },
	{ 0x003e,	"MEMO Operation" },
	{ 0x0058,	"Download group friend" },
	{ 0x005c,	"Get level" },
	{ 0x0062,	"Request login" },
	{ 0x0065,	"Request extra information" },
	{ 0x0067,	"Signature operation" },
	{ 0x0080,	"Receive system message" },
	{ 0x0081,	"Get statur of friend" },
	{ 0x00b5,	"Get friend's statur of group" },
	{ 0,			NULL }
};

/* dissect_oicq - dissects oicq packet data
 * tvb - tvbuff for packet data (IN)
 * pinfo - packet info
 * proto_tree - resolved protocol tree
 */
static void
dissect_oicq(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *oicq_tree;
	proto_item	*ti;
	int offset = 0;
	
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "OICQ");

	if (check_col(pinfo->cinfo, COL_INFO))
	{
		col_clear(pinfo->cinfo, COL_INFO);
		col_set_str(pinfo->cinfo, COL_INFO, "OICQ Protocol ");
		
	}


	if (tree) {
		ti = proto_tree_add_item(tree, proto_oicq, tvb, 0, -1, FALSE);
		oicq_tree = proto_item_add_subtree(ti, ett_oicq);

		proto_tree_add_item(oicq_tree, hf_oicq_flag, tvb, offset, 1, FALSE);
		offset += 1;
		
		proto_tree_add_item(oicq_tree, hf_oicq_version, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(oicq_tree, hf_oicq_command, tvb, offset, 2, FALSE);
		offset += 2;


		proto_tree_add_item(oicq_tree, hf_oicq_seq, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(oicq_tree, hf_oicq_qqid, tvb, offset, 4, FALSE);
		offset += 4;
		
		proto_tree_add_item(oicq_tree, hf_oicq_data, tvb, offset, -1, FALSE);
		
		
	}
}

void
proto_register_oicq(void)
{
	static hf_register_info hf[] = {
		{ &hf_oicq_flag, {
			"Flag", "oicq.flag", FT_UINT8, BASE_HEX,
			VALS(oicq_flag_vals), 0, "Protocol Flag", HFILL }},
		{ &hf_oicq_version, {
			"Version", "oicq.version", FT_UINT16, BASE_HEX,
			NULL, 0, "Version-zz", HFILL }},
		{ &hf_oicq_command, {
			"Command", "oicq.command", FT_UINT16, BASE_DEC,
			VALS(oicq_command_vals), 0, "Command", HFILL }},
		{ &hf_oicq_seq, {
			"Sequence", "oicq.seq", FT_UINT16, BASE_DEC,
			NULL, 0, "Sequence", HFILL }},
		{ &hf_oicq_qqid, {
			"Data(OICQ Number,if sender is client)", "oicq.qqid", FT_UINT32, BASE_DEC,
			NULL, 0, "", HFILL }},
		{ &hf_oicq_data, {
			"Data", "oicq.data", FT_STRING, 0,
			NULL, 0, "Data", HFILL }},
        };
	static gint *ett[] = {
		&ett_oicq,
	};

	proto_oicq = proto_register_protocol("OICQ - IM software, popular in China", "OICQ",
	    "oicq");
	proto_register_field_array(proto_oicq, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_oicq(void)
{
	dissector_handle_t oicq_handle;

	oicq_handle = create_dissector_handle(dissect_oicq, proto_oicq);
	dissector_add("udp.port", UDP_PORT_OICQ, oicq_handle);
}

