/* packet-aim-chat.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC Chat
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 * Copyright 2000, Ralf Hoelzer <ralf@well.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/emem.h>

#include "packet-tcp.h"
#include "packet-aim.h"

/* SNAC families */
#define FAMILY_CHAT       0x000E

#define AIM_CHAT_TLV_BROWSABLE_TREE 		0x001
#define AIM_CHAT_TLV_CLASS_EXCLUSIVE		0x002
#define AIM_CHAT_TLV_MAX_CONCURRENT_ROOMS	0x003
#define AIM_CHAT_TLV_MAX_ROOM_NAME_LEN		0x004
#define AIM_CHAT_TLV_ROOT_ROOMS				0x005
#define AIM_CHAT_TLV_SEARCH_TAGS			0x006
#define AIM_CHAT_TLV_CHILD_ROOMS			0x065
#define AIM_CHAT_TLV_CONTAINS_USER_CLASS	0x066
#define AIM_CHAT_TLV_CONTAINS_USER_ARRAY	0x067

static const aim_tlv chat_tlvs[] = {
	{ AIM_CHAT_TLV_BROWSABLE_TREE, "Browsable tree", dissect_aim_tlv_value_bytes },
	{ AIM_CHAT_TLV_CLASS_EXCLUSIVE, "Exclusively for class", dissect_aim_tlv_value_userclass },
	{ AIM_CHAT_TLV_MAX_CONCURRENT_ROOMS, "Max. number of concurrent rooms", dissect_aim_tlv_value_uint8 },
	{ AIM_CHAT_TLV_MAX_ROOM_NAME_LEN, "Max. length of room name", dissect_aim_tlv_value_uint8 },
	{ AIM_CHAT_TLV_ROOT_ROOMS, "Root Rooms", dissect_aim_tlv_value_bytes },
	{ AIM_CHAT_TLV_SEARCH_TAGS, "Search Tags", dissect_aim_tlv_value_bytes },
	{ AIM_CHAT_TLV_CHILD_ROOMS, "Child Rooms", dissect_aim_tlv_value_bytes },
	{ AIM_CHAT_TLV_CONTAINS_USER_CLASS, "Contains User Class", dissect_aim_tlv_value_bytes },
	{ AIM_CHAT_TLV_CONTAINS_USER_ARRAY, "Contains User Array", dissect_aim_tlv_value_bytes },
	{ 0, NULL, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_aim_chat = -1;

/* Initialize the subtree pointers */
static gint ett_aim_chat          = -1;

static int dissect_aim_chat_userinfo_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *chat_tree)
{
	int offset = 0;
	while(tvb_length_remaining(tvb, offset) > 0) {
		offset = dissect_aim_userinfo(tvb, pinfo, offset, chat_tree);
	}
	return offset;
}

static int dissect_aim_chat_outgoing_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *chat_tree _U_)
{
	char *buddyname;
	guchar *msg;
	int buddyname_length;

	buddyname=ep_alloc(MAX_BUDDYNAME_LENGTH+1);
	msg=ep_alloc(1000);
	buddyname_length = aim_get_buddyname( buddyname, tvb, 30, 31 );

	/* channel message from client */
	aim_get_message( msg, tvb, 40 + buddyname_length, tvb_length(tvb) 
					 - 40 - buddyname_length );

	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
	
	return tvb_length(tvb);
}


static int dissect_aim_chat_incoming_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *chat_tree)
{
	char *buddyname;
	guchar *msg;
	/* channel message to client */
	int buddyname_length;
	
	buddyname=ep_alloc(MAX_BUDDYNAME_LENGTH+1);
	msg=ep_alloc(1000);
	buddyname_length = aim_get_buddyname( buddyname, tvb, 30, 31 );

	aim_get_message( msg, tvb, 36 + buddyname_length, tvb_length(tvb) 
					 - 36 - buddyname_length );

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, "from: %s", buddyname);
		col_append_fstr(pinfo->cinfo, COL_INFO, " -> %s", msg);
	}

	if(chat_tree) {
		proto_tree_add_text(chat_tree, tvb, 31, buddyname_length, 
							"Screen Name: %s",
							format_text(buddyname, buddyname_length));
	}
	return tvb_length(tvb);
}

static const aim_subtype aim_fnac_family_chat[] = {
  { 0x0001, "Error", dissect_aim_snac_error },
  { 0x0002, "Room Info Update", NULL },
  { 0x0003, "User Join", dissect_aim_chat_userinfo_list },
  { 0x0004, "User Leave", dissect_aim_chat_userinfo_list },
  { 0x0005, "Outgoing Message", dissect_aim_chat_outgoing_msg },
  { 0x0006, "Incoming Message", dissect_aim_chat_incoming_msg },
  { 0x0007, "Evil Request", NULL },
  { 0x0008, "Evil Reply", NULL },
  { 0, NULL, NULL }
};

/* Register the protocol with Wireshark */
void
proto_register_aim_chat(void)
{

/* Setup list of header fields */
/*FIXME
  static hf_register_info hf[] = {
  };*/

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_chat,
  };

/* Register the protocol name and description */
  proto_aim_chat = proto_register_protocol("AIM Chat Service", "AIM Chat", "aim_chat");

/* Required function calls to register the header fields and subtrees used */
/*FIXME
  proto_register_field_array(proto_aim_chat, hf, array_length(hf));*/
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_chat(void)
{
  aim_init_family(proto_aim_chat, ett_aim_chat, FAMILY_CHAT, aim_fnac_family_chat);
}
