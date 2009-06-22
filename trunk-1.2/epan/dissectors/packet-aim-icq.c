/* packet-aim-icq.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC ICQ
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
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

#include "packet-aim.h"

#define FAMILY_ICQ        0x0015


#define ICQ_CLI_OFFLINE_MESSAGE_REQ 	0x003c
#define ICQ_CLI_DELETE_OFFLINE_MSGS		0x003e
#define ICQ_SRV_OFFLINE_MSGS			0x0041
#define ICQ_SRV_END_OF_OFFLINE_MSGS		0x0042
#define ICQ_CLI_META_INFO_REQ			0x07d0
#define ICQ_SRV_META_INFO_REPL			0x07da

static const value_string aim_icq_data_types[] = {
  { ICQ_CLI_OFFLINE_MESSAGE_REQ, "Offline Message Request" },
  { ICQ_SRV_OFFLINE_MSGS, "Offline Messages Reply" },
  { ICQ_SRV_END_OF_OFFLINE_MSGS, "End Of Offline Messages Reply" },
  { ICQ_CLI_DELETE_OFFLINE_MSGS, "Delete Offline Messages Request" },
  { ICQ_CLI_META_INFO_REQ, "Metainfo Request" },
  { ICQ_SRV_META_INFO_REPL, "Metainfo Reply" },
  { 0, NULL }
};


static int dissect_aim_tlv_value_icq(proto_item *ti, guint16 subtype, tvbuff_t *tvb, packet_info *pinfo _U_);

#define TLV_ICQ_META_DATA 			  0x0001

static const aim_tlv icq_tlv[] = {
   { TLV_ICQ_META_DATA, "Encapsulated ICQ Meta Data", dissect_aim_tlv_value_icq },
   { 0, NULL, NULL },
};

/* Initialize the protocol and registered fields */
static int proto_aim_icq = -1;

/* Initialize the subtree pointers */
static gint ett_aim_icq      = -1;
static gint ett_aim_icq_tlv  = -1;

static gint hf_icq_tlv_data_chunk_size = -1;
static gint hf_icq_tlv_request_owner_uid = -1;
static gint hf_icq_tlv_request_type = -1;
static gint hf_icq_meta_subtype = -1;
static gint hf_icq_tlv_request_seq_num = -1;
static gint hf_icq_dropped_msg_flag = -1;


static struct
{
	guint16 subtype;
	const char *name;
	int (*dissector) (tvbuff_t *, packet_info *, proto_tree *);
} icq_calls [] = {
	{ 0x0001, "Server Error Reply", NULL },
	{ 0x0064, "Set User Home Info Reply", NULL },
	{ 0x006e, "Set User Work Info Reply", NULL },
	{ 0x0078, "Set User More Info Reply", NULL },
	{ 0x0082, "Set User Notes Info Reply", NULL },
	{ 0x0087, "Set User Email Info Reply", NULL },
	{ 0x008c, "Set User Interests Info Reply", NULL },
	{ 0x0096, "Set User Affiliations Info Reply", NULL },
	{ 0x00a0, "Set User Permissions Reply", NULL },
	{ 0x00aa, "Set User Password Reply", NULL },
	{ 0x00b4, "Unregister Account Reply", NULL },
	{ 0x00be, "Set User Homepage Category Reply", NULL },
	{ 0x00c8, "User Basic Info Reply", NULL },
	{ 0x00d2, "User Work Info Reply", NULL },
	{ 0x00dc, "User More Info Reply", NULL },
	{ 0x00e6, "User Notes Info Reply", NULL },
	{ 0x00eb, "User Extended Email Reply", NULL },
	{ 0x00f0, "User Interests Info Reply", NULL },
	{ 0x00fa, "User Affiliations Info Reply", NULL },
	{ 0x0104, "Short User Info Reply", NULL },
	{ 0x010e, "User Homepage Category Reply", NULL },
	{ 0x01a4, "Search: User found", NULL },
	{ 0x0302, "Registration Stats Reply", NULL },
	{ 0x0366, "Random Search Server Reply", NULL },
	{ 0x03ea, "Set User Home Info Request", NULL },
	{ 0x03f3, "Set User Work Info Request", NULL },
	{ 0x03fd, "Set User More Info Request", NULL },
	{ 0x0406, "Set User Notes Request", NULL },
	{ 0x040b, "Set User Extended Email Info Request", NULL },
	{ 0x0410, "Set User Interests Info Request", NULL },
	{ 0x041a, "Set User Affiliations Info Request", NULL },
	{ 0x0424, "Set User Permissions Info Request", NULL },
	{ 0x042e, "Change User Password Request", NULL },
	{ 0x0442, "Set User Homepage Category Request", NULL },
	{ 0x04b2, "Fullinfo Request", NULL },
	{ 0x04ba, "Short User Info Request", NULL },
	{ 0x04c4, "Unregister User Request", NULL },
	{ 0x0515, "Search By Details Request", NULL },
	{ 0x0569, "Search By UIN Request", NULL },
	{ 0x055f, "Whitepages Search Request", NULL },
	{ 0x0573, "Search By Email Request", NULL },
	{ 0x074e, "Random Chat User Search Request", NULL },
	{ 0x0898, "Server Variable Request (XML)", NULL },
	{ 0x0aa5, "Registration Report Request", NULL },
	{ 0x0aaf, "Shortcut Bar Stats Report Request", NULL },
	{ 0x0c3a, "Save Info Request", NULL },
	{ 0x1482, "Send SMS Request", NULL },
	{ 0x2008, "Spam Report Request", NULL },
	{ 0x08a2, "Server Variable Reply (XML)", NULL },
	{ 0x0c3f, "Set Fullinfo Reply", NULL },
	{ 0x2012, "User Spam Report Reply", NULL },
	{ 0, NULL, NULL },
};


static int dissect_aim_tlv_value_icq(proto_item *ti _U_, guint16 subtype _U_, tvbuff_t *tvb _U_, packet_info *pinfo)
{
	int offset = 0;
	int i;
	proto_item *subtype_item;
	guint16 req_type, req_subtype;
	proto_tree *t = proto_item_add_subtree(ti, ett_aim_icq_tlv);

	proto_tree_add_item(t, hf_icq_tlv_data_chunk_size, tvb, offset, 2, TRUE);
	offset += 2;
	
	proto_tree_add_item(t, hf_icq_tlv_request_owner_uid, tvb, offset, 4, TRUE);
	offset += 4;

	proto_tree_add_item(t, hf_icq_tlv_request_type, tvb, offset, 2, TRUE);
	req_type = tvb_get_letohs(tvb, offset);
	offset += 2;

	proto_tree_add_item(t, hf_icq_tlv_request_seq_num, tvb, offset, 2, TRUE);
	offset += 2;

	switch(req_type) {
	case ICQ_CLI_OFFLINE_MESSAGE_REQ: return offset;
	case ICQ_CLI_DELETE_OFFLINE_MSGS: return offset;
	case ICQ_SRV_OFFLINE_MSGS:
		/* FIXME */
		break;
	case ICQ_SRV_END_OF_OFFLINE_MSGS: 
		proto_tree_add_item(t, hf_icq_dropped_msg_flag, tvb, offset, 1, TRUE);
		return offset+1;
	case ICQ_CLI_META_INFO_REQ:
	case ICQ_SRV_META_INFO_REPL:
		req_subtype = tvb_get_letohs(tvb, offset);
		subtype_item = proto_tree_add_item(t, hf_icq_meta_subtype, tvb, offset, 2, TRUE); offset+=2;
		
		for(i = 0; icq_calls[i].name; i++) {
			if(icq_calls[i].subtype == req_subtype) break;
		}

		if(check_col(pinfo->cinfo, COL_INFO)) 
			col_set_str(pinfo->cinfo, COL_INFO, icq_calls[i].name?icq_calls[i].name:"Unknown ICQ Meta Call");

		proto_item_append_text(subtype_item, " (%s)", icq_calls[i].name?icq_calls[i].name:"Unknown");

		if(icq_calls[i].dissector) 
			return icq_calls[i].dissector(tvb_new_subset(tvb, offset, -1, -1), pinfo, t);

	default:
		break;
	}

	return offset;
}

static int dissect_aim_icq_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	return dissect_aim_tlv(tvb, pinfo, 0, tree, icq_tlv);
}

static const aim_subtype aim_fnac_family_icq[] = {
  { 0x0001, "Error", dissect_aim_snac_error },
  { 0x0002, "ICQ Request", dissect_aim_icq_tlv },
  { 0x0003, "ICQ Response", dissect_aim_icq_tlv },
  { 0x0006, "Auth Request", NULL },
  { 0x0007, "Auth Response", NULL },
  { 0, NULL, NULL }
};


/* Register the protocol with Wireshark */
void
proto_register_aim_icq(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
	  { &hf_icq_tlv_data_chunk_size,
	    { "Data chunk size", "aim_icq.chunk_size", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL },
	  },
	  { &hf_icq_tlv_request_owner_uid,
	    { "Owner UID", "aim_icq.owner_uid", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL},
	  },
	  { &hf_icq_tlv_request_type,
	    {"Request Type", "aim_icq.request_type", FT_UINT16, BASE_DEC, VALS(aim_icq_data_types), 0x0, "", HFILL},
	  },
	  { &hf_icq_tlv_request_seq_num,
	    {"Request Sequence Number", "aim_icq.request_seq_number", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL},
	  },
	  { &hf_icq_dropped_msg_flag,
		{"Dropped messages flag", "aim_icq.offline_msgs.dropped_flag", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL },
	  },
	  { &hf_icq_meta_subtype,
		{"Meta Request Subtype", "aim_icq.subtype", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL },
	  },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_aim_icq,
	&ett_aim_icq_tlv
  };

/* Register the protocol name and description */
  proto_aim_icq = proto_register_protocol("AIM ICQ", "AIM ICQ", "aim_icq");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_aim_icq, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_aim_icq(void)
{
  aim_init_family(proto_aim_icq, ett_aim_icq, FAMILY_ICQ, aim_fnac_family_icq);
}
