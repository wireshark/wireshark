/* packet-aim-icq.c
 * Routines for AIM Instant Messenger (OSCAR) dissection, SNAC ICQ
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-aim.h"

#define FAMILY_ICQ        0x0015

/* Family ICQ */
#define FAMILY_ICQ_ERROR              0x0001
#define FAMILY_ICQ_LOGINREQUEST       0x0002
#define FAMILY_ICQ_LOGINRESPONSE      0x0003
#define FAMILY_ICQ_AUTHREQUEST        0x0006
#define FAMILY_ICQ_AUTHRESPONSE       0x0007

static const value_string aim_fnac_family_icq[] = {
  { FAMILY_ICQ_ERROR, "Error" },
  { FAMILY_ICQ_LOGINREQUEST, "Login Request" },
  { FAMILY_ICQ_LOGINRESPONSE, "Login Response" },
  { FAMILY_ICQ_AUTHREQUEST, "Auth Request" },
  { FAMILY_ICQ_AUTHRESPONSE, "Auth Response" },
  { 0, NULL }
};

#define ICQ_CLI_OFFLINE_MESSAGE_REQ 	0x003c
#define ICQ_CLI_DELETE_OFFLINE_MSGS		0x003e
#define ICQ_SRV_END_OF_OFFLINE_MSGS		0x0042
#define ICQ_CLI_META_INFO_REQ			0x07d0
#define ICQ_SRV_META_INFO_REPL			0x07da

static const value_string aim_icq_data_types[] = {
  { ICQ_CLI_OFFLINE_MESSAGE_REQ, "Offline Message Request" },
  { ICQ_SRV_END_OF_OFFLINE_MSGS, "End Of Offline Messages Reply" },
  { ICQ_CLI_DELETE_OFFLINE_MSGS, "Delete Offline Messages Request" },
  { ICQ_CLI_META_INFO_REQ, "Metainfo Request" },
  { ICQ_SRV_META_INFO_REPL, "Metainfo Reply" },
  { 0, NULL }
};

int dissect_aim_tlv_value_icq(proto_item *ti, guint16, tvbuff_t *);

#define TLV_ICQ_META_DATA 			  0x0001

static const aim_tlv icq_tlv[] = {
   { TLV_ICQ_META_DATA, "Encapsulated ICQ Meta Data", dissect_aim_tlv_value_icq },
   { 0, "Unknown", NULL },
};

/* Initialize the protocol and registered fields */
static int proto_aim_icq = -1;

/* Initialize the subtree pointers */
static gint ett_aim_icq      = -1;
static gint ett_aim_icq_tlv  = -1;


static gint hf_icq_tlv_data_chunk_size = -1;
static gint hf_icq_tlv_request_owner_uid = -1;
static gint hf_icq_tlv_request_type = -1;
static gint hf_icq_tlv_request_seq_num = -1;

int dissect_aim_tlv_value_icq(proto_item *ti _U_, guint16 subtype _U_, tvbuff_t *tvb _U_)
{
	int offset = 0;
	proto_tree *t = proto_item_add_subtree(ti, ett_aim_icq_tlv);

	proto_tree_add_item(t, hf_icq_tlv_data_chunk_size, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
	offset += 2;
	
	proto_tree_add_item(t, hf_icq_tlv_request_owner_uid, tvb, offset, 4, tvb_get_ntoh24(tvb, offset));
	offset += 4;

	proto_tree_add_item(t, hf_icq_tlv_request_type, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
	offset += 2;


	proto_tree_add_item(t, hf_icq_tlv_request_seq_num, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
	offset += 2;

	return 0;
}

static int dissect_aim_icq(tvbuff_t *tvb, packet_info *pinfo, 
				    proto_tree *tree)
{
   struct aiminfo *aiminfo = pinfo->private_data;
   int offset = 0;
   switch(aiminfo->subtype) {
   case FAMILY_ICQ_ERROR:
	   return dissect_aim_snac_error(tvb, pinfo, offset, tree);
   case FAMILY_ICQ_LOGINREQUEST:
   case FAMILY_ICQ_LOGINRESPONSE:
	   return dissect_aim_tlv(tvb, pinfo, offset, tree, icq_tlv);
   case FAMILY_ICQ_AUTHREQUEST:
   case FAMILY_ICQ_AUTHRESPONSE:
	   /* FIXME */
	default:
	   return 0;
   }
}

/* Register the protocol with Ethereal */
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
  dissector_handle_t aim_handle;

  aim_handle = new_create_dissector_handle(dissect_aim_icq, proto_aim_icq);
  dissector_add("aim.family", FAMILY_ICQ, aim_handle);
  aim_init_family(FAMILY_ICQ, "ICQ", aim_fnac_family_icq);
}
