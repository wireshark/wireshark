/* packet-dcerpc-frsrpc.c
 * Routines for the frs (File Replication Service) MSRPC interface 
 * Copyright 2004 Jean-Baptiste Marchand <jbm@hsc.fr>
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
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-frsrpc.h"
#include "packet-smb-common.h"
#include "packet-windows-common.h"

static int proto_dcerpc_frsrpc		= -1;

static int hf_frsrpc_opnum 		= -1;
static int hf_frsrpc_tlvsize		= -1;
static int hf_frsrpc_tlv		= -1;
static int hf_frsrpc_tlv_item		= -1;
static int hf_frsrpc_tlv_tag		= -1;
static int hf_frsrpc_tlv_size		= -1;
static int hf_frsrpc_tlv_data		= -1;
static int hf_frsrpc_unknown32		= -1;
static int hf_frsrpc_unknownbytes	= -1;
static int hf_frsrpc_guid_size		= -1;
static int hf_frsrpc_ssrv_guid		= -1;
static int hf_frsrpc_dsrv_guid		= -1;
static int hf_frsrpc_str_size		= -1;
static int hf_frsrpc_ssrv		= -1;
static int hf_frsrpc_dsrv		= -1;
static int hf_frsrpc_timestamp		= -1;


static gint ett_dcerpc_frsrpc		= -1;
static gint ett_frsrpc_tlv		= -1;
static gint ett_frsrpc_tlv_item		= -1;

/*
IDL [ uuid(f5cc59b4-4264-101a-8c59-08002b2f8426),
IDL  version(1.1),
IDL  implicit_handle(handle_t rpc_binding)
IDL ] interface frsrpc
*/


static e_uuid_t uuid_dcerpc_frsrpc = {
	0xf5cc59b4, 0x4264, 0x101a,
	{ 0x8c, 0x59, 0x08, 0x00, 0x2b, 0x2f, 0x84, 0x26 }
};

static guint16 ver_dcerpc_frsrpc = 1; 

#define TLV_SSRV	3
#define TLV_DSRV	4
#define TLV_TS		18
static const value_string tag_vals[] = {
	{TLV_SSRV,	"SOURCE SERVER"},
	{TLV_DSRV,	"DESTINATION SERVER"},
	{TLV_TS,	"TIMESTAMP"},
	{0,NULL}
};



static void
dissect_tlv_ssrv(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, guint8 *drep)
{
	int offset = 0;
	const char *dn;
	int dn_len;
	guint16 bc;

	/* a GUID */
	proto_tree_add_item(tree, hf_frsrpc_guid_size, tvb, offset, 4, TRUE);
	offset+=4;

	offset=dissect_ndr_uuid_t(tvb, offset, pinfo, tree, drep, hf_frsrpc_ssrv_guid, NULL);


	/* the name of the source server sending this */
	proto_tree_add_item(tree, hf_frsrpc_str_size, tvb, offset, 4, TRUE);
	dn_len = tvb_get_ntohl(tvb, offset);
	offset+=4;

	bc = tvb_length_remaining(tvb, offset);
	dn = get_unicode_or_ascii_string(tvb, &offset, TRUE, &dn_len, TRUE, TRUE, &bc);
	proto_tree_add_string(tree, hf_frsrpc_ssrv, tvb, offset, dn_len, dn);
}

static void
dissect_tlv_dsrv(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, guint8 *drep)
{
	int offset = 0;
	const char *dn;
	int dn_len;
	guint16 bc;

	/* a GUID */
	proto_tree_add_item(tree, hf_frsrpc_guid_size, tvb, offset, 4, TRUE);
	offset+=4;

	offset=dissect_ndr_uuid_t(tvb, offset, pinfo, tree, drep, hf_frsrpc_dsrv_guid, NULL);


	/* the name of the source server sending this */
	proto_tree_add_item(tree, hf_frsrpc_str_size, tvb, offset, 4, TRUE);
	dn_len = tvb_get_ntohl(tvb, offset);
	offset+=4;

	bc = tvb_length_remaining(tvb, offset);
	dn = get_unicode_or_ascii_string(tvb, &offset, TRUE, &dn_len, TRUE, TRUE, &bc);
	proto_tree_add_string(tree, hf_frsrpc_dsrv, tvb, offset, dn_len, dn);
}


static void
dissect_tlv_ts(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, guint8 *drep _U_)
{
	dissect_nt_64bit_time(tvb, tree, 0, hf_frsrpc_timestamp);
}


static void
dissect_TLV_blob(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, guint8 *drep)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	proto_item *tlv_item = NULL;
	proto_tree *tlv_tree = NULL;
	unsigned int offset = 0;
	guint16 tag;
	guint32 size;

	item = proto_tree_add_item(parent_tree, hf_frsrpc_tlv, tvb, offset, -1, TRUE);
	tree = proto_item_add_subtree(item, ett_frsrpc_tlv);

	while (offset < tvb_length(tvb)) {
		unsigned int old_offset = offset;
		tvbuff_t *next_tvb;

		tlv_item = proto_tree_add_item(tree, hf_frsrpc_tlv_item, tvb, offset, -1, TRUE);
		tlv_tree = proto_item_add_subtree(tlv_item, ett_frsrpc_tlv_item);

		tag = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(tlv_tree, hf_frsrpc_tlv_tag, tvb, offset, 2, TRUE);
		offset+=2;
		proto_item_append_text(tlv_item, " %s", val_to_str(tag, tag_vals, "UNKNOWN TAG:0x%x"));


		size = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(tlv_tree, hf_frsrpc_tlv_size, tvb, offset, 2, TRUE);
		offset+=4;

		next_tvb = tvb_new_subset(tvb, offset, size, size);
		switch (tag) {
		case TLV_SSRV:
			dissect_tlv_ssrv(pinfo, tlv_tree, next_tvb, drep);
			break;
		case TLV_DSRV:
			dissect_tlv_dsrv(pinfo, tlv_tree, next_tvb, drep);
			break;
		case TLV_TS:
			dissect_tlv_ts(pinfo, tlv_tree, next_tvb, drep);
			break;
		default:
			proto_tree_add_item(tlv_tree, hf_frsrpc_tlv_data, next_tvb, 0, size, TRUE);
		}
		offset+=size;

		proto_item_set_len(tlv_item, offset-old_offset);
	}
}

static int
frsrpc_dissect_SendCommPkt_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	tvbuff_t *next_tvb;
	guint32 tlvsize;
	dcerpc_info *di;

	di=pinfo->private_data;
	pinfo->dcerpc_procedure_name="SendCommPkt";

	if(di->conformant_run){
		/* just a run to handle conformant arrays, no scalars to dissect */
		return offset;
	}

	/* 16 unknown bytes */
	proto_tree_add_item(tree, hf_frsrpc_unknownbytes, tvb, offset, 16, TRUE);
	offset+=16;

	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_frsrpc_tlvsize, 0);

	/* 16 unknown bytes */
	proto_tree_add_item(tree, hf_frsrpc_unknownbytes, tvb, offset, 16, TRUE);
	offset+=16;

	/* this is a subcontext that starts with the length of the data in bytes
	   followed by concatenated TLV values.
	   this is NOT ndr encoded
	*/
	offset = dissect_dcerpc_uint32 (tvb, offset, pinfo, tree, drep, hf_frsrpc_tlvsize, &tlvsize);
	next_tvb = tvb_new_subset(tvb, offset, tlvsize, tlvsize);
	dissect_TLV_blob(pinfo, tree, next_tvb, drep);
	offset+=tlvsize;



	proto_tree_add_item(tree, hf_frsrpc_unknownbytes, tvb, offset, -1, TRUE);
	offset += tvb_length_remaining(tvb, offset);

	return offset;
}

static dcerpc_sub_dissector dcerpc_frsrpc_dissectors[] = {
	{ FRSRPC_SEND_COMM_PKT, "FrsRpcSendCommPkt", 
		frsrpc_dissect_SendCommPkt_request, NULL },
	{ FRSRPC_VERIFY_PROMOTION_PARENT, "FrsRpcVerifyPromotionParent", 
		NULL, NULL },
	{ FRSRPC_START_PROMOTION_PARENT, "FrsRpcStartPromotionParent", 
		NULL, NULL },
	{ FRSRPC_NOP, "FrsRpcNop", NULL, NULL },
/* operations 4 to 9 are apparently identical */
	{ FRSRPC_BACKUP_COMPLETE, "FrsRpcBackupComplete", NULL, NULL },
	{ FRSRPC_BACKUP_COMPLETE_5, "FrsRpcBackupComplete", NULL, NULL },
	{ FRSRPC_BACKUP_COMPLETE_6, "FrsRpcBackupComplete", NULL, NULL },
	{ FRSRPC_BACKUP_COMPLETE_7, "FrsRpcBackupComplete", NULL, NULL },
	{ FRSRPC_BACKUP_COMPLETE_8, "FrsRpcBackupComplete", NULL, NULL },
	{ FRSRPC_BACKUP_COMPLETE_9, "FrsRpcBackupComplete", NULL, NULL },
	{ FRSRPC_VERIFY_PROMOTION_PARENT_EX, "FrsRpcVerifyPromotionParentEx",
		NULL, NULL },
        { 0, NULL, NULL,  NULL }
};


void
proto_register_dcerpc_frsrpc(void)
{

        static hf_register_info hf[] = {

		{ &hf_frsrpc_opnum, 
		  { "Operation", "frsrpc.opnum", FT_UINT16, BASE_DEC,
		   NULL, 0x0, NULL, HFILL }},	

		{ &hf_frsrpc_unknown32, 
		  { "unknown32", "frsrpc.unknown32", FT_UINT32, BASE_HEX,
		   NULL, 0x0, "unknown int32", HFILL }},	

		{ &hf_frsrpc_tlvsize, 
		  { "TLV Size", "frsrpc.tlv_size", FT_UINT32, BASE_DEC,
		   NULL, 0x0, "Size of tlv blob in bytes", HFILL }},	

		{ &hf_frsrpc_tlv, 
		  { "TLV", "frsrpc.tlv", FT_NONE, BASE_NONE,
		   NULL, 0x0, "A tlv blob", HFILL }},	

		{ &hf_frsrpc_tlv_item, 
		  { "TLV", "frsrpc.tlv_item", FT_NONE, BASE_NONE,
		   NULL, 0x0, "A tlv item", HFILL }},	

		{ &hf_frsrpc_tlv_tag, 
		  { "TLV Tag", "frsrpc.tlv.tag", FT_UINT16, BASE_DEC,
		   NULL, 0x0, NULL, HFILL }},	

		{ &hf_frsrpc_tlv_size, 
		  { "TLV Size", "frsrpc.tlv.size", FT_UINT32, BASE_DEC,
		   NULL, 0x0, NULL, HFILL }},	

		{ &hf_frsrpc_tlv_data, 
		  { "TLV Data", "frsrpc.tlv.data", FT_BYTES, BASE_NONE,
		   NULL, 0x0, NULL, HFILL }},	

		{ &hf_frsrpc_unknownbytes, 
		  { "unknown", "frsrpc.unknownbytes", FT_BYTES, BASE_NONE,
		   NULL, 0x0, "unknown bytes", HFILL }},	

		{ &hf_frsrpc_guid_size, 
		  { "Guid Size", "frsrpc.guid.size", FT_UINT32, BASE_DEC,
		   NULL, 0x0, NULL, HFILL }},	

		{ &hf_frsrpc_ssrv_guid,
		  { "SSRV GUID", "frsrpc.ssrv.guid", FT_GUID, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_frsrpc_dsrv_guid,
		  { "DSRV GUID", "frsrpc.dsrv.guid", FT_GUID, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_frsrpc_str_size, 
		  { "String Size", "frsrpc.str.size", FT_UINT32, BASE_DEC,
		   NULL, 0x0, NULL, HFILL }},	

		{ &hf_frsrpc_ssrv,
		  { "SSRV", "frsrpc.ssrv", FT_STRING, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_frsrpc_dsrv,
		  { "DSRV", "frsrpc.dsrv", FT_STRING, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_frsrpc_timestamp,
		  { "Timestamp", "frsrpc.timestamp", FT_ABSOLUTE_TIME, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
	};


        static gint *ett[] = {
                &ett_dcerpc_frsrpc,
		&ett_frsrpc_tlv,
		&ett_frsrpc_tlv_item,
        };


	proto_dcerpc_frsrpc = proto_register_protocol(
		"Microsoft File Replication Service", "FRSRPC", "frsrpc");

	proto_register_field_array(proto_dcerpc_frsrpc, hf, array_length(hf));

        proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_dcerpc_frsrpc(void)
{
	/* register protocol as dcerpc */

	dcerpc_init_uuid(
		proto_dcerpc_frsrpc, ett_dcerpc_frsrpc, &uuid_dcerpc_frsrpc,
		ver_dcerpc_frsrpc, dcerpc_frsrpc_dissectors, hf_frsrpc_opnum);
}
