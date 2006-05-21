/* packet-dcerpc-mapi.c
 * Routines for MS Exchange MAPI
 * Copyright 2002, Ronnie Sahlberg
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
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-mapi.h"
#include "packet-windows-common.h"	/* for "NT_errors[]" */
#include <epan/prefs.h>

static int proto_dcerpc_mapi = -1;
static int hf_mapi_opnum = -1;
static int hf_mapi_unknown_string = -1;
static int hf_mapi_unknown_short = -1;
static int hf_mapi_unknown_long = -1;
static int hf_mapi_hnd = -1;
static int hf_mapi_rc = -1;
static int hf_mapi_encap_datalen = -1;
static int hf_mapi_encrypted_data = -1;
static int hf_mapi_decrypted_data_maxlen = -1;
static int hf_mapi_decrypted_data_offset = -1;
static int hf_mapi_decrypted_data_len = -1;
static int hf_mapi_decrypted_data = -1;
static int hf_mapi_pdu_len = -1;

static gint ett_dcerpc_mapi = -1;
static gint ett_mapi_decrypted_pdu = -1;

static e_uuid_t uuid_dcerpc_mapi = {
        0xa4f1db00, 0xca47, 0x1067,
        { 0xb3, 0x1f, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda }
};

static guint16 ver_dcerpc_mapi = 0;

#define DISSECT_UNKNOWN(len) \
	{\
	proto_tree_add_text(tree, tvb, offset, len,\
		"unknown data (%d byte%s)", len,\
		plurality(len, "", "s"));\
	offset += len;\
	}

/* decryption */
static gboolean mapi_decrypt = FALSE;

static int
mapi_decrypt_pdu(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	dcerpc_info *di;
	guint8 *decrypted_data;
	tvbuff_t *decrypted_tvb;
	guint32 length;
	gint len, reported_len;
	const guint8 *ptr;
	gint i;
	guint16 pdu_len;
	proto_item *it = NULL;
	proto_tree *tr = NULL;

	di=pinfo->private_data;
	if(di->conformant_run){
		return offset;
	}

	offset=dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_mapi_decrypted_data_maxlen, NULL);
	offset=dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_mapi_decrypted_data_offset, NULL);
	offset=dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_mapi_decrypted_data_len, &length);

	len = tvb_length_remaining(tvb, offset);
	reported_len = tvb_reported_length_remaining(tvb, offset);
	if((guint32)reported_len > length)
		reported_len = length;
	if(len > reported_len)
		len = reported_len;

	ptr=tvb_get_ptr(tvb, offset, len);
	decrypted_data=g_malloc(len);
	for(i=0;i<len;i++){
		/*
		 * Now *that's* secure encryption!
		 */
		decrypted_data[i]=ptr[i]^0xa5;
	}

	/* Allocate a new tvbuff, referring to the decrypted data. */
	decrypted_tvb=tvb_new_real_data(decrypted_data, len, reported_len);

	/* Arrange that the allocated packet data copy be freed when the
	   tvbuff is freed. */
	tvb_set_free_cb(decrypted_tvb, g_free);

	/* Add the tvbuff to the list of tvbuffs to which the tvbuff we
	   were handed refers, so it'll get cleaned up when that tvbuff
	   is cleaned up. */
	tvb_set_child_real_data_tvbuff(tvb, decrypted_tvb);

	/* Add the decrypted data to the data source list. */
	add_new_data_source(pinfo, decrypted_tvb, "Decrypted MAPI");

	/* decrypted PDU */
	/* All from 10 minutes eyeballing. This may be wrong.
	   The PDU is NOT NDR encoded. So this completely new marshalling
	   used by MAPI needs to be figured out.

	   It seems that ASCII text strings always are NULL terminated,
	   also no obvious string-length-byte can be seen so it seems the
	   length of strings are determined by searching the terminating null
	   byte.

	   The first two bytes of the PDU is the length of the PDU including
	   the two length bytes.
	   The third byte may be a subcommand byte ?

	   After the PDU comes, in requests a 4 byte thing. Which is either
	   (not very often) 0xffffffff or something else. If it is
	   'something else' these four bytes are repeated for the matching
	   response packet.
	   In some repsonse packets, this 4 byte trailer are sometimes followed
	   by some other data. Unclear if this is just random padding or actual
	   data. Seems a bit non-random for padding though.

	   Some response packets have a PDU of 2 bytes only, ie only the
	   2 byte length field followed by the 4 byte trailer.
	   strange.
	   perhaps the 4 byte trailers, and the extra trailers have some
	   special meaning?
	   More work needs to be done in this area.
	*/
	it=proto_tree_add_text(tree, decrypted_tvb, 0, len, "Decrypted MAPI PDU");
	tr=proto_item_add_subtree(it, ett_mapi_decrypted_pdu);

	pdu_len=tvb_get_letohs(decrypted_tvb, 0);
	proto_tree_add_uint(tr, hf_mapi_pdu_len, decrypted_tvb, 0, 2, pdu_len);

	/*XXX call dissector here */
	proto_tree_add_item(tr, hf_mapi_decrypted_data, decrypted_tvb, 2, pdu_len-2, FALSE);

	offset+=len;

	return offset;
}

static int
mapi_logon_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
        offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep,
			sizeof(guint8), hf_mapi_unknown_string, TRUE, NULL);

        DISSECT_UNKNOWN(tvb_length_remaining(tvb, offset));

	return offset;
}

/* The strings in this function are decoded properly on seen captures.
There might be offsets/padding mismatched due to potential pointer expansions
or padding bytes. Captures where this code breaks will tell us about that */
static int
mapi_logon_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_mapi_hnd, NULL, NULL, FALSE, FALSE);

        DISSECT_UNKNOWN(20); /* this is 20 bytes, unless there are pointers */

        offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep,
			sizeof(guint8), hf_mapi_unknown_string, TRUE, NULL);

        /* Was DISSECT_UNKNOWN(6), but the 1 or 2 bytes the comment that
           was here referred to probably were padding, if they were seen;
           in another capture, there are 5 bytes there - it's probably a
           4-byte quantity, always aligned on a 4-byte boundary. */
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_mapi_unknown_long, NULL);

        offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep,
			sizeof(guint8), hf_mapi_unknown_string, TRUE, NULL);

        DISSECT_UNKNOWN( tvb_length_remaining(tvb, offset)-4 );

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
			hf_mapi_rc, NULL);

	return offset;
}

static int
mapi_ec_do_rpc_request(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_mapi_hnd, NULL, NULL, FALSE, FALSE);

	if(!mapi_decrypt){
		/* this is a unidimensional varying and conformant array of
		   encrypted data */
       		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
				dissect_ndr_byte_array, NDR_POINTER_REF,
				"Encrypted data", hf_mapi_encrypted_data);
	} else {
		offset = mapi_decrypt_pdu(tvb, offset, pinfo, tree, drep);
	}

	/* length of encrypted data. */
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_mapi_encap_datalen, NULL);

	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_mapi_unknown_short, NULL);

	return offset;
}
static int
mapi_ec_do_rpc_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_mapi_hnd, NULL, NULL, FALSE, FALSE);

	if(!mapi_decrypt){
		/* this is a unidimensional varying and conformant array of
		   encrypted data */
       		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
				dissect_ndr_byte_array, NDR_POINTER_REF,
				"Encrypted data", hf_mapi_encrypted_data);
	} else {
		offset = mapi_decrypt_pdu(tvb, offset, pinfo, tree, drep);
	}

	/* length of encrypted data */
	offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
			hf_mapi_encap_datalen, NULL);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
			hf_mapi_rc, NULL);

	return offset;
}

static int
mapi_logoff_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_mapi_hnd, NULL, NULL, FALSE, FALSE);

	return offset;
}

static int
mapi_logoff_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_mapi_hnd, NULL, NULL, FALSE, FALSE);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
			hf_mapi_rc, NULL);

	return offset;
}


static dcerpc_sub_dissector dcerpc_mapi_dissectors[] = {
        { MAPI_EC_DO_CONNECT,	"EcDoConnect",
		mapi_logon_rqst,
		mapi_logon_reply },
        { MAPI_EC_DO_DISCONNECT,"EcDoDisconnect",
		mapi_logoff_rqst,
		mapi_logoff_reply },
        { MAPI_EC_DO_RPC,	"EcDoRpc",
		mapi_ec_do_rpc_request,
		mapi_ec_do_rpc_reply },
	{ MAPI_EC_GET_MORE_RPC, "EcGetMoreRpc", NULL, NULL },
	{ MAPI_EC_REGISTER_PUSH_NOTIFICATION, "EcRRegisterPushNotification",
		NULL, NULL },
	{ MAPI_EC_UNREGISTER_PUSH_NOTIFICATION, "EcRUnregisterPushNotification",
		NULL, NULL },
	{ MAPI_EC_DUMMY_RPC, "EcDummyRpc", NULL, NULL },
	{ MAPI_EC_GET_DC_NAME, "EcRGetDCName", NULL, NULL },
 	{ MAPI_EC_NET_GET_DC_NAME, "EcRNetGetDCName", NULL, NULL },
	{ MAPI_EC_DO_RPC_EXT, "EcDoRpcExt", NULL, NULL },
        {0, NULL, NULL,  NULL }
};

void
proto_register_dcerpc_mapi(void)
{

static hf_register_info hf[] = {
	{ &hf_mapi_opnum,
	        { "Operation", "mapi.opnum", FT_UINT16, BASE_DEC,
		  NULL, 0x0, "", HFILL }},

	{ &hf_mapi_hnd,
		{ "Context Handle", "mapi.hnd", FT_BYTES, BASE_NONE,
		NULL, 0x0, "", HFILL }},

	{ &hf_mapi_rc,
		{ "Return code", "mapi.rc", FT_UINT32, BASE_HEX,
		VALS (NT_errors), 0x0, "", HFILL }},

	{ &hf_mapi_unknown_string,
		{ "Unknown string", "mapi.unknown_string", FT_STRING, BASE_NONE,
		NULL, 0, "Unknown string. If you know what this is, contact wireshark developers.", HFILL }},

	{ &hf_mapi_unknown_short,
		{ "Unknown short", "mapi.unknown_short", FT_UINT16, BASE_HEX,
		NULL, 0, "Unknown short. If you know what this is, contact wireshark developers.", HFILL }},

	{ &hf_mapi_unknown_long,
		{ "Unknown long", "mapi.unknown_long", FT_UINT32, BASE_HEX,
		NULL, 0, "Unknown long. If you know what this is, contact wireshark developers.", HFILL }},

	{ &hf_mapi_encap_datalen,
		{ "Length", "mapi.encap_len", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Length of encapsulated/encrypted data", HFILL }},

	{ &hf_mapi_encrypted_data,
		{ "Encrypted data", "mapi.encrypted_data", FT_BYTES, BASE_HEX,
		NULL, 0, "Encrypted data", HFILL }},

	{ &hf_mapi_decrypted_data_maxlen,
		{ "Max Length", "mapi.decrypted.data.maxlen", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Maximum size of buffer for decrypted data", HFILL }},

	{ &hf_mapi_decrypted_data_offset,
		{ "Offset", "mapi.decrypted.data.offset", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Offset into buffer for decrypted data", HFILL }},

	{ &hf_mapi_decrypted_data_len,
		{ "Length", "mapi.decrypted.data.len", FT_UINT32, BASE_DEC,
		NULL, 0x0, "Used size of buffer for decrypted data", HFILL }},

	{ &hf_mapi_decrypted_data,
		{ "Decrypted data", "mapi.decrypted.data", FT_BYTES, BASE_HEX,
		NULL, 0x0, "Decrypted data", HFILL }},

	{ &hf_mapi_pdu_len,
		{ "Length", "mapi.pdu.len", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Size of the command PDU", HFILL }},

	};


        static gint *ett[] = {
                &ett_dcerpc_mapi,
                &ett_mapi_decrypted_pdu
        };
	module_t *mapi_module;

        proto_dcerpc_mapi = proto_register_protocol(
                "Microsoft Exchange MAPI", "MAPI", "mapi");

        proto_register_field_array(proto_dcerpc_mapi, hf,
				   array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
	mapi_module = prefs_register_protocol(proto_dcerpc_mapi, NULL);
	prefs_register_bool_preference(mapi_module, "decrypt",
		"Decrypt MAPI PDUs",
		"Whether the dissector should decrypt MAPI PDUs",
		&mapi_decrypt);
}

void
proto_reg_handoff_dcerpc_mapi(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_mapi, ett_dcerpc_mapi,
                         &uuid_dcerpc_mapi, ver_dcerpc_mapi,
                         dcerpc_mapi_dissectors, hf_mapi_opnum);
}
