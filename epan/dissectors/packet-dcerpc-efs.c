/* packet-dcerpc-efs.c
 * Routines for the efsrpc MSRPC interface
 * Copyright 2004 Ronnie Sahlberg, Jean-Baptiste Marchand
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-dcerpc-efs.h"
#include "packet-windows-common.h"


static int proto_dcerpc_efs = -1;
static int hf_efsrpc_opnum = -1;
static int hf_efsrpc_rc = -1;
static int hf_efsrpc_filename = -1;
static int hf_efsrpc_flags = -1;
static int hf_efsrpc_hnd = -1;
static int hf_efsrpc_reserved = -1;
static int hf_efsrpc_num_entries = -1;
static int hf_efsrpc_data_size = -1;
static int hf_efsrpc_cert_dn = -1;

static gint ett_dcerpc_efs = -1;
static gint ett_dcerpc_efs_cert_hash = -1;


/* 
IDL [ uuid(c681d488-d850-11d0-8c52-00c04fd90f7e),
IDL  version(1.0),
IDL  implicit_handle(handle_t rpc_binding)
IDL ] interface efsrpc
*/


static e_uuid_t uuid_dcerpc_efs = {
	0xc681d488, 0xd850, 0x11d0,
	{ 0x8c, 0x52, 0x00, 0xc0, 0x4f, 0xd9, 0x0f, 0x7e }
};

static guint16 ver_dcerpc_efs = 1; 


/*
IDL long EfsRpcOpenFileRaw(
IDL       [out] [context_handle] void *pvContext,
IDL        [in] [string] wchar_t FileName,
IDL        [in] long Flags
IDL  );
*/

static int
efsrpc_dissect_open_file_raw_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep,
                                      sizeof(guint16),
			              hf_efsrpc_filename, TRUE, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_efsrpc_flags, NULL);

	return offset;

}

static int
efsrpc_dissect_open_file_raw_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_efsrpc_hnd, NULL, NULL, TRUE, FALSE);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_efsrpc_rc, NULL);

	return offset;
}



/*
IDL  long EfsRpcReadFileRaw(
IDL        [in] [context_handle] void *pvContext,
IDL       [out] ??? element_5
IDL  );
*/

static int
efsrpc_dissect_read_file_raw_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_efsrpc_hnd, NULL, NULL, FALSE, FALSE);

	return offset;

}


/*
IDL  long EfsRpcWriteFileRaw(
IDL        [in] [context_handle] void *pvContext,
IDL        [in] ??? element_7
IDL  );
*/


static int
efsrpc_dissect_write_file_raw_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_efsrpc_hnd, NULL, NULL, FALSE, FALSE);

	return offset;

}


static int
efsrpc_dissect_write_file_raw_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_efsrpc_rc, NULL);

	return offset;

}


/*
IDL
IDL  void EfsRpcCloseRaw(
IDL        [in,out] [context_handle] void *pvContext,
IDL  );
*/


static int
efsrpc_dissect_close_file_raw_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_efsrpc_hnd, NULL, NULL, FALSE, TRUE);

	return offset;

}


static int
efsrpc_dissect_close_file_raw_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_efsrpc_hnd, NULL, NULL, FALSE, FALSE);

	return offset;

}



/*
IDL long EfsRpcEncryptFileSrv(
IDL       [in] [string] wchar_t Filename
IDL );
 */

static int
efsrpc_dissect_encrypt_file_srv_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep,
                                      sizeof(guint16),
			              hf_efsrpc_filename, TRUE, NULL);

	return offset;

}


static int
efsrpc_dissect_encrypt_file_srv_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_efsrpc_rc, NULL);

	return offset;

}


/*
IDL  long EfsRpcDecryptFileSrv(
IDL        [in] [string] wchar_t FileName, 
IDL        [in] long Reserved
IDL  );
*/


static int
efsrpc_dissect_decrypt_file_srv_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep,
                                      sizeof(guint16),
			              hf_efsrpc_filename, TRUE, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_efsrpc_reserved, NULL);

	return offset;

}


static int
efsrpc_dissect_decrypt_file_srv_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_efsrpc_rc, NULL);

	return offset;

}


/*
IDL typedef struct {
IDL    long   cbData;
IDL    [size_is(cbData)]  void  *pbData;
IDL } EFS_HASH_BLOB;
*/

static int
efsrpc_dissect_EFS_HASH_BLOB_data(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	guint32 size;
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;

	if(di->conformant_run){
		return offset;   /* cant modify offset while performing conformant run */
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_efsrpc_data_size, &size);

	/* XXX insert some sort of proto_tree_add_item  here and show hex data
	   of the blob */
	offset += size;
	return offset;
}

static int
efsrpc_dissect_EFS_HASH_BLOB(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	guint32 size;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_efsrpc_data_size, &size);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		efsrpc_dissect_EFS_HASH_BLOB_data, NDR_POINTER_UNIQUE,
		"HASH_BLOB", -1);

	return offset;
}


static int
efsrpc_dissect_efs_SID_ptr(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_nt_SID(tvb, offset, pinfo, tree, drep);

	return offset;
}


/*
IDL typedef struct {
IDL    long cbTotalLength;
IDL    SID *pUserSid;
IDL    EFS_HASH_BLOB  *pHash;
IDL    [string] wchar_t lpDisplayInformation;
IDL } ENCRYPTION_CERTIFICATE_HASH;
*/

static int
efsrpc_dissect_ENCRYPTION_CERTIFICATE_HASH(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *parent_tree,
				     guint8 *drep)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "ENCRYPTION_CERTIFICATE_HASH");
		tree = proto_item_add_subtree(item, ett_dcerpc_efs_cert_hash);
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_efsrpc_data_size, NULL);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		efsrpc_dissect_efs_SID_ptr, NDR_POINTER_UNIQUE,
		"SID", -1);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		efsrpc_dissect_EFS_HASH_BLOB, NDR_POINTER_UNIQUE,
		"EFS_HASH_BLOB", -1);

	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
		"Certificate DN", hf_efsrpc_cert_dn, cb_wstr_postprocess,
		GINT_TO_POINTER(CB_STR_COL_INFO | 1));

	return offset;
}


static int
efsrpc_dissect_ENCRYPTION_CERTIFICATE_HASH_ptr(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		efsrpc_dissect_ENCRYPTION_CERTIFICATE_HASH, NDR_POINTER_UNIQUE,
		"ENCRYPTION_CERTIFICATE_HASH", -1);

	return offset;

}


static int
efsrpc_dissect_ENCRYPTION_CERTIFICATE_HASH_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			efsrpc_dissect_ENCRYPTION_CERTIFICATE_HASH_ptr);

	return offset;
}

/*
IDL  typedef struct {
IDL    long nCert_Hash;
IDL    [size_is(nCert_Hash)] [unique] ENCRYPTION_CERTIFICATE_HASH *pUsers;
IDL  } ENCRYPTION_CERTIFICATE_HASH_LIST;
*/

static int 
efsrpc_dissect_ENCRYPTION_CERTIFICATE_HASH_LIST(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_efsrpc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		efsrpc_dissect_ENCRYPTION_CERTIFICATE_HASH_array, NDR_POINTER_UNIQUE,
		"ENCRYPTION_CERTIFICATE_HASH array:", -1);

	return offset;

}



/*
IDL  long EfsRpcQueryUsersOnFile(
IDL        [in] [string] wchar_t FileName,
IDL       [out] [ref] ENCRYPTION_CERTIFICATE_HASH_LIST **pUsers
IDL  );
*/


static int
efsrpc_dissect_query_users_on_file_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep,
                                      sizeof(guint16),
			              hf_efsrpc_filename, TRUE, NULL);


	return offset;

}


static int
efsrpc_dissect_query_users_on_file_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		efsrpc_dissect_ENCRYPTION_CERTIFICATE_HASH_LIST, NDR_POINTER_UNIQUE,
		"ENCRYPTION_CERTIFICATE_HASH_LIST", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_efsrpc_rc, NULL);

	return offset;

}

/*
IDL  long EfsRpcQueryRecoveryAgents(
IDL        [in] [string] wchar_t FileName,
IDL       [out] [ref] ENCRYPTION_CERTIFICATE_HASH_LIST **pRecoveryAgents
IDL  );
*/

static int
efsrpc_dissect_query_recovery_agents_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep,
                                      sizeof(guint16),
			              hf_efsrpc_filename, TRUE, NULL);

	return offset;

}


static int
efsrpc_dissect_query_recovery_agents_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		efsrpc_dissect_ENCRYPTION_CERTIFICATE_HASH_LIST, NDR_POINTER_UNIQUE,
		"ENCRYPTION_CERTIFICATE_HASH_LIST", -1);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_efsrpc_rc, NULL);

	return offset;


}



/*
IDL long EfsRpcRemoveUsersFromFile(
IDL        [in] [string] wchar_t FileName,
IDL        [in] ENCRYPTION_CERTIFICATE_LIST Hashes
IDL  );
*/

static int
efsrpc_dissect_remove_users_from_file_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep,
                                      sizeof(guint16),
			              hf_efsrpc_filename, TRUE, NULL);
#if 0
	offset = efsrpc_dissect_ENCRYPTION_CERTIFICATE_LIST(tvb, offset,
			pinfo, tree, drep);
#endif
	return offset;

}


static int
efsrpc_dissect_remove_users_from_file_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_efsrpc_rc, NULL);

	return offset;

}

/*
IDL long EfsRpcAddUsersToFile(
IDL        [in] [string] wchar_t FileName,
IDL        [in] ENCRYPTION_CERTIFICATE_LIST Hashes
IDL  );
*/

static int
efsrpc_dissect_add_users_from_file_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

        offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep,
                                      sizeof(guint16),
			              hf_efsrpc_filename, TRUE, NULL);
#if 0
	offset = efsrpc_dissect_ENCRYPTION_CERTIFICATE_LIST(tvb, offset,
			pinfo, tree, drep);
#endif
	return offset;

}


static int
efsrpc_dissect_add_users_from_file_reply(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			hf_efsrpc_rc, NULL);

	return offset;

}


/*
IDL typedef struct {
IDL    long dwCertEncodingType;
IDL    long cbData;
IDL    [size_is(cbData)] [unique] byte *pbData
IDL  } EFS_CERTIFICATE_BLOB;
*/

/*
IDL typedef struct {
IDL    long TotalLength;
IDL    [unique] SID *pUserSid;
IDL    [unique] EFS_CERTIFICATE_BLOB *pCertBlob;
IDL  } ENCRYPTION_CERTIFICATE;
*/

/*
IDL  long EfsRpcSetFileEncryptionKey(
IDL        [in] [unique] ENCRYPTION_CERTIFICATE *pEncryptionCertificate
IDL  );
*/

static dcerpc_sub_dissector dcerpc_efs_dissectors[] = {
        { EFS_RPC_OPEN_FILE_RAW , "EfsRpcOpenFileRaw",
		efsrpc_dissect_open_file_raw_rqst,
		efsrpc_dissect_open_file_raw_reply },
        { EFS_RPC_READ_FILE_RAW, "EfsRpcReadFileRaw",
		efsrpc_dissect_read_file_raw_rqst,
		NULL },
        { EFS_RPC_WRITE_FILE_RAW, "EfsRpcWriteFileRaw",
		efsrpc_dissect_write_file_raw_rqst,
		efsrpc_dissect_write_file_raw_reply },
        { EFS_RPC_CLOSE_RAW, "EfsRpcCloseRaw",
		efsrpc_dissect_close_file_raw_rqst,
		efsrpc_dissect_close_file_raw_reply },
        { EFS_RPC_ENCRYPT_FILE_SRV, "EfsRpcEncryptFileSrv",
		efsrpc_dissect_encrypt_file_srv_rqst, 
        	efsrpc_dissect_encrypt_file_srv_reply },
        { EFS_RPC_DECRYPT_FILE_SRV, "EfsRpcDecryptFileSrv",
		efsrpc_dissect_decrypt_file_srv_rqst, 
        	efsrpc_dissect_decrypt_file_srv_reply },
        { EFS_RPC_QUERY_USERS_ON_FILE, "EfsRpcQueryUsersOnFile",
		efsrpc_dissect_query_users_on_file_rqst,
		efsrpc_dissect_query_users_on_file_reply },
        { EFS_RPC_QUERY_RECOVERY_AGENTS, "EfsRpcQueryRecoveryAgents",
		efsrpc_dissect_query_recovery_agents_rqst,
		efsrpc_dissect_query_recovery_agents_reply },
        { EFS_RPC_REMOVE_USERS_FROM_FILE, "EfsRpcRemoveUsersFromFile",
		efsrpc_dissect_remove_users_from_file_rqst,
		efsrpc_dissect_remove_users_from_file_reply },
        { EFS_RPC_ADD_USERS_TO_FILE, "EfsRpcAddUsersToFile",
		efsrpc_dissect_add_users_from_file_rqst,
		efsrpc_dissect_add_users_from_file_reply },
        { EFS_RPC_SET_FILE_ENCRYPTION_KEY, "EfsRpcSetFileEncryptionKey"
		, NULL, NULL },
        { EFS_RPC_NOT_SUPPORTED, "EfsRpcNotSupported"
		, NULL, NULL },
        { EFS_RPC_FILE_KEY_INFO, "EfsRpcFileKeyInfo"
		, NULL, NULL },
        { EFS_RPC_DUPLICATE_ENCRYPTION_INFO_FILE,
		"EfsRpcDuplicateEncryptionInfoFile", NULL, NULL },
        { 0, NULL, NULL,  NULL }
};

void
proto_register_dcerpc_efs(void)
{
static hf_register_info hf[] = {
	{ &hf_efsrpc_opnum, { 
		"Operation", "efsrpc.opnum", FT_UINT16, BASE_DEC,
		NULL, 0x0, "", HFILL }},
	{ &hf_efsrpc_rc, {
		"Return code", "efsrpc.rc", FT_UINT32, BASE_HEX,
		VALS(NT_errors), 0x0, "EFSRPC return code", HFILL }},
	{ &hf_efsrpc_filename,
	    { "Filename", "efsrpc.filename", FT_STRING, BASE_NONE,
	      NULL, 0x0, "File name", HFILL}},

	{ &hf_efsrpc_flags, {
		"Flags", "efsrpc.flags", FT_UINT32, BASE_HEX,
		NULL, 0x0, "EFSRPC Flags", HFILL }},

	{ &hf_efsrpc_hnd, { 
		"Context Handle", "efsrpc.hnd", FT_BYTES,
	      	BASE_NONE, NULL, 0x0, "Context Handle", HFILL}},

	{ &hf_efsrpc_reserved, {
		"Reserved value", "efsrpc.reserved", FT_UINT32, BASE_HEX,
		NULL, 0x0, "Reserved value", HFILL }},

	 { &hf_efsrpc_num_entries,
	    { "Number of entries", "efsrpc.num_entries", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of Entries", HFILL}},

	 { &hf_efsrpc_data_size,
	    { "Size of data structure", "efsrpc.data_size", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Size of data structure", HFILL}},

	{ &hf_efsrpc_cert_dn,
	    { "Certificate DN", "efsrpc.cert_dn", FT_STRING, BASE_NONE,
	      NULL, 0x0, "Distinguished Name of EFS certificate", HFILL}},


	};

        static gint *ett[] = {
                &ett_dcerpc_efs,
		&ett_dcerpc_efs_cert_hash
        };

        proto_dcerpc_efs = proto_register_protocol(
                "Microsoft Encrypted File System Service", "EFSRPC", "efsrpc");

        proto_register_field_array(proto_dcerpc_efs, hf,
				   array_length(hf));

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_efs(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_efs, ett_dcerpc_efs,
                         &uuid_dcerpc_efs, ver_dcerpc_efs,
                         dcerpc_efs_dissectors, hf_efsrpc_opnum);
}
