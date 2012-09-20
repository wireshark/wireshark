/* DO NOT EDIT
	This filter was automatically generated
	from efs.idl and efs.cnf.
	
	Pidl is a perl based IDL compiler for DCE/RPC idl files. 
	It is maintained by the Samba team, not the Wireshark team.
	Instructions on how to download and install Pidl can be 
	found at http://wiki.wireshark.org/Pidl

	$Id$
*/


#include "config.h"

#ifdef _MSC_VER
#pragma warning(disable:4005)
#pragma warning(disable:4013)
#pragma warning(disable:4018)
#pragma warning(disable:4101)
#endif

#include <glib.h>
#include <string.h>
#include <epan/packet.h>

#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-windows-common.h"
#include "packet-dcerpc-efs.h"

/* Ett declarations */
static gint ett_dcerpc_efs = -1;
static gint ett_efs_EFS_HASH_BLOB = -1;
static gint ett_efs_ENCRYPTION_CERTIFICATE_HASH = -1;
static gint ett_efs_ENCRYPTION_CERTIFICATE_HASH_LIST = -1;
static gint ett_efs_EFS_CERTIFICATE_BLOB = -1;
static gint ett_efs_ENCRYPTION_CERTIFICATE = -1;


/* Header field declarations */
static gint hf_efs_EfsRpcCloseRaw_pvContext = -1;
static gint hf_efs_EfsRpcSetFileEncryptionKey_pEncryptionCertificate = -1;
static gint hf_efs_EfsRpcOpenFileRaw_pvContext = -1;
static gint hf_efs_ENCRYPTION_CERTIFICATE_HASH_pUserSid = -1;
static gint hf_efs_EfsRpcReadFileRaw_pvContext = -1;
static gint hf_efs_EfsRpcQueryRecoveryAgents_FileName = -1;
static gint hf_efs_EfsRpcQueryUsersOnFile_FileName = -1;
static gint hf_efs_EfsRpcOpenFileRaw_FileName = -1;
static gint hf_efs_ENCRYPTION_CERTIFICATE_pCertBlob = -1;
static gint hf_efs_opnum = -1;
static gint hf_efs_EFS_HASH_BLOB_pbData = -1;
static gint hf_efs_ENCRYPTION_CERTIFICATE_HASH_lpDisplayInformation = -1;
static gint hf_efs_EfsRpcOpenFileRaw_Flags = -1;
static gint hf_efs_EFS_CERTIFICATE_BLOB_pbData = -1;
static gint hf_efs_ENCRYPTION_CERTIFICATE_HASH_LIST_nCert_Hash = -1;
static gint hf_efs_EfsRpcEncryptFileSrv_Filename = -1;
static gint hf_efs_EfsRpcRemoveUsersFromFile_FileName = -1;
static gint hf_efs_EfsRpcQueryUsersOnFile_pUsers = -1;
static gint hf_efs_EfsRpcDecryptFileSrv_FileName = -1;
static gint hf_efs_ENCRYPTION_CERTIFICATE_TotalLength = -1;
static gint hf_efs_EfsRpcAddUsersToFile_FileName = -1;
static gint hf_efs_EfsRpcQueryRecoveryAgents_pRecoveryAgents = -1;
static gint hf_efs_ENCRYPTION_CERTIFICATE_HASH_pHash = -1;
static gint hf_efs_ENCRYPTION_CERTIFICATE_HASH_cbTotalLength = -1;
static gint hf_efs_werror = -1;
static gint hf_efs_EFS_HASH_BLOB_cbData = -1;
static gint hf_efs_EfsRpcWriteFileRaw_pvContext = -1;
static gint hf_efs_ENCRYPTION_CERTIFICATE_HASH_LIST_pUsers = -1;
static gint hf_efs_ENCRYPTION_CERTIFICATE_pUserSid = -1;
static gint hf_efs_EFS_CERTIFICATE_BLOB_dwCertEncodingType = -1;
static gint hf_efs_EfsRpcDecryptFileSrv_Reserved = -1;
static gint hf_efs_EFS_CERTIFICATE_BLOB_cbData = -1;

static gint proto_dcerpc_efs = -1;
/* Version information */


static e_uuid_t uuid_dcerpc_efs = {
	0xc681d488, 0xd850, 0x11d0,
	{ 0x8c, 0x52, 0x00, 0xc0, 0x4f, 0xd9, 0x0f, 0x7e }
};
static guint16 ver_dcerpc_efs = 1;

static int efs_dissect_element_EFS_HASH_BLOB_cbData(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EFS_HASH_BLOB_pbData(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EFS_HASH_BLOB_pbData_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EFS_HASH_BLOB_pbData__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_cbTotalLength(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_pUserSid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_pUserSid_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_pHash(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_pHash_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_lpDisplayInformation(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_lpDisplayInformation_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_LIST_nCert_Hash(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_LIST_pUsers(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_LIST_pUsers_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_LIST_pUsers__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EFS_CERTIFICATE_BLOB_dwCertEncodingType(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EFS_CERTIFICATE_BLOB_cbData(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EFS_CERTIFICATE_BLOB_pbData(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EFS_CERTIFICATE_BLOB_pbData_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EFS_CERTIFICATE_BLOB_pbData__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_ENCRYPTION_CERTIFICATE_TotalLength(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_ENCRYPTION_CERTIFICATE_pUserSid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_ENCRYPTION_CERTIFICATE_pUserSid_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_ENCRYPTION_CERTIFICATE_pCertBlob(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_ENCRYPTION_CERTIFICATE_pCertBlob_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcOpenFileRaw_pvContext(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcOpenFileRaw_pvContext_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcOpenFileRaw_FileName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcOpenFileRaw_Flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcReadFileRaw_pvContext(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcReadFileRaw_pvContext_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcWriteFileRaw_pvContext(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcWriteFileRaw_pvContext_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcCloseRaw_pvContext(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcCloseRaw_pvContext_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcEncryptFileSrv_Filename(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcDecryptFileSrv_FileName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcDecryptFileSrv_Reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcQueryUsersOnFile_FileName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcQueryUsersOnFile_pUsers(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcQueryUsersOnFile_pUsers_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcQueryUsersOnFile_pUsers__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcQueryRecoveryAgents_FileName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcQueryRecoveryAgents_pRecoveryAgents(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcQueryRecoveryAgents_pRecoveryAgents_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcQueryRecoveryAgents_pRecoveryAgents__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcRemoveUsersFromFile_FileName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcAddUsersToFile_FileName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcSetFileEncryptionKey_pEncryptionCertificate(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int efs_dissect_element_EfsRpcSetFileEncryptionKey_pEncryptionCertificate_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_);
static int
efs_dissect_struct_dom_sid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	dcerpc_info *di = (dcerpc_info *)pinfo->private_data;
	if(di->conformant_run){
		/* just a run to handle conformant arrays, no scalars to dissect */
		return offset;
	}
	offset=dissect_nt_sid(tvb, offset, tree, "SID", NULL, -1);
	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 cbData; */
/* IDL: 	[size_is(cbData)] [unique(1)] uint8 *pbData; */
/* IDL: } */

static int
efs_dissect_element_EFS_HASH_BLOB_cbData(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_efs_EFS_HASH_BLOB_cbData, 0);

	return offset;
}

static int
efs_dissect_element_EFS_HASH_BLOB_pbData(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_EFS_HASH_BLOB_pbData_, NDR_POINTER_UNIQUE, "Pointer to Pbdata (uint8)",hf_efs_EFS_HASH_BLOB_pbData);

	return offset;
}

static int
efs_dissect_element_EFS_HASH_BLOB_pbData_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, efs_dissect_element_EFS_HASH_BLOB_pbData__);

	return offset;
}

static int
efs_dissect_element_EFS_HASH_BLOB_pbData__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_efs_EFS_HASH_BLOB_pbData, 0);

	return offset;
}

int
efs_dissect_struct_EFS_HASH_BLOB(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_efs_EFS_HASH_BLOB);
	}
	
	offset = efs_dissect_element_EFS_HASH_BLOB_cbData(tvb, offset, pinfo, tree, drep);

	offset = efs_dissect_element_EFS_HASH_BLOB_pbData(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 cbTotalLength; */
/* IDL: 	[unique(1)] dom_sid *pUserSid; */
/* IDL: 	[unique(1)] EFS_HASH_BLOB *pHash; */
/* IDL: 	[charset(UTF16)] [unique(1)] uint16 *lpDisplayInformation; */
/* IDL: } */

static int
efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_cbTotalLength(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_efs_ENCRYPTION_CERTIFICATE_HASH_cbTotalLength, 0);

	return offset;
}

static int
efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_pUserSid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_pUserSid_, NDR_POINTER_UNIQUE, "Pointer to Pusersid (dom_sid)",hf_efs_ENCRYPTION_CERTIFICATE_HASH_pUserSid);

	return offset;
}

static int
efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_pUserSid_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = efs_dissect_struct_dom_sid(tvb,offset,pinfo,tree,drep,hf_efs_ENCRYPTION_CERTIFICATE_HASH_pUserSid,0);

	return offset;
}

static int
efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_pHash(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_pHash_, NDR_POINTER_UNIQUE, "Pointer to Phash (EFS_HASH_BLOB)",hf_efs_ENCRYPTION_CERTIFICATE_HASH_pHash);

	return offset;
}

static int
efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_pHash_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = efs_dissect_struct_EFS_HASH_BLOB(tvb,offset,pinfo,tree,drep,hf_efs_ENCRYPTION_CERTIFICATE_HASH_pHash,0);

	return offset;
}

static int
efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_lpDisplayInformation(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_lpDisplayInformation_, NDR_POINTER_UNIQUE, "Pointer to Lpdisplayinformation (uint16)",hf_efs_ENCRYPTION_CERTIFICATE_HASH_lpDisplayInformation);

	return offset;
}

static int
efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_lpDisplayInformation_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_efs_ENCRYPTION_CERTIFICATE_HASH_lpDisplayInformation, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

int
efs_dissect_struct_ENCRYPTION_CERTIFICATE_HASH(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_efs_ENCRYPTION_CERTIFICATE_HASH);
	}
	
	offset = efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_cbTotalLength(tvb, offset, pinfo, tree, drep);

	offset = efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_pUserSid(tvb, offset, pinfo, tree, drep);

	offset = efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_pHash(tvb, offset, pinfo, tree, drep);

	offset = efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_lpDisplayInformation(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 nCert_Hash; */
/* IDL: 	[size_is(nCert_Hash)] [unique(1)] ENCRYPTION_CERTIFICATE_HASH *pUsers[*]; */
/* IDL: } */

static int
efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_LIST_nCert_Hash(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_efs_ENCRYPTION_CERTIFICATE_HASH_LIST_nCert_Hash, 0);

	return offset;
}

static int
efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_LIST_pUsers(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_LIST_pUsers_);

	return offset;
}

static int
efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_LIST_pUsers_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_LIST_pUsers__, NDR_POINTER_UNIQUE, "Pointer to Pusers (ENCRYPTION_CERTIFICATE_HASH)",hf_efs_ENCRYPTION_CERTIFICATE_HASH_LIST_pUsers);

	return offset;
}

static int
efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_LIST_pUsers__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = efs_dissect_struct_ENCRYPTION_CERTIFICATE_HASH(tvb,offset,pinfo,tree,drep,hf_efs_ENCRYPTION_CERTIFICATE_HASH_LIST_pUsers,0);

	return offset;
}

int
efs_dissect_struct_ENCRYPTION_CERTIFICATE_HASH_LIST(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_efs_ENCRYPTION_CERTIFICATE_HASH_LIST);
	}
	
	offset = efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_LIST_nCert_Hash(tvb, offset, pinfo, tree, drep);

	offset = efs_dissect_element_ENCRYPTION_CERTIFICATE_HASH_LIST_pUsers(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 dwCertEncodingType; */
/* IDL: 	uint32 cbData; */
/* IDL: 	[size_is(cbData)] [unique(1)] uint8 *pbData; */
/* IDL: } */

static int
efs_dissect_element_EFS_CERTIFICATE_BLOB_dwCertEncodingType(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_efs_EFS_CERTIFICATE_BLOB_dwCertEncodingType, 0);

	return offset;
}

static int
efs_dissect_element_EFS_CERTIFICATE_BLOB_cbData(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_efs_EFS_CERTIFICATE_BLOB_cbData, 0);

	return offset;
}

static int
efs_dissect_element_EFS_CERTIFICATE_BLOB_pbData(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_EFS_CERTIFICATE_BLOB_pbData_, NDR_POINTER_UNIQUE, "Pointer to Pbdata (uint8)",hf_efs_EFS_CERTIFICATE_BLOB_pbData);

	return offset;
}

static int
efs_dissect_element_EFS_CERTIFICATE_BLOB_pbData_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, efs_dissect_element_EFS_CERTIFICATE_BLOB_pbData__);

	return offset;
}

static int
efs_dissect_element_EFS_CERTIFICATE_BLOB_pbData__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint8(tvb, offset, pinfo, tree, drep, hf_efs_EFS_CERTIFICATE_BLOB_pbData, 0);

	return offset;
}

int
efs_dissect_struct_EFS_CERTIFICATE_BLOB(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_efs_EFS_CERTIFICATE_BLOB);
	}
	
	offset = efs_dissect_element_EFS_CERTIFICATE_BLOB_dwCertEncodingType(tvb, offset, pinfo, tree, drep);

	offset = efs_dissect_element_EFS_CERTIFICATE_BLOB_cbData(tvb, offset, pinfo, tree, drep);

	offset = efs_dissect_element_EFS_CERTIFICATE_BLOB_pbData(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}


/* IDL: struct { */
/* IDL: 	uint32 TotalLength; */
/* IDL: 	[unique(1)] dom_sid *pUserSid; */
/* IDL: 	[unique(1)] EFS_CERTIFICATE_BLOB *pCertBlob; */
/* IDL: } */

static int
efs_dissect_element_ENCRYPTION_CERTIFICATE_TotalLength(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_efs_ENCRYPTION_CERTIFICATE_TotalLength, 0);

	return offset;
}

static int
efs_dissect_element_ENCRYPTION_CERTIFICATE_pUserSid(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_ENCRYPTION_CERTIFICATE_pUserSid_, NDR_POINTER_UNIQUE, "Pointer to Pusersid (dom_sid)",hf_efs_ENCRYPTION_CERTIFICATE_pUserSid);

	return offset;
}

static int
efs_dissect_element_ENCRYPTION_CERTIFICATE_pUserSid_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = efs_dissect_struct_dom_sid(tvb,offset,pinfo,tree,drep,hf_efs_ENCRYPTION_CERTIFICATE_pUserSid,0);

	return offset;
}

static int
efs_dissect_element_ENCRYPTION_CERTIFICATE_pCertBlob(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_ENCRYPTION_CERTIFICATE_pCertBlob_, NDR_POINTER_UNIQUE, "Pointer to Pcertblob (EFS_CERTIFICATE_BLOB)",hf_efs_ENCRYPTION_CERTIFICATE_pCertBlob);

	return offset;
}

static int
efs_dissect_element_ENCRYPTION_CERTIFICATE_pCertBlob_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = efs_dissect_struct_EFS_CERTIFICATE_BLOB(tvb,offset,pinfo,tree,drep,hf_efs_ENCRYPTION_CERTIFICATE_pCertBlob,0);

	return offset;
}

int
efs_dissect_struct_ENCRYPTION_CERTIFICATE(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	int old_offset;

	ALIGN_TO_4_BYTES;

	old_offset = offset;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, hf_index, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_efs_ENCRYPTION_CERTIFICATE);
	}
	
	offset = efs_dissect_element_ENCRYPTION_CERTIFICATE_TotalLength(tvb, offset, pinfo, tree, drep);

	offset = efs_dissect_element_ENCRYPTION_CERTIFICATE_pUserSid(tvb, offset, pinfo, tree, drep);

	offset = efs_dissect_element_ENCRYPTION_CERTIFICATE_pCertBlob(tvb, offset, pinfo, tree, drep);


	proto_item_set_len(item, offset-old_offset);

	return offset;
}

static int
efs_dissect_element_EfsRpcOpenFileRaw_pvContext(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_EfsRpcOpenFileRaw_pvContext_, NDR_POINTER_REF, "Pointer to Pvcontext (policy_handle)",hf_efs_EfsRpcOpenFileRaw_pvContext);

	return offset;
}

static int
efs_dissect_element_EfsRpcOpenFileRaw_pvContext_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_efs_EfsRpcOpenFileRaw_pvContext, PIDL_POLHND_OPEN);

	return offset;
}

static int
efs_dissect_element_EfsRpcOpenFileRaw_FileName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_efs_EfsRpcOpenFileRaw_FileName, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
efs_dissect_element_EfsRpcOpenFileRaw_Flags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_efs_EfsRpcOpenFileRaw_Flags, 0);

	return offset;
}

/* IDL: WERROR EfsRpcOpenFileRaw( */
/* IDL: [out] [ref] policy_handle *pvContext, */
/* IDL: [charset(UTF16)] [in] uint16 FileName[*], */
/* IDL: [in] uint32 Flags */
/* IDL: ); */

static int
efs_dissect_EfsRpcOpenFileRaw_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="EfsRpcOpenFileRaw";
	offset = efs_dissect_element_EfsRpcOpenFileRaw_pvContext(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_efs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
efs_dissect_EfsRpcOpenFileRaw_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EfsRpcOpenFileRaw";
	offset = efs_dissect_element_EfsRpcOpenFileRaw_FileName(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = efs_dissect_element_EfsRpcOpenFileRaw_Flags(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
efs_dissect_element_EfsRpcReadFileRaw_pvContext(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_EfsRpcReadFileRaw_pvContext_, NDR_POINTER_REF, "Pointer to Pvcontext (policy_handle)",hf_efs_EfsRpcReadFileRaw_pvContext);

	return offset;
}

static int
efs_dissect_element_EfsRpcReadFileRaw_pvContext_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_efs_EfsRpcReadFileRaw_pvContext, 0);

	return offset;
}

/* IDL: WERROR EfsRpcReadFileRaw( */
/* IDL: [in] [ref] policy_handle *pvContext */
/* IDL: ); */

static int
efs_dissect_EfsRpcReadFileRaw_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="EfsRpcReadFileRaw";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_efs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
efs_dissect_EfsRpcReadFileRaw_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EfsRpcReadFileRaw";
	offset = efs_dissect_element_EfsRpcReadFileRaw_pvContext(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
efs_dissect_element_EfsRpcWriteFileRaw_pvContext(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_EfsRpcWriteFileRaw_pvContext_, NDR_POINTER_REF, "Pointer to Pvcontext (policy_handle)",hf_efs_EfsRpcWriteFileRaw_pvContext);

	return offset;
}

static int
efs_dissect_element_EfsRpcWriteFileRaw_pvContext_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_efs_EfsRpcWriteFileRaw_pvContext, 0);

	return offset;
}

/* IDL: WERROR EfsRpcWriteFileRaw( */
/* IDL: [in] [ref] policy_handle *pvContext */
/* IDL: ); */

static int
efs_dissect_EfsRpcWriteFileRaw_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="EfsRpcWriteFileRaw";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_efs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
efs_dissect_EfsRpcWriteFileRaw_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EfsRpcWriteFileRaw";
	offset = efs_dissect_element_EfsRpcWriteFileRaw_pvContext(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
efs_dissect_element_EfsRpcCloseRaw_pvContext(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_EfsRpcCloseRaw_pvContext_, NDR_POINTER_REF, "Pointer to Pvcontext (policy_handle)",hf_efs_EfsRpcCloseRaw_pvContext);

	return offset;
}

static int
efs_dissect_element_EfsRpcCloseRaw_pvContext_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_policy_hnd(tvb, offset, pinfo, tree, drep, hf_efs_EfsRpcCloseRaw_pvContext, PIDL_POLHND_CLOSE);

	return offset;
}

/* IDL: void EfsRpcCloseRaw( */
/* IDL: [out] [in] [ref] policy_handle *pvContext */
/* IDL: ); */

static int
efs_dissect_EfsRpcCloseRaw_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EfsRpcCloseRaw";
	offset = efs_dissect_element_EfsRpcCloseRaw_pvContext(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	return offset;
}

static int
efs_dissect_EfsRpcCloseRaw_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EfsRpcCloseRaw";
	offset = efs_dissect_element_EfsRpcCloseRaw_pvContext(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
efs_dissect_element_EfsRpcEncryptFileSrv_Filename(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_efs_EfsRpcEncryptFileSrv_Filename, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

/* IDL: WERROR EfsRpcEncryptFileSrv( */
/* IDL: [charset(UTF16)] [in] uint16 Filename[*] */
/* IDL: ); */

static int
efs_dissect_EfsRpcEncryptFileSrv_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="EfsRpcEncryptFileSrv";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_efs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
efs_dissect_EfsRpcEncryptFileSrv_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EfsRpcEncryptFileSrv";
	offset = efs_dissect_element_EfsRpcEncryptFileSrv_Filename(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
efs_dissect_element_EfsRpcDecryptFileSrv_FileName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_efs_EfsRpcDecryptFileSrv_FileName, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
efs_dissect_element_EfsRpcDecryptFileSrv_Reserved(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = PIDL_dissect_uint32(tvb, offset, pinfo, tree, drep, hf_efs_EfsRpcDecryptFileSrv_Reserved, 0);

	return offset;
}

/* IDL: WERROR EfsRpcDecryptFileSrv( */
/* IDL: [charset(UTF16)] [in] uint16 FileName[*], */
/* IDL: [in] uint32 Reserved */
/* IDL: ); */

static int
efs_dissect_EfsRpcDecryptFileSrv_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="EfsRpcDecryptFileSrv";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_efs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
efs_dissect_EfsRpcDecryptFileSrv_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EfsRpcDecryptFileSrv";
	offset = efs_dissect_element_EfsRpcDecryptFileSrv_FileName(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	offset = efs_dissect_element_EfsRpcDecryptFileSrv_Reserved(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
efs_dissect_element_EfsRpcQueryUsersOnFile_FileName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_efs_EfsRpcQueryUsersOnFile_FileName, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
efs_dissect_element_EfsRpcQueryUsersOnFile_pUsers(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_EfsRpcQueryUsersOnFile_pUsers_, NDR_POINTER_REF, "Pointer to Pusers (ENCRYPTION_CERTIFICATE_HASH_LIST)",hf_efs_EfsRpcQueryUsersOnFile_pUsers);

	return offset;
}

static int
efs_dissect_element_EfsRpcQueryUsersOnFile_pUsers_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_EfsRpcQueryUsersOnFile_pUsers__, NDR_POINTER_REF, "Pointer to Pusers (ENCRYPTION_CERTIFICATE_HASH_LIST)",hf_efs_EfsRpcQueryUsersOnFile_pUsers);

	return offset;
}

static int
efs_dissect_element_EfsRpcQueryUsersOnFile_pUsers__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = efs_dissect_struct_ENCRYPTION_CERTIFICATE_HASH_LIST(tvb,offset,pinfo,tree,drep,hf_efs_EfsRpcQueryUsersOnFile_pUsers,0);

	return offset;
}

/* IDL: WERROR EfsRpcQueryUsersOnFile( */
/* IDL: [charset(UTF16)] [in] uint16 FileName[*], */
/* IDL: [out] [unique(1)] [ref] ENCRYPTION_CERTIFICATE_HASH_LIST **pUsers */
/* IDL: ); */

static int
efs_dissect_EfsRpcQueryUsersOnFile_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="EfsRpcQueryUsersOnFile";
	offset = efs_dissect_element_EfsRpcQueryUsersOnFile_pUsers(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_efs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
efs_dissect_EfsRpcQueryUsersOnFile_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EfsRpcQueryUsersOnFile";
	offset = efs_dissect_element_EfsRpcQueryUsersOnFile_FileName(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
efs_dissect_element_EfsRpcQueryRecoveryAgents_FileName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_efs_EfsRpcQueryRecoveryAgents_FileName, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

static int
efs_dissect_element_EfsRpcQueryRecoveryAgents_pRecoveryAgents(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_EfsRpcQueryRecoveryAgents_pRecoveryAgents_, NDR_POINTER_REF, "Pointer to Precoveryagents (ENCRYPTION_CERTIFICATE_HASH_LIST)",hf_efs_EfsRpcQueryRecoveryAgents_pRecoveryAgents);

	return offset;
}

static int
efs_dissect_element_EfsRpcQueryRecoveryAgents_pRecoveryAgents_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_embedded_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_EfsRpcQueryRecoveryAgents_pRecoveryAgents__, NDR_POINTER_REF, "Pointer to Precoveryagents (ENCRYPTION_CERTIFICATE_HASH_LIST)",hf_efs_EfsRpcQueryRecoveryAgents_pRecoveryAgents);

	return offset;
}

static int
efs_dissect_element_EfsRpcQueryRecoveryAgents_pRecoveryAgents__(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = efs_dissect_struct_ENCRYPTION_CERTIFICATE_HASH_LIST(tvb,offset,pinfo,tree,drep,hf_efs_EfsRpcQueryRecoveryAgents_pRecoveryAgents,0);

	return offset;
}

/* IDL: WERROR EfsRpcQueryRecoveryAgents( */
/* IDL: [charset(UTF16)] [in] uint16 FileName[*], */
/* IDL: [out] [unique(1)] [ref] ENCRYPTION_CERTIFICATE_HASH_LIST **pRecoveryAgents */
/* IDL: ); */

static int
efs_dissect_EfsRpcQueryRecoveryAgents_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="EfsRpcQueryRecoveryAgents";
	offset = efs_dissect_element_EfsRpcQueryRecoveryAgents_pRecoveryAgents(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_efs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
efs_dissect_EfsRpcQueryRecoveryAgents_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EfsRpcQueryRecoveryAgents";
	offset = efs_dissect_element_EfsRpcQueryRecoveryAgents_FileName(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
efs_dissect_element_EfsRpcRemoveUsersFromFile_FileName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_efs_EfsRpcRemoveUsersFromFile_FileName, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

/* IDL: WERROR EfsRpcRemoveUsersFromFile( */
/* IDL: [charset(UTF16)] [in] uint16 FileName[*] */
/* IDL: ); */

static int
efs_dissect_EfsRpcRemoveUsersFromFile_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="EfsRpcRemoveUsersFromFile";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_efs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
efs_dissect_EfsRpcRemoveUsersFromFile_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EfsRpcRemoveUsersFromFile";
	offset = efs_dissect_element_EfsRpcRemoveUsersFromFile_FileName(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
efs_dissect_element_EfsRpcAddUsersToFile_FileName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	char *data;

	offset = dissect_ndr_cvstring(tvb, offset, pinfo, tree, drep, sizeof(guint16), hf_efs_EfsRpcAddUsersToFile_FileName, FALSE, &data);
	proto_item_append_text(tree, ": %s", data);

	return offset;
}

/* IDL: WERROR EfsRpcAddUsersToFile( */
/* IDL: [charset(UTF16)] [in] uint16 FileName[*] */
/* IDL: ); */

static int
efs_dissect_EfsRpcAddUsersToFile_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="EfsRpcAddUsersToFile";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_efs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
efs_dissect_EfsRpcAddUsersToFile_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EfsRpcAddUsersToFile";
	offset = efs_dissect_element_EfsRpcAddUsersToFile_FileName(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

static int
efs_dissect_element_EfsRpcSetFileEncryptionKey_pEncryptionCertificate(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = dissect_ndr_toplevel_pointer(tvb, offset, pinfo, tree, drep, efs_dissect_element_EfsRpcSetFileEncryptionKey_pEncryptionCertificate_, NDR_POINTER_UNIQUE, "Pointer to Pencryptioncertificate (ENCRYPTION_CERTIFICATE)",hf_efs_EfsRpcSetFileEncryptionKey_pEncryptionCertificate);

	return offset;
}

static int
efs_dissect_element_EfsRpcSetFileEncryptionKey_pEncryptionCertificate_(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	offset = efs_dissect_struct_ENCRYPTION_CERTIFICATE(tvb,offset,pinfo,tree,drep,hf_efs_EfsRpcSetFileEncryptionKey_pEncryptionCertificate,0);

	return offset;
}

/* IDL: WERROR EfsRpcSetFileEncryptionKey( */
/* IDL: [unique(1)] [in] ENCRYPTION_CERTIFICATE *pEncryptionCertificate */
/* IDL: ); */

static int
efs_dissect_EfsRpcSetFileEncryptionKey_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="EfsRpcSetFileEncryptionKey";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_efs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
efs_dissect_EfsRpcSetFileEncryptionKey_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EfsRpcSetFileEncryptionKey";
	offset = efs_dissect_element_EfsRpcSetFileEncryptionKey_pEncryptionCertificate(tvb, offset, pinfo, tree, drep);
	offset = dissect_deferred_pointers(pinfo, tvb, offset, drep);
	return offset;
}

/* IDL: WERROR EfsRpcNotSupported( */
/* IDL:  */
/* IDL: ); */

static int
efs_dissect_EfsRpcNotSupported_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="EfsRpcNotSupported";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_efs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
efs_dissect_EfsRpcNotSupported_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EfsRpcNotSupported";
	return offset;
}

/* IDL: WERROR EfsRpcFileKeyInfo( */
/* IDL:  */
/* IDL: ); */

static int
efs_dissect_EfsRpcFileKeyInfo_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="EfsRpcFileKeyInfo";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_efs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
efs_dissect_EfsRpcFileKeyInfo_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EfsRpcFileKeyInfo";
	return offset;
}

/* IDL: WERROR EfsRpcDuplicateEncryptionInfoFile( */
/* IDL:  */
/* IDL: ); */

static int
efs_dissect_EfsRpcDuplicateEncryptionInfoFile_response(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	guint32 status;

	pinfo->dcerpc_procedure_name="EfsRpcDuplicateEncryptionInfoFile";
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_efs_werror, &status);

	if (status != 0 && check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Error: %s", val_to_str(status, WERR_errors, "Unknown DOS error 0x%08x"));

	return offset;
}

static int
efs_dissect_EfsRpcDuplicateEncryptionInfoFile_request(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_)
{
	pinfo->dcerpc_procedure_name="EfsRpcDuplicateEncryptionInfoFile";
	return offset;
}


static dcerpc_sub_dissector efs_dissectors[] = {
	{ 0, "EfsRpcOpenFileRaw",
	   efs_dissect_EfsRpcOpenFileRaw_request, efs_dissect_EfsRpcOpenFileRaw_response},
	{ 1, "EfsRpcReadFileRaw",
	   efs_dissect_EfsRpcReadFileRaw_request, efs_dissect_EfsRpcReadFileRaw_response},
	{ 2, "EfsRpcWriteFileRaw",
	   efs_dissect_EfsRpcWriteFileRaw_request, efs_dissect_EfsRpcWriteFileRaw_response},
	{ 3, "EfsRpcCloseRaw",
	   efs_dissect_EfsRpcCloseRaw_request, efs_dissect_EfsRpcCloseRaw_response},
	{ 4, "EfsRpcEncryptFileSrv",
	   efs_dissect_EfsRpcEncryptFileSrv_request, efs_dissect_EfsRpcEncryptFileSrv_response},
	{ 5, "EfsRpcDecryptFileSrv",
	   efs_dissect_EfsRpcDecryptFileSrv_request, efs_dissect_EfsRpcDecryptFileSrv_response},
	{ 6, "EfsRpcQueryUsersOnFile",
	   efs_dissect_EfsRpcQueryUsersOnFile_request, efs_dissect_EfsRpcQueryUsersOnFile_response},
	{ 7, "EfsRpcQueryRecoveryAgents",
	   efs_dissect_EfsRpcQueryRecoveryAgents_request, efs_dissect_EfsRpcQueryRecoveryAgents_response},
	{ 8, "EfsRpcRemoveUsersFromFile",
	   efs_dissect_EfsRpcRemoveUsersFromFile_request, efs_dissect_EfsRpcRemoveUsersFromFile_response},
	{ 9, "EfsRpcAddUsersToFile",
	   efs_dissect_EfsRpcAddUsersToFile_request, efs_dissect_EfsRpcAddUsersToFile_response},
	{ 10, "EfsRpcSetFileEncryptionKey",
	   efs_dissect_EfsRpcSetFileEncryptionKey_request, efs_dissect_EfsRpcSetFileEncryptionKey_response},
	{ 11, "EfsRpcNotSupported",
	   efs_dissect_EfsRpcNotSupported_request, efs_dissect_EfsRpcNotSupported_response},
	{ 12, "EfsRpcFileKeyInfo",
	   efs_dissect_EfsRpcFileKeyInfo_request, efs_dissect_EfsRpcFileKeyInfo_response},
	{ 13, "EfsRpcDuplicateEncryptionInfoFile",
	   efs_dissect_EfsRpcDuplicateEncryptionInfoFile_request, efs_dissect_EfsRpcDuplicateEncryptionInfoFile_response},
	{ 0, NULL, NULL, NULL }
};

void proto_register_dcerpc_efs(void)
{
	static hf_register_info hf[] = {
	{ &hf_efs_EfsRpcCloseRaw_pvContext, 
	  { "Pvcontext", "efs.EfsRpcCloseRaw.pvContext", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EfsRpcSetFileEncryptionKey_pEncryptionCertificate, 
	  { "Pencryptioncertificate", "efs.EfsRpcSetFileEncryptionKey.pEncryptionCertificate", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EfsRpcOpenFileRaw_pvContext, 
	  { "Pvcontext", "efs.EfsRpcOpenFileRaw.pvContext", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_ENCRYPTION_CERTIFICATE_HASH_pUserSid, 
	  { "Pusersid", "efs.ENCRYPTION_CERTIFICATE_HASH.pUserSid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EfsRpcReadFileRaw_pvContext, 
	  { "Pvcontext", "efs.EfsRpcReadFileRaw.pvContext", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EfsRpcQueryRecoveryAgents_FileName, 
	  { "Filename", "efs.EfsRpcQueryRecoveryAgents.FileName", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EfsRpcQueryUsersOnFile_FileName, 
	  { "Filename", "efs.EfsRpcQueryUsersOnFile.FileName", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EfsRpcOpenFileRaw_FileName, 
	  { "Filename", "efs.EfsRpcOpenFileRaw.FileName", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_ENCRYPTION_CERTIFICATE_pCertBlob, 
	  { "Pcertblob", "efs.ENCRYPTION_CERTIFICATE.pCertBlob", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_opnum, 
	  { "Operation", "efs.opnum", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EFS_HASH_BLOB_pbData, 
	  { "Pbdata", "efs.EFS_HASH_BLOB.pbData", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_efs_ENCRYPTION_CERTIFICATE_HASH_lpDisplayInformation, 
	  { "Lpdisplayinformation", "efs.ENCRYPTION_CERTIFICATE_HASH.lpDisplayInformation", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EfsRpcOpenFileRaw_Flags, 
	  { "Flags", "efs.EfsRpcOpenFileRaw.Flags", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EFS_CERTIFICATE_BLOB_pbData, 
	  { "Pbdata", "efs.EFS_CERTIFICATE_BLOB.pbData", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_efs_ENCRYPTION_CERTIFICATE_HASH_LIST_nCert_Hash, 
	  { "Ncert Hash", "efs.ENCRYPTION_CERTIFICATE_HASH_LIST.nCert_Hash", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EfsRpcEncryptFileSrv_Filename, 
	  { "Filename", "efs.EfsRpcEncryptFileSrv.Filename", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EfsRpcRemoveUsersFromFile_FileName, 
	  { "Filename", "efs.EfsRpcRemoveUsersFromFile.FileName", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EfsRpcQueryUsersOnFile_pUsers, 
	  { "Pusers", "efs.EfsRpcQueryUsersOnFile.pUsers", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EfsRpcDecryptFileSrv_FileName, 
	  { "Filename", "efs.EfsRpcDecryptFileSrv.FileName", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_ENCRYPTION_CERTIFICATE_TotalLength, 
	  { "Totallength", "efs.ENCRYPTION_CERTIFICATE.TotalLength", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EfsRpcAddUsersToFile_FileName, 
	  { "Filename", "efs.EfsRpcAddUsersToFile.FileName", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EfsRpcQueryRecoveryAgents_pRecoveryAgents, 
	  { "Precoveryagents", "efs.EfsRpcQueryRecoveryAgents.pRecoveryAgents", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_ENCRYPTION_CERTIFICATE_HASH_pHash, 
	  { "Phash", "efs.ENCRYPTION_CERTIFICATE_HASH.pHash", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_ENCRYPTION_CERTIFICATE_HASH_cbTotalLength, 
	  { "Cbtotallength", "efs.ENCRYPTION_CERTIFICATE_HASH.cbTotalLength", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_efs_werror, 
	  { "Windows Error", "efs.werror", FT_UINT32, BASE_HEX, VALS(WERR_errors), 0, NULL, HFILL }},
	{ &hf_efs_EFS_HASH_BLOB_cbData, 
	  { "Cbdata", "efs.EFS_HASH_BLOB.cbData", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EfsRpcWriteFileRaw_pvContext, 
	  { "Pvcontext", "efs.EfsRpcWriteFileRaw.pvContext", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_ENCRYPTION_CERTIFICATE_HASH_LIST_pUsers, 
	  { "Pusers", "efs.ENCRYPTION_CERTIFICATE_HASH_LIST.pUsers", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_ENCRYPTION_CERTIFICATE_pUserSid, 
	  { "Pusersid", "efs.ENCRYPTION_CERTIFICATE.pUserSid", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EFS_CERTIFICATE_BLOB_dwCertEncodingType, 
	  { "Dwcertencodingtype", "efs.EFS_CERTIFICATE_BLOB.dwCertEncodingType", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EfsRpcDecryptFileSrv_Reserved, 
	  { "Reserved", "efs.EfsRpcDecryptFileSrv.Reserved", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_efs_EFS_CERTIFICATE_BLOB_cbData, 
	  { "Cbdata", "efs.EFS_CERTIFICATE_BLOB.cbData", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	};


	static gint *ett[] = {
		&ett_dcerpc_efs,
		&ett_efs_EFS_HASH_BLOB,
		&ett_efs_ENCRYPTION_CERTIFICATE_HASH,
		&ett_efs_ENCRYPTION_CERTIFICATE_HASH_LIST,
		&ett_efs_EFS_CERTIFICATE_BLOB,
		&ett_efs_ENCRYPTION_CERTIFICATE,
	};

	proto_dcerpc_efs = proto_register_protocol("EFS (pidl)", "EFS", "efs");
	proto_register_field_array(proto_dcerpc_efs, hf, array_length (hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_dcerpc_efs(void)
{
	dcerpc_init_uuid(proto_dcerpc_efs, ett_dcerpc_efs,
		&uuid_dcerpc_efs, ver_dcerpc_efs,
		efs_dissectors, hf_efs_opnum);
}
