/* packet-smb2.c
 * Routines for smb2 packet dissection
 *
 * See http://wiki.ethereal.com/SMB2  for documentation of
 * this protocol.
 * If you edit this file, keep the wiki updated as well.
 *
 * $Id: packet-smb2.c 16113 2005-10-04 10:23:40Z guy $
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

#define MIN(x,y) ((x)<(y)?(x):(y))

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/tap.h>
#include <epan/emem.h>

#include "packet-smb2.h"
#include "packet-dcerpc.h"
#include "packet-ntlmssp.h"
#include "packet-windows-common.h"
#include "packet-smb-common.h"
#include "packet-dcerpc-nt.h"



static int proto_smb2 = -1;
static int hf_smb2_cmd = -1;
static int hf_smb2_nt_status = -1;
static int hf_smb2_response_to = -1;
static int hf_smb2_response_in = -1;
static int hf_smb2_time = -1;
static int hf_smb2_header_len = -1;
static int hf_smb2_seqnum = -1;
static int hf_smb2_pid = -1;
static int hf_smb2_tid = -1;
static int hf_smb2_uid = -1;
static int hf_smb2_suid = -1;
static int hf_smb2_flags_response = -1;
static int hf_smb2_security_blob_len = -1;
static int hf_smb2_security_blob = -1;
static int hf_smb2_unknown = -1;
static int hf_smb2_unknown_timestamp = -1;
static int hf_smb2_create_timestamp = -1;
static int hf_smb2_last_access_timestamp = -1;
static int hf_smb2_last_write_timestamp = -1;
static int hf_smb2_last_change_timestamp = -1;
static int hf_smb2_filename_len = -1;
static int hf_smb2_filename = -1;
static int hf_smb2_fstype_len = -1;
static int hf_smb2_fstype = -1;
static int hf_smb2_tree_len = -1;
static int hf_smb2_tree = -1;
static int hf_smb2_search_len = -1;
static int hf_smb2_search = -1;
static int hf_smb2_find_response_size = -1;
static int hf_smb2_server_guid = -1;
static int hf_smb2_class = -1;
static int hf_smb2_infolevel = -1;
static int hf_smb2_max_response_size = -1;
static int hf_smb2_response_size = -1;
static int hf_smb2_file_info_12 = -1;
static int hf_smb2_file_info_22 = -1;
static int hf_smb2_file_info_0d = -1;
static int hf_smb2_fs_info_01 = -1;
static int hf_smb2_fs_info_05 = -1;
static int hf_smb2_fid = -1;
static int hf_smb2_write_length = -1;
static int hf_smb2_write_data = -1;
static int hf_smb2_disposition_delete_on_close = -1;

static gint ett_smb2 = -1;
static gint ett_smb2_header = -1;
static gint ett_smb2_command = -1;
static gint ett_smb2_secblob = -1;
static gint ett_smb2_file_info_12 = -1;
static gint ett_smb2_file_info_22 = -1;
static gint ett_smb2_file_info_0d = -1;
static gint ett_smb2_fs_info_01 = -1;
static gint ett_smb2_fs_info_05 = -1;

static dissector_handle_t gssapi_handle = NULL;

#define SMB2_CLASS_FILE_INFO	0x01
#define SMB2_CLASS_FS_INFO	0x02
static const value_string smb2_class_vals[] = {
	{ SMB2_CLASS_FILE_INFO,	"FILE_INFO"},
	{ SMB2_CLASS_FS_INFO,	"FS_INFO"},
	{ 0, NULL }
};

#define SMB2_FILE_INFO_22	0x22
#define SMB2_FILE_INFO_12	0x12
#define SMB2_FILE_INFO_0d	0x0d

#define SMB2_FS_INFO_01		0x01 
#define SMB2_FS_INFO_05		0x05 

/* unmatched smb_saved_info structures.
   For unmatched smb_saved_info structures we store the smb_saved_info
   structure using the SEQNUM field.
*/
static gint
smb2_saved_info_equal_unmatched(gconstpointer k1, gconstpointer k2)
{
	smb2_saved_info_t *key1 = (smb2_saved_info_t *)k1;
	smb2_saved_info_t *key2 = (smb2_saved_info_t *)k2;
	return key1->seqnum==key2->seqnum;
}
static guint
smb2_saved_info_hash_unmatched(gconstpointer k)
{
	smb2_saved_info_t *key = (smb2_saved_info_t *)k;
	guint32 hash;

	hash=key->seqnum&0xffffffff;
	return hash;
}

/* matched smb_saved_info structures.
   For matched smb_saved_info structures we store the smb_saved_info
   structure using the SEQNUM field.
*/
static gint
smb2_saved_info_equal_matched(gconstpointer k1, gconstpointer k2)
{
	smb2_saved_info_t *key1 = (smb2_saved_info_t *)k1;
	smb2_saved_info_t *key2 = (smb2_saved_info_t *)k2;
	return key1->seqnum==key2->seqnum;
}
static guint
smb2_saved_info_hash_matched(gconstpointer k)
{
	smb2_saved_info_t *key = (smb2_saved_info_t *)k;
	guint32 hash;

	hash=key->seqnum&0xffffffff;
	return hash;
}






typedef struct _smb2_function {
       int (*request)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_saved_info_t *ssi);
       int (*response)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_saved_info_t *ssi);
} smb2_function;

#define SMB2_FLAGS_RESPONSE	0x01

static const true_false_string tfs_flags_response = {
	"This is a RESPONSE",
	"This is a REQUEST"
};



/* fake the dce/rpc support structures so we can piggy back on
 * dissect_nt_policy_hnd()   since this will allow us
 * a cheap way to track where FIDs are opened, closed
 * and fid->filename mappings
 * if we want to do those things in the future.
 */
#define FID_MODE_OPEN		0
#define FID_MODE_CLOSE		1
#define FID_MODE_USE		2
static int
dissect_smb2_fid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_saved_info_t *ssi, int mode)
{
	guint8 drep[4] = { 0x10, 0x00, 0x00, 0x00}; /* fake DREP struct */
	dcerpc_info di;	/* fake dcerpc_info struct */
	void *old_private_data;
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item;
	char *fid_name;

	di.conformant_run=0;
	di.call_data=NULL;
	old_private_data=pinfo->private_data;
	pinfo->private_data=&di;

	switch(mode){
	case FID_MODE_OPEN:
		offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_smb2_fid, &policy_hnd, &hnd_item, TRUE, FALSE);
		if(!pinfo->fd->flags.visited && ssi){
			if(ssi->create_name){
				fid_name = se_strdup_printf("File:%s", ssi->create_name);
			} else {
				fid_name = se_strdup_printf("File: ");
			}
			dcerpc_smb_store_pol_name(&policy_hnd, pinfo,
						  fid_name);
		}
/*
		if (hnd_item && ssi)
			proto_item_append_text(hnd_item, "%s", ssi->create_name);
*/
		break;
	case FID_MODE_CLOSE:
		offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_smb2_fid, NULL, NULL, FALSE, TRUE);
		break;
	case FID_MODE_USE:
		offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep, hf_smb2_fid, NULL, NULL, FALSE, FALSE);
		break;
	}

	pinfo->private_data=old_private_data;

	return offset;
}


static int
dissect_smb2_file_info_12(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_saved_info_t *ssi _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_info_12, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_info_12);
	}

	/* create time */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

	/* last access */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

	/* last write */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

	/* last change */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, tvb_length_remaining(tvb, offset), FALSE);
	offset += tvb_length_remaining(tvb, offset);

	return offset;
}

static int
dissect_smb2_file_info_22(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_saved_info_t *ssi _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_info_22, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_info_22);
	}

	/* create time */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

	/* last access */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

	/* last write */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

	/* last change */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, FALSE);
	offset += 16;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 8, FALSE);
	offset += 8;

	return offset;
}

static const true_false_string tfs_disposition_delete_on_close = {
	"DELETE this file when closed",
	"Normal access, do not delete on close"
};

static int
dissect_smb2_file_info_0d(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_saved_info_t *ssi _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_info_0d, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_info_0d);
	}

	/* file disposition */
	proto_tree_add_item(tree, hf_smb2_disposition_delete_on_close, tvb, offset, 1, TRUE);

	return offset;
}

static int
dissect_smb2_fs_info_05(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_saved_info_t *ssi _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int name_len;
	const char *name;
	guint16 bc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_05, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_05);
	}

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 8, FALSE);
	offset += 8;

	/* fstype name length */
	name_len=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_fstype_len, tvb, offset, 2, TRUE);
	offset += 4;

	/* fstype name */
	bc=tvb_length_remaining(tvb, offset);
	name = get_unicode_or_ascii_string(tvb, &offset,
		TRUE, &name_len, TRUE, TRUE, &bc);
	if(name){
		proto_tree_add_string(tree, hf_smb2_fstype, tvb,
			offset, name_len, name);
	}
	offset += name_len;


	return offset;
}
static int
dissect_smb2_fs_info_01(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_saved_info_t *ssi _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_01, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_01);
	}

	/* unknown timestamp */
	dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_unknown_timestamp);
	offset += 8;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 10, FALSE);
	offset += 10;

	return offset;
}


static int
dissect_smb2_session_setup_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_saved_info_t *ssi _U_)
{
	proto_item *blob_item;
	proto_tree *blob_tree;
	tvbuff_t *blob_tvb;
	guint16 sbloblen;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 14, FALSE);
	offset += 14;

	/* length of security blob */
	sbloblen = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb2_security_blob_len, tvb, offset, 2, sbloblen);
	offset += 2;

	/* the security blob itself */
	blob_item = proto_tree_add_item(tree, hf_smb2_security_blob, tvb, offset, sbloblen, TRUE);
	blob_tree = proto_item_add_subtree(blob_item, ett_smb2_secblob);

	blob_tvb = tvb_new_subset(tvb, offset, sbloblen, sbloblen);
	call_dissector(gssapi_handle, blob_tvb, pinfo, blob_tree);
	offset += sbloblen;

	return offset;
}

static int
dissect_smb2_session_setup_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_saved_info_t *ssi _U_)
{
	proto_item *blob_item;
	proto_tree *blob_tree;
	tvbuff_t *blob_tvb;
	guint16 sbloblen;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 6, FALSE);
	offset += 6;

	/* length of security blob */
	sbloblen = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb2_security_blob_len, tvb, offset, 2, sbloblen);
	offset += 2;

	/* the security blob itself */
	blob_item = proto_tree_add_item(tree, hf_smb2_security_blob, tvb, offset, sbloblen, TRUE);
	blob_tree = proto_item_add_subtree(blob_item, ett_smb2_secblob);

	blob_tvb = tvb_new_subset(tvb, offset, sbloblen, sbloblen);
	call_dissector(gssapi_handle, blob_tvb, pinfo, blob_tree);
	offset += sbloblen;

	return offset;
}

static int
dissect_smb2_tree_connect_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_saved_info_t *ssi _U_)
{
	int tree_len;
	const char *name;
	guint16 bc;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 6, TRUE);
	offset += 6;

	/* tree name length */
	tree_len=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_tree_len, tvb, offset, 2, TRUE);
	offset += 2;

	/* tree name */
	bc=tvb_length_remaining(tvb, offset);
	name = get_unicode_or_ascii_string(tvb, &offset,
		TRUE, &tree_len, TRUE, TRUE, &bc);
	if(name){
		proto_tree_add_string(tree, hf_smb2_tree, tvb,
			offset, tree_len, name);
	}
	offset += tree_len;


	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, " Tree:%s",
			name);
	}


	return offset;
}


static int
dissect_smb2_find_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_saved_info_t *ssi _U_)
{
	int search_len;
	const char *name;
	guint16 bc;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, ssi, FID_MODE_USE);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	/* search name length */
	search_len=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_search_len, tvb, offset, 2, TRUE);
	offset += 2;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	/* search pattern */
	bc=tvb_length_remaining(tvb, offset);
	name = get_unicode_or_ascii_string(tvb, &offset,
		TRUE, &search_len, TRUE, TRUE, &bc);
	if(name){
		proto_tree_add_string(tree, hf_smb2_search, tvb,
			offset, search_len, name);
	}
	offset += search_len;


	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, " Pattern:%s",
			name);
	}


	return offset;
}

static int
dissect_smb2_find_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_saved_info_t *ssi _U_)
{
	guint32 len;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	/* length of response data */
	len=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_find_response_size, tvb, offset, 4, TRUE);
	offset += 4;

/*qqq*/
	return offset;
}

static int
dissect_smb2_negotiate_protocol_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_saved_info_t *ssi _U_)
{
	tvbuff_t *gssapi_tvb;
	guint16 sbloblen;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 8, TRUE);
	offset += 8;

	/* server GUID */
	proto_tree_add_item(tree, hf_smb2_server_guid, tvb, offset, 16, TRUE);
	offset += 16;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
	offset += 16;

	/* unknown timestamp */
	dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_unknown_timestamp);
	offset += 8;

	/* unknown timestamp */
	dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_unknown_timestamp);
	offset += 8;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	/* sec blob length */
	sbloblen = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb2_security_blob_len, tvb, offset, 2, sbloblen);
	offset += 2;
	
	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	/* security blob */
	gssapi_tvb = tvb_new_subset(tvb, offset, MIN(sbloblen,tvb_length_remaining(tvb, offset)), sbloblen);
	call_dissector(gssapi_handle, gssapi_tvb, pinfo, tree);


	offset += MIN(sbloblen,tvb_length_remaining(tvb, offset));
	return offset;
}

static int
dissect_smb2_getinfo_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_saved_info_t *ssi)
{
	guint8 class, infolevel;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	/* class */
	class=tvb_get_guint8(tvb, offset);
	if(ssi){
		ssi->class=class;
	}
	proto_tree_add_item(tree, hf_smb2_class, tvb, offset, 1, TRUE);
	offset += 1;

	/* infolevel */
	infolevel=tvb_get_guint8(tvb, offset);
	if(ssi){
		ssi->infolevel=infolevel;
	}
	proto_tree_add_item(tree, hf_smb2_infolevel, tvb, offset, 1, TRUE);
	offset += 1;

	/* max response size */
	proto_tree_add_item(tree, hf_smb2_max_response_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 12, TRUE);
	offset += 12;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, ssi, FID_MODE_USE);

	return offset;
}

static void
dissect_smb2_infolevel(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_saved_info_t *ssi, guint8 class, guint8 infolevel)
{

	switch(class){
	case SMB2_CLASS_FILE_INFO:
		switch(infolevel){
		case SMB2_FILE_INFO_0d:
			dissect_smb2_file_info_0d(tvb, pinfo, tree, offset, ssi);
			break;
		case SMB2_FILE_INFO_12:
			dissect_smb2_file_info_12(tvb, pinfo, tree, offset, ssi);
			break;
		case SMB2_FILE_INFO_22:
			dissect_smb2_file_info_22(tvb, pinfo, tree, offset, ssi);
			break;
		default:
			/* we dont handle this infolevel yet */
			proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, tvb_length_remaining(tvb, offset), TRUE);
			offset += tvb_length_remaining(tvb, offset);
		}
		break;
	case SMB2_CLASS_FS_INFO:
		switch(infolevel){
		case SMB2_FS_INFO_01:
			dissect_smb2_fs_info_01(tvb, pinfo, tree, offset, ssi);
			break;
		case SMB2_FS_INFO_05:
			dissect_smb2_fs_info_05(tvb, pinfo, tree, offset, ssi);
			break;
		default:
			/* we dont handle this infolevel yet */
			proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, tvb_length_remaining(tvb, offset), TRUE);
			offset += tvb_length_remaining(tvb, offset);
		}
		break;
	default:
		/* we dont handle this class yet */
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, tvb_length_remaining(tvb, offset), TRUE);
	}
}


static int
dissect_smb2_getinfo_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_saved_info_t *ssi)
{
	guint8 class=0;
	guint8 infolevel=0;
	guint32 response_size;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	/* class/infolevel */
	if(ssi){
		proto_item *item;

		class=ssi->class;
		item=proto_tree_add_uint(tree, hf_smb2_class, tvb, 0, 0, class);
		PROTO_ITEM_SET_GENERATED(item);

		infolevel=ssi->infolevel;
		item=proto_tree_add_uint(tree, hf_smb2_infolevel, tvb, 0, 0, infolevel);
		PROTO_ITEM_SET_GENERATED(item);
	}

	/* response size */
	response_size=tvb_get_letohl(tvb,offset);
	proto_tree_add_item(tree, hf_smb2_response_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* data */
	dissect_smb2_infolevel(tvb, pinfo, tree, offset, ssi, class, infolevel);
	offset += response_size;

	return offset;
}

static int
dissect_smb2_close_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_saved_info_t *ssi)
{
	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, ssi, FID_MODE_CLOSE);

	return offset;
}

static int
dissect_smb2_close_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_saved_info_t *ssi _U_)
{
	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 8, TRUE);
	offset += 8;

	/* create time */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

	/* last access */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

	/* last write */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

	/* last change */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 20, TRUE);
	offset += 20;

	return offset;
}



static int
dissect_smb2_write_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_saved_info_t *ssi)
{
	guint32 length;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	/* length  might even be 64bits if they are ambitious*/
	length=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_write_length, tvb, offset, 4, TRUE);
	offset += 4;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, ssi, FID_MODE_USE);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
	offset += 16;

	/* data */
	proto_tree_add_item(tree, hf_smb2_write_data, tvb, offset, length, TRUE);
	offset += MIN(length,(guint32)tvb_length_remaining(tvb, offset));

	return offset;
}


static int
dissect_smb2_write_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_saved_info_t *ssi _U_)
{
	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	/* length  might even be 64bits if they are ambitious*/
	proto_tree_add_item(tree, hf_smb2_write_length, tvb, offset, 4, TRUE);
	offset += 4;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 9, TRUE);
	offset += 9;

	return offset;
}


static int
dissect_smb2_create_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_saved_info_t *ssi)
{
	int length;
	const char *name="";
	guint16 bc;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
	offset += 16;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
	offset += 16;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 14, TRUE);
	offset += 14;

	/* file name length */
	length=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 2, TRUE);
	offset += 2;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 8, TRUE);
	offset += 8;

	/* file name */
	if(length){
		bc=tvb_length_remaining(tvb, offset);
		name = get_unicode_or_ascii_string(tvb, &offset,
			TRUE, &length, TRUE, TRUE, &bc);
		if(name){
			proto_tree_add_string(tree, hf_smb2_filename, tvb,
				offset, length, name);
		}

		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, " File:%s",
			name);
		}
	} else {
		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, " File:");
		}
	}
	offset += length;

	/* save the name if it looks sane */
	if(!pinfo->fd->flags.visited){
		if(ssi->create_name){
			g_free(ssi->create_name);
			ssi->create_name=NULL;
		}
		if(length && (length<256)){
			ssi->create_name=g_malloc(length+1);
			g_snprintf(ssi->create_name, length+1, "%s", name);
		}
	}

	/* strange,   maybe this buffer here is minimum 8 bytes? 
	 * we have to do this and the padding below to ensure the deterministic
	 * tail is exactly 24 bytes.
	 *
	 * assume the filename is stored in a buffer that is
	 * minimum 8 bytes and that is padded to 8 bytes.
	 * this has to be wrong,   but will do for now.
         */
	if(!length){
		offset += 8;
	}
	/* pad to 8 bytes */
	offset=(offset+7)&(~0x00000007);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 24, TRUE);
	offset += 24;

	return offset;
}

static int
dissect_smb2_create_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_saved_info_t *ssi)
{
	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 8, TRUE);
	offset += 8;

	/* create time */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

	/* last access */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

	/* last write */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

	/* last change */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 20, TRUE);
	offset += 20;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, ssi, FID_MODE_OPEN);

	/* free ssi->create_name   we dont need it any more */
	if(ssi->create_name){
		g_free(ssi->create_name);
		ssi->create_name=NULL;
	}

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 40, TRUE);
	offset += 40;

	return offset;
}


static int
dissect_smb2_setinfo_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_saved_info_t *ssi)
{
	guint8 class, infolevel;
	guint32 response_size;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	/* class */
	class=tvb_get_guint8(tvb, offset);
	if(ssi){
		ssi->class=class;
	}
	proto_tree_add_item(tree, hf_smb2_class, tvb, offset, 1, TRUE);
	offset += 1;

	/* infolevel */
	infolevel=tvb_get_guint8(tvb, offset);
	if(ssi){
		ssi->infolevel=infolevel;
	}
	proto_tree_add_item(tree, hf_smb2_infolevel, tvb, offset, 1, TRUE);
	offset += 1;

	/* response size */
	response_size=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_response_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, ssi, FID_MODE_USE);

	/* data */
	dissect_smb2_infolevel(tvb, pinfo, tree, offset, ssi, class, infolevel);
	offset += response_size;

	return offset;
}


/* names here are just until we find better names for these functions */
const value_string smb2_cmd_vals[] = {
  { 0x00, "NegotiateProtocol" },
  { 0x01, "SessionSetupAndX" },
  { 0x02, "unknown-0x02" },
  { 0x03, "TreeConnect" },
  { 0x04, "TreeDisconnect" },
  { 0x05, "Create" },
  { 0x06, "Close" },
  { 0x07, "unknown-0x07" },
  { 0x08, "Read" },
  { 0x09, "Write" },
  { 0x0A, "unknown-0x0A" },
  { 0x0B, "unknown-0x0B" },
  { 0x0C, "unknown-0x0C" },
  { 0x0D, "unknown-0x0D" },
  { 0x0E, "Find" },
  { 0x0F, "unknown-0x0F" },
  { 0x10, "GetInfo" },
  { 0x11, "SetInfo" },
  { 0x12, "unknown-0x12" },
  { 0x13, "unknown-0x13" },
  { 0x14, "unknown-0x14" },
  { 0x15, "unknown-0x15" },
  { 0x16, "unknown-0x16" },
  { 0x17, "unknown-0x17" },
  { 0x18, "unknown-0x18" },
  { 0x19, "unknown-0x19" },
  { 0x1A, "unknown-0x1A" },
  { 0x1B, "unknown-0x1B" },
  { 0x1C, "unknown-0x1C" },
  { 0x1D, "unknown-0x1D" },
  { 0x1E, "unknown-0x1E" },
  { 0x1F, "unknown-0x1F" },
  { 0x20, "unknown-0x20" },
  { 0x21, "unknown-0x21" },
  { 0x22, "unknown-0x22" },
  { 0x23, "unknown-0x23" },
  { 0x24, "unknown-0x24" },
  { 0x25, "unknown-0x25" },
  { 0x26, "unknown-0x26" },
  { 0x27, "unknown-0x27" },
  { 0x28, "unknown-0x28" },
  { 0x29, "unknown-0x29" },
  { 0x2A, "unknown-0x2A" },
  { 0x2B, "unknown-0x2B" },
  { 0x2C, "unknown-0x2C" },
  { 0x2D, "unknown-0x2D" },
  { 0x2E, "unknown-0x2E" },
  { 0x2F, "unknown-0x2F" },
  { 0x30, "unknown-0x30" },
  { 0x31, "unknown-0x31" },
  { 0x32, "unknown-0x32" },
  { 0x33, "unknown-0x33" },
  { 0x34, "unknown-0x34" },
  { 0x35, "unknown-0x35" },
  { 0x36, "unknown-0x36" },
  { 0x37, "unknown-0x37" },
  { 0x38, "unknown-0x38" },
  { 0x39, "unknown-0x39" },
  { 0x3A, "unknown-0x3A" },
  { 0x3B, "unknown-0x3B" },
  { 0x3C, "unknown-0x3C" },
  { 0x3D, "unknown-0x3D" },
  { 0x3E, "unknown-0x3E" },
  { 0x3F, "unknown-0x3F" },
  { 0x40, "unknown-0x40" },
  { 0x41, "unknown-0x41" },
  { 0x42, "unknown-0x42" },
  { 0x43, "unknown-0x43" },
  { 0x44, "unknown-0x44" },
  { 0x45, "unknown-0x45" },
  { 0x46, "unknown-0x46" },
  { 0x47, "unknown-0x47" },
  { 0x48, "unknown-0x48" },
  { 0x49, "unknown-0x49" },
  { 0x4A, "unknown-0x4A" },
  { 0x4B, "unknown-0x4B" },
  { 0x4C, "unknown-0x4C" },
  { 0x4D, "unknown-0x4D" },
  { 0x4E, "unknown-0x4E" },
  { 0x4F, "unknown-0x4F" },
  { 0x50, "unknown-0x50" },
  { 0x51, "unknown-0x51" },
  { 0x52, "unknown-0x52" },
  { 0x53, "unknown-0x53" },
  { 0x54, "unknown-0x54" },
  { 0x55, "unknown-0x55" },
  { 0x56, "unknown-0x56" },
  { 0x57, "unknown-0x57" },
  { 0x58, "unknown-0x58" },
  { 0x59, "unknown-0x59" },
  { 0x5A, "unknown-0x5A" },
  { 0x5B, "unknown-0x5B" },
  { 0x5C, "unknown-0x5C" },
  { 0x5D, "unknown-0x5D" },
  { 0x5E, "unknown-0x5E" },
  { 0x5F, "unknown-0x5F" },
  { 0x60, "unknown-0x60" },
  { 0x61, "unknown-0x61" },
  { 0x62, "unknown-0x62" },
  { 0x63, "unknown-0x63" },
  { 0x64, "unknown-0x64" },
  { 0x65, "unknown-0x65" },
  { 0x66, "unknown-0x66" },
  { 0x67, "unknown-0x67" },
  { 0x68, "unknown-0x68" },
  { 0x69, "unknown-0x69" },
  { 0x6A, "unknown-0x6A" },
  { 0x6B, "unknown-0x6B" },
  { 0x6C, "unknown-0x6C" },
  { 0x6D, "unknown-0x6D" },
  { 0x6E, "unknown-0x6E" },
  { 0x6F, "unknown-0x6F" },
  { 0x70, "unknown-0x70" },
  { 0x71, "unknown-0x71" },
  { 0x72, "unknown-0x72" },
  { 0x73, "unknown-0x73" },
  { 0x74, "unknown-0x74" },
  { 0x75, "unknown-0x75" },
  { 0x76, "unknown-0x76" },
  { 0x77, "unknown-0x77" },
  { 0x78, "unknown-0x78" },
  { 0x79, "unknown-0x79" },
  { 0x7A, "unknown-0x7A" },
  { 0x7B, "unknown-0x7B" },
  { 0x7C, "unknown-0x7C" },
  { 0x7D, "unknown-0x7D" },
  { 0x7E, "unknown-0x7E" },
  { 0x7F, "unknown-0x7F" },
  { 0x80, "unknown-0x80" },
  { 0x81, "unknown-0x81" },
  { 0x82, "unknown-0x82" },
  { 0x83, "unknown-0x83" },
  { 0x84, "unknown-0x84" },
  { 0x85, "unknown-0x85" },
  { 0x86, "unknown-0x86" },
  { 0x87, "unknown-0x87" },
  { 0x88, "unknown-0x88" },
  { 0x89, "unknown-0x89" },
  { 0x8A, "unknown-0x8A" },
  { 0x8B, "unknown-0x8B" },
  { 0x8C, "unknown-0x8C" },
  { 0x8D, "unknown-0x8D" },
  { 0x8E, "unknown-0x8E" },
  { 0x8F, "unknown-0x8F" },
  { 0x90, "unknown-0x90" },
  { 0x91, "unknown-0x91" },
  { 0x92, "unknown-0x92" },
  { 0x93, "unknown-0x93" },
  { 0x94, "unknown-0x94" },
  { 0x95, "unknown-0x95" },
  { 0x96, "unknown-0x96" },
  { 0x97, "unknown-0x97" },
  { 0x98, "unknown-0x98" },
  { 0x99, "unknown-0x99" },
  { 0x9A, "unknown-0x9A" },
  { 0x9B, "unknown-0x9B" },
  { 0x9C, "unknown-0x9C" },
  { 0x9D, "unknown-0x9D" },
  { 0x9E, "unknown-0x9E" },
  { 0x9F, "unknown-0x9F" },
  { 0xA0, "unknown-0xA0" },
  { 0xA1, "unknown-0xA1" },
  { 0xA2, "unknown-0xA2" },
  { 0xA3, "unknown-0xA3" },
  { 0xA4, "unknown-0xA4" },
  { 0xA5, "unknown-0xA5" },
  { 0xA6, "unknown-0xA6" },
  { 0xA7, "unknown-0xA7" },
  { 0xA8, "unknown-0xA8" },
  { 0xA9, "unknown-0xA9" },
  { 0xAA, "unknown-0xAA" },
  { 0xAB, "unknown-0xAB" },
  { 0xAC, "unknown-0xAC" },
  { 0xAD, "unknown-0xAD" },
  { 0xAE, "unknown-0xAE" },
  { 0xAF, "unknown-0xAF" },
  { 0xB0, "unknown-0xB0" },
  { 0xB1, "unknown-0xB1" },
  { 0xB2, "unknown-0xB2" },
  { 0xB3, "unknown-0xB3" },
  { 0xB4, "unknown-0xB4" },
  { 0xB5, "unknown-0xB5" },
  { 0xB6, "unknown-0xB6" },
  { 0xB7, "unknown-0xB7" },
  { 0xB8, "unknown-0xB8" },
  { 0xB9, "unknown-0xB9" },
  { 0xBA, "unknown-0xBA" },
  { 0xBB, "unknown-0xBB" },
  { 0xBC, "unknown-0xBC" },
  { 0xBD, "unknown-0xBD" },
  { 0xBE, "unknown-0xBE" },
  { 0xBF, "unknown-0xBF" },
  { 0xC0, "unknown-0xC0" },
  { 0xC1, "unknown-0xC1" },
  { 0xC2, "unknown-0xC2" },
  { 0xC3, "unknown-0xC3" },
  { 0xC4, "unknown-0xC4" },
  { 0xC5, "unknown-0xC5" },
  { 0xC6, "unknown-0xC6" },
  { 0xC7, "unknown-0xC7" },
  { 0xC8, "unknown-0xC8" },
  { 0xC9, "unknown-0xC9" },
  { 0xCA, "unknown-0xCA" },
  { 0xCB, "unknown-0xCB" },
  { 0xCC, "unknown-0xCC" },
  { 0xCD, "unknown-0xCD" },
  { 0xCE, "unknown-0xCE" },
  { 0xCF, "unknown-0xCF" },
  { 0xD0, "unknown-0xD0" },
  { 0xD1, "unknown-0xD1" },
  { 0xD2, "unknown-0xD2" },
  { 0xD3, "unknown-0xD3" },
  { 0xD4, "unknown-0xD4" },
  { 0xD5, "unknown-0xD5" },
  { 0xD6, "unknown-0xD6" },
  { 0xD7, "unknown-0xD7" },
  { 0xD8, "unknown-0xD8" },
  { 0xD9, "unknown-0xD9" },
  { 0xDA, "unknown-0xDA" },
  { 0xDB, "unknown-0xDB" },
  { 0xDC, "unknown-0xDC" },
  { 0xDD, "unknown-0xDD" },
  { 0xDE, "unknown-0xDE" },
  { 0xDF, "unknown-0xDF" },
  { 0xE0, "unknown-0xE0" },
  { 0xE1, "unknown-0xE1" },
  { 0xE2, "unknown-0xE2" },
  { 0xE3, "unknown-0xE3" },
  { 0xE4, "unknown-0xE4" },
  { 0xE5, "unknown-0xE5" },
  { 0xE6, "unknown-0xE6" },
  { 0xE7, "unknown-0xE7" },
  { 0xE8, "unknown-0xE8" },
  { 0xE9, "unknown-0xE9" },
  { 0xEA, "unknown-0xEA" },
  { 0xEB, "unknown-0xEB" },
  { 0xEC, "unknown-0xEC" },
  { 0xED, "unknown-0xED" },
  { 0xEE, "unknown-0xEE" },
  { 0xEF, "unknown-0xEF" },
  { 0xF0, "unknown-0xF0" },
  { 0xF1, "unknown-0xF1" },
  { 0xF2, "unknown-0xF2" },
  { 0xF3, "unknown-0xF3" },
  { 0xF4, "unknown-0xF4" },
  { 0xF5, "unknown-0xF5" },
  { 0xF6, "unknown-0xF6" },
  { 0xF7, "unknown-0xF7" },
  { 0xF8, "unknown-0xF8" },
  { 0xF9, "unknown-0xF9" },
  { 0xFA, "unknown-0xFA" },
  { 0xFB, "unknown-0xFB" },
  { 0xFC, "unknown-0xFC" },
  { 0xFD, "unknown-0xFD" },
  { 0xFE, "unknown-0xFE" },
  { 0xFF, "unknown-0xFF" },
  { 0x00, NULL },
};
static const char *decode_smb2_name(guint8 cmd)
{
  return(smb2_cmd_vals[cmd].strptr);
}

static smb2_function smb2_dissector[256] = {
  /* 0x00 NegotiateProtocol*/  
	{NULL,
	 dissect_smb2_negotiate_protocol_response},
  /* 0x01 SessionSetup*/  
	{dissect_smb2_session_setup_request, 
	 dissect_smb2_session_setup_response},
  /* 0x02 */  {NULL, NULL},
  /* 0x03 TreeConnect*/  
	{dissect_smb2_tree_connect_request,
	 NULL},
  /* 0x04 */  {NULL, NULL},
  /* 0x05 Create*/  
	{dissect_smb2_create_request,
	 dissect_smb2_create_response},
  /* 0x06 Close*/  
	{dissect_smb2_close_request,
	 dissect_smb2_close_response},
  /* 0x07 */  {NULL, NULL},
  /* 0x08 */  {NULL, NULL},
  /* 0x09 Writew*/  
	{dissect_smb2_write_request,
	 dissect_smb2_write_response},
  /* 0x0a */  {NULL, NULL},
  /* 0x0b */  {NULL, NULL},
  /* 0x0c */  {NULL, NULL},
  /* 0x0d */  {NULL, NULL},
  /* 0x0e Find*/  
	{dissect_smb2_find_request,
	 dissect_smb2_find_response},
  /* 0x0f */  {NULL, NULL},
  /* 0x10 GetInfo*/  
	{dissect_smb2_getinfo_request,
	 dissect_smb2_getinfo_response},
  /* 0x11 SetInfo*/  
	{dissect_smb2_setinfo_request,
	 NULL},
  /* 0x12 */  {NULL, NULL},
  /* 0x13 */  {NULL, NULL},
  /* 0x14 */  {NULL, NULL},
  /* 0x15 */  {NULL, NULL},
  /* 0x16 */  {NULL, NULL},
  /* 0x17 */  {NULL, NULL},
  /* 0x18 */  {NULL, NULL},
  /* 0x19 */  {NULL, NULL},
  /* 0x1a */  {NULL, NULL},
  /* 0x1b */  {NULL, NULL},
  /* 0x1c */  {NULL, NULL},
  /* 0x1d */  {NULL, NULL},
  /* 0x1e */  {NULL, NULL},
  /* 0x1f */  {NULL, NULL},
  /* 0x20 */  {NULL, NULL},
  /* 0x21 */  {NULL, NULL},
  /* 0x22 */  {NULL, NULL},
  /* 0x23 */  {NULL, NULL},
  /* 0x24 */  {NULL, NULL},
  /* 0x25 */  {NULL, NULL},
  /* 0x26 */  {NULL, NULL},
  /* 0x27 */  {NULL, NULL},
  /* 0x28 */  {NULL, NULL},
  /* 0x29 */  {NULL, NULL},
  /* 0x2a */  {NULL, NULL},
  /* 0x2b */  {NULL, NULL},
  /* 0x2c */  {NULL, NULL},
  /* 0x2d */  {NULL, NULL},
  /* 0x2e */  {NULL, NULL},
  /* 0x2f */  {NULL, NULL},
  /* 0x30 */  {NULL, NULL},
  /* 0x31 */  {NULL, NULL},
  /* 0x32 */  {NULL, NULL},
  /* 0x33 */  {NULL, NULL},
  /* 0x34 */  {NULL, NULL},
  /* 0x35 */  {NULL, NULL},
  /* 0x36 */  {NULL, NULL},
  /* 0x37 */  {NULL, NULL},
  /* 0x38 */  {NULL, NULL},
  /* 0x39 */  {NULL, NULL},
  /* 0x3a */  {NULL, NULL},
  /* 0x3b */  {NULL, NULL},
  /* 0x3c */  {NULL, NULL},
  /* 0x3d */  {NULL, NULL},
  /* 0x3e */  {NULL, NULL},
  /* 0x3f */  {NULL, NULL},
  /* 0x40 */  {NULL, NULL},
  /* 0x41 */  {NULL, NULL},
  /* 0x42 */  {NULL, NULL},
  /* 0x43 */  {NULL, NULL},
  /* 0x44 */  {NULL, NULL},
  /* 0x45 */  {NULL, NULL},
  /* 0x46 */  {NULL, NULL},
  /* 0x47 */  {NULL, NULL},
  /* 0x48 */  {NULL, NULL},
  /* 0x49 */  {NULL, NULL},
  /* 0x4a */  {NULL, NULL},
  /* 0x4b */  {NULL, NULL},
  /* 0x4c */  {NULL, NULL},
  /* 0x4d */  {NULL, NULL},
  /* 0x4e */  {NULL, NULL},
  /* 0x4f */  {NULL, NULL},
  /* 0x50 */  {NULL, NULL},
  /* 0x51 */  {NULL, NULL},
  /* 0x52 */  {NULL, NULL},
  /* 0x53 */  {NULL, NULL},
  /* 0x54 */  {NULL, NULL},
  /* 0x55 */  {NULL, NULL},
  /* 0x56 */  {NULL, NULL},
  /* 0x57 */  {NULL, NULL},
  /* 0x58 */  {NULL, NULL},
  /* 0x59 */  {NULL, NULL},
  /* 0x5a */  {NULL, NULL},
  /* 0x5b */  {NULL, NULL},
  /* 0x5c */  {NULL, NULL},
  /* 0x5d */  {NULL, NULL},
  /* 0x5e */  {NULL, NULL},
  /* 0x5f */  {NULL, NULL},
  /* 0x60 */  {NULL, NULL},
  /* 0x61 */  {NULL, NULL},
  /* 0x62 */  {NULL, NULL},
  /* 0x63 */  {NULL, NULL},
  /* 0x64 */  {NULL, NULL},
  /* 0x65 */  {NULL, NULL},
  /* 0x66 */  {NULL, NULL},
  /* 0x67 */  {NULL, NULL},
  /* 0x68 */  {NULL, NULL},
  /* 0x69 */  {NULL, NULL},
  /* 0x6a */  {NULL, NULL},
  /* 0x6b */  {NULL, NULL},
  /* 0x6c */  {NULL, NULL},
  /* 0x6d */  {NULL, NULL},
  /* 0x6e */  {NULL, NULL},
  /* 0x6f */  {NULL, NULL},
  /* 0x70 */  {NULL, NULL},
  /* 0x71 */  {NULL, NULL},
  /* 0x72 */  {NULL, NULL},
  /* 0x73 */  {NULL, NULL},
  /* 0x74 */  {NULL, NULL},
  /* 0x75 */  {NULL, NULL},
  /* 0x76 */  {NULL, NULL},
  /* 0x77 */  {NULL, NULL},
  /* 0x78 */  {NULL, NULL},
  /* 0x79 */  {NULL, NULL},
  /* 0x7a */  {NULL, NULL},
  /* 0x7b */  {NULL, NULL},
  /* 0x7c */  {NULL, NULL},
  /* 0x7d */  {NULL, NULL},
  /* 0x7e */  {NULL, NULL},
  /* 0x7f */  {NULL, NULL},
  /* 0x80 */  {NULL, NULL},
  /* 0x81 */  {NULL, NULL},
  /* 0x82 */  {NULL, NULL},
  /* 0x83 */  {NULL, NULL},
  /* 0x84 */  {NULL, NULL},
  /* 0x85 */  {NULL, NULL},
  /* 0x86 */  {NULL, NULL},
  /* 0x87 */  {NULL, NULL},
  /* 0x88 */  {NULL, NULL},
  /* 0x89 */  {NULL, NULL},
  /* 0x8a */  {NULL, NULL},
  /* 0x8b */  {NULL, NULL},
  /* 0x8c */  {NULL, NULL},
  /* 0x8d */  {NULL, NULL},
  /* 0x8e */  {NULL, NULL},
  /* 0x8f */  {NULL, NULL},
  /* 0x90 */  {NULL, NULL},
  /* 0x91 */  {NULL, NULL},
  /* 0x92 */  {NULL, NULL},
  /* 0x93 */  {NULL, NULL},
  /* 0x94 */  {NULL, NULL},
  /* 0x95 */  {NULL, NULL},
  /* 0x96 */  {NULL, NULL},
  /* 0x97 */  {NULL, NULL},
  /* 0x98 */  {NULL, NULL},
  /* 0x99 */  {NULL, NULL},
  /* 0x9a */  {NULL, NULL},
  /* 0x9b */  {NULL, NULL},
  /* 0x9c */  {NULL, NULL},
  /* 0x9d */  {NULL, NULL},
  /* 0x9e */  {NULL, NULL},
  /* 0x9f */  {NULL, NULL},
  /* 0xa0 */  {NULL, NULL},
  /* 0xa1 */  {NULL, NULL},
  /* 0xa2 */  {NULL, NULL},
  /* 0xa3 */  {NULL, NULL},
  /* 0xa4 */  {NULL, NULL},
  /* 0xa5 */  {NULL, NULL},
  /* 0xa6 */  {NULL, NULL},
  /* 0xa7 */  {NULL, NULL},
  /* 0xa8 */  {NULL, NULL},
  /* 0xa9 */  {NULL, NULL},
  /* 0xaa */  {NULL, NULL},
  /* 0xab */  {NULL, NULL},
  /* 0xac */  {NULL, NULL},
  /* 0xad */  {NULL, NULL},
  /* 0xae */  {NULL, NULL},
  /* 0xaf */  {NULL, NULL},
  /* 0xb0 */  {NULL, NULL},
  /* 0xb1 */  {NULL, NULL},
  /* 0xb2 */  {NULL, NULL},
  /* 0xb3 */  {NULL, NULL},
  /* 0xb4 */  {NULL, NULL},
  /* 0xb5 */  {NULL, NULL},
  /* 0xb6 */  {NULL, NULL},
  /* 0xb7 */  {NULL, NULL},
  /* 0xb8 */  {NULL, NULL},
  /* 0xb9 */  {NULL, NULL},
  /* 0xba */  {NULL, NULL},
  /* 0xbb */  {NULL, NULL},
  /* 0xbc */  {NULL, NULL},
  /* 0xbd */  {NULL, NULL},
  /* 0xbe */  {NULL, NULL},
  /* 0xbf */  {NULL, NULL},
  /* 0xc0 */  {NULL, NULL},
  /* 0xc1 */  {NULL, NULL},
  /* 0xc2 */  {NULL, NULL},
  /* 0xc3 */  {NULL, NULL},
  /* 0xc4 */  {NULL, NULL},
  /* 0xc5 */  {NULL, NULL},
  /* 0xc6 */  {NULL, NULL},
  /* 0xc7 */  {NULL, NULL},
  /* 0xc8 */  {NULL, NULL},
  /* 0xc9 */  {NULL, NULL},
  /* 0xca */  {NULL, NULL},
  /* 0xcb */  {NULL, NULL},
  /* 0xcc */  {NULL, NULL},
  /* 0xcd */  {NULL, NULL},
  /* 0xce */  {NULL, NULL},
  /* 0xcf */  {NULL, NULL},
  /* 0xd0 */  {NULL, NULL},
  /* 0xd1 */  {NULL, NULL},
  /* 0xd2 */  {NULL, NULL},
  /* 0xd3 */  {NULL, NULL},
  /* 0xd4 */  {NULL, NULL},
  /* 0xd5 */  {NULL, NULL},
  /* 0xd6 */  {NULL, NULL},
  /* 0xd7 */  {NULL, NULL},
  /* 0xd8 */  {NULL, NULL},
  /* 0xd9 */  {NULL, NULL},
  /* 0xda */  {NULL, NULL},
  /* 0xdb */  {NULL, NULL},
  /* 0xdc */  {NULL, NULL},
  /* 0xdd */  {NULL, NULL},
  /* 0xde */  {NULL, NULL},
  /* 0xdf */  {NULL, NULL},
  /* 0xe0 */  {NULL, NULL},
  /* 0xe1 */  {NULL, NULL},
  /* 0xe2 */  {NULL, NULL},
  /* 0xe3 */  {NULL, NULL},
  /* 0xe4 */  {NULL, NULL},
  /* 0xe5 */  {NULL, NULL},
  /* 0xe6 */  {NULL, NULL},
  /* 0xe7 */  {NULL, NULL},
  /* 0xe8 */  {NULL, NULL},
  /* 0xe9 */  {NULL, NULL},
  /* 0xea */  {NULL, NULL},
  /* 0xeb */  {NULL, NULL},
  /* 0xec */  {NULL, NULL},
  /* 0xed */  {NULL, NULL},
  /* 0xee */  {NULL, NULL},
  /* 0xef */  {NULL, NULL},
  /* 0xf0 */  {NULL, NULL},
  /* 0xf1 */  {NULL, NULL},
  /* 0xf2 */  {NULL, NULL},
  /* 0xf3 */  {NULL, NULL},
  /* 0xf4 */  {NULL, NULL},
  /* 0xf5 */  {NULL, NULL},
  /* 0xf6 */  {NULL, NULL},
  /* 0xf7 */  {NULL, NULL},
  /* 0xf8 */  {NULL, NULL},
  /* 0xf9 */  {NULL, NULL},
  /* 0xfa */  {NULL, NULL},
  /* 0xfb */  {NULL, NULL},
  /* 0xfc */  {NULL, NULL},
  /* 0xfd */  {NULL, NULL},
  /* 0xfe */  {NULL, NULL},
  /* 0xff */  {NULL, NULL},
};


static int
dissect_smb2_command(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, guint8 cmd, guint8 response, smb2_saved_info_t *ssi)
{
	int (*cmd_dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_saved_info_t *ssi);
	proto_item *cmd_item;
	proto_tree *cmd_tree;


	cmd_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s %s (0x%02x)",
			decode_smb2_name(cmd),
			response?"Response":"Request",
			cmd);
	cmd_tree = proto_item_add_subtree(cmd_item, ett_smb2_command);


	cmd_dissector=response?
		smb2_dissector[cmd&0xff].response:
		smb2_dissector[cmd&0xff].request;
	if(cmd_dissector){
		offset=(*cmd_dissector)(tvb, pinfo, cmd_tree, offset, ssi);
	} else {
		proto_tree_add_item(cmd_tree, hf_smb2_unknown, tvb, offset, -1, FALSE);
		offset=tvb_length(tvb);
	}

	return offset;
}

static void
dissect_smb2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	proto_item *header_item=NULL;
	proto_tree *header_tree=NULL;
	int offset=0;
	int old_offset;
	guint8 cmd, response;
	guint16 header_len;
	guint32 nt_status;
	conversation_t *conversation;
	smb2_info_t *si;
	smb2_saved_info_t *ssi, ssi_key;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMB2");
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, proto_smb2, tvb, offset,
			-1, FALSE);
		tree = proto_item_add_subtree(item, ett_smb2);
	}

	if (tree) {
		header_item = proto_tree_add_text(tree, tvb, offset, -1, "SMB2 Header");
		header_tree = proto_item_add_subtree(header_item, ett_smb2_header);
	}
	old_offset=offset;

	/* Decode the header */
	/* SMB2 marker */
	proto_tree_add_text(header_tree, tvb, offset, 4, "Server Component: SMB2");
	offset += 4;

	/* header length */
	header_len=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(header_tree, hf_smb2_header_len, tvb, offset, 2, TRUE);
	offset += 2;

	/* padding */
	offset += 2;

	/* Status Code */
	nt_status=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(header_tree, hf_smb2_nt_status, tvb, offset, 4, TRUE);
	offset += 4;


	/* CMD either 1 or two bytes*/
	cmd=tvb_get_guint8(tvb, offset);
	proto_tree_add_item(header_tree, hf_smb2_cmd, tvb, offset, 2, TRUE);
	offset += 2;

	/* some unknown bytes */
	proto_tree_add_item(header_tree, hf_smb2_unknown, tvb, offset, 2, FALSE);
	offset += 2;

	/* flags */
	response=tvb_get_guint8(tvb, offset)&SMB2_FLAGS_RESPONSE;
	proto_tree_add_item(header_tree, hf_smb2_flags_response, tvb, offset, 1, FALSE);
	offset += 1;

	/* some unknown bytes */
	proto_tree_add_item(header_tree, hf_smb2_unknown, tvb, offset, 7, FALSE);
	offset += 7;

	/* command sequence number*/
	ssi_key.seqnum=tvb_get_letoh64(tvb, offset);
	proto_tree_add_item(header_tree, hf_smb2_seqnum, tvb, offset, 8, TRUE);
	offset += 8;

	/* Process ID */
	proto_tree_add_item(header_tree, hf_smb2_pid, tvb, offset, 4, TRUE);
	offset += 4;

	/* Tree ID */
	proto_tree_add_item(header_tree, hf_smb2_tid, tvb, offset, 4, TRUE);
	offset += 4;

	/* User ID */
	proto_tree_add_item(header_tree, hf_smb2_uid, tvb, offset, 4, TRUE);
	offset += 4;

	/* Secondary User ID */
	proto_tree_add_item(header_tree, hf_smb2_suid, tvb, offset, 4, TRUE);
	offset += 4;

	/* some unknown bytes */
	proto_tree_add_item(header_tree, hf_smb2_unknown, tvb, offset, 4, FALSE);
	offset += 4;

	/* some unknown bytes */
	proto_tree_add_item(header_tree, hf_smb2_unknown, tvb, offset, 12, FALSE);
	offset += 12;

	proto_item_set_len(header_item, offset-old_offset);



	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s",
			decode_smb2_name(cmd),
			response?"Response":"Request");
		if(nt_status){
			col_append_fstr(
				pinfo->cinfo, COL_INFO, ", Error: %s",
				val_to_str(nt_status, NT_errors,
				"Unknown (0x%08X)"));
		}
	}


	/* find which conversation we are part of and get the tables for that
	 * conversation
	 */
	conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,  pinfo->srcport, pinfo->destport, 0);
	if(!conversation){
		/* OK this is a new conversation so lets create it */
		conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
			pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	}
	si=conversation_get_proto_data(conversation, proto_smb2);
	if(!si){
		/* no smb2_into_t structure for this conversation yet,
		 * create it.
		 */
		si=se_alloc(sizeof(smb2_info_t));
		/* qqq this leaks memory for now since we never free
		   the hashtables */
		si->matched= g_hash_table_new(smb2_saved_info_hash_matched,
			smb2_saved_info_equal_matched);
		si->unmatched= g_hash_table_new(smb2_saved_info_hash_unmatched,
			smb2_saved_info_equal_unmatched);

		conversation_add_proto_data(conversation, proto_smb2, si);
	}
	if(!pinfo->fd->flags.visited){
		/* see if we can find this seqnum in the unmatched table */
		ssi=g_hash_table_lookup(si->unmatched, &ssi_key);

		if(!response){
			/* This is a request */
			if(ssi){
				/* this is a request and we already found 
				 * an older ssi so just delete the previous 
				 * one 
				 */
				g_hash_table_remove(si->unmatched, ssi);
				ssi=NULL;
			}

			if(!ssi){
				/* no we couldnt find it, so just add it then
				 * if was a request we are decoding 
				 */
				ssi=se_alloc(sizeof(smb2_saved_info_t));
				ssi->class=0;
				ssi->infolevel=0;
				ssi->seqnum=ssi_key.seqnum;
				ssi->create_name=NULL;
				ssi->frame_req=pinfo->fd->num;
				ssi->frame_res=0;
				ssi->req_time=pinfo->fd->abs_ts;
				g_hash_table_insert(si->unmatched, ssi, ssi);
			}
		} else {
			/* This is a response */
			if(ssi){
				/* just  set the response frame and move it to the matched table */
				ssi->frame_res=pinfo->fd->num;
				g_hash_table_remove(si->unmatched, ssi);
				g_hash_table_insert(si->matched, ssi, ssi);
			}
		}
	} else {
		/* see if we can find this seqnum in the matched table */
		ssi=g_hash_table_lookup(si->matched, &ssi_key);
	}

	if(ssi){
		if(!response){
			if(ssi->frame_res){
				proto_item *tmp_item;
				tmp_item=proto_tree_add_uint(header_tree, hf_smb2_response_in, tvb, 0, 0, ssi->frame_res);
				PROTO_ITEM_SET_GENERATED(tmp_item);
			}
		} else {
			if(ssi->frame_req){
				proto_item *tmp_item;
				nstime_t t, deltat;

				tmp_item=proto_tree_add_uint(header_tree, hf_smb2_response_to, tvb, 0, 0, ssi->frame_req);
				PROTO_ITEM_SET_GENERATED(tmp_item);
				t = pinfo->fd->abs_ts;
				nstime_delta(&deltat, &t, &ssi->req_time);
				tmp_item=proto_tree_add_time(header_tree, hf_smb2_time, tvb,
				    0, 0, &deltat);
				PROTO_ITEM_SET_GENERATED(tmp_item);
			}
		}
	}
	/* if we dont have ssi yet we must fake it */
	/*qqq*/

	/* Decode the payload */
	dissect_smb2_command(pinfo, tree, tvb, offset, cmd, response, ssi);
}

static gboolean
dissect_smb2_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	/* must check that this really is a smb2 packet */
	if (!tvb_bytes_exist(tvb, 0, 4))
		return FALSE;

	if( (tvb_get_guint8(tvb, 0) != 0xfe)
	    || (tvb_get_guint8(tvb, 1) != 'S')
	    || (tvb_get_guint8(tvb, 2) != 'M')
	    || (tvb_get_guint8(tvb, 3) != 'B') ){
		return FALSE;
	}

	dissect_smb2(tvb, pinfo, parent_tree);
	return TRUE;
}

void
proto_register_smb2(void)
{
	static hf_register_info hf[] = {
	{ &hf_smb2_cmd,
		{ "Command", "smb2.cmd", FT_UINT16, BASE_DEC,
		VALS(smb2_cmd_vals), 0, "SMB2 Command Opcode", HFILL }},
	{ &hf_smb2_response_to,
		{ "Response to", "smb2.response_to", FT_FRAMENUM, BASE_NONE,
		NULL, 0, "This packet is a response to the packet in this frame", HFILL }},
	{ &hf_smb2_response_in,
		{ "Response in", "smb2.response_in", FT_FRAMENUM, BASE_NONE,
		NULL, 0, "The response to this packet is in this packet", HFILL }},
	{ &hf_smb2_time,
		{ "Time from request", "smb2.time", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0, "Time between Request and Response for SMB2 cmds", HFILL }},
	{ &hf_smb2_header_len,
		{ "Header Length", "smb2.header_len", FT_UINT16, BASE_DEC,
		NULL, 0, "SMB2 Size of Header", HFILL }},
	{ &hf_smb2_nt_status,
		{ "NT Status", "smb2.nt_status", FT_UINT32, BASE_HEX,
		VALS(NT_errors), 0, "NT Status code", HFILL }},
	{ &hf_smb2_seqnum,
		{ "Command Sequence Number", "smb2.seq_num", FT_UINT64, BASE_DEC,
		NULL, 0, "SMB2 Command Sequence Number", HFILL }},
	{ &hf_smb2_tid,
		{ "Tree Id", "smb2.tid", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 Tree Id", HFILL }},
	{ &hf_smb2_uid,
		{ "User Id", "smb2.uid", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 User Id", HFILL }},
	{ &hf_smb2_suid,
		{ "Secondary User Id", "smb2.suid", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 Secondary User Id", HFILL }},
	{ &hf_smb2_max_response_size,
		{ "Max Response Size", "smb2.max_response_size", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 Maximum response size", HFILL }},
	{ &hf_smb2_response_size,
		{ "Response Size", "smb2.response_size", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 response size", HFILL }},
	{ &hf_smb2_pid,
		{ "Process Id", "smb2.pid", FT_UINT32, BASE_HEX,
		NULL, 0, "SMB2 Process Id", HFILL }},
	{ &hf_smb2_flags_response,
		{ "Response", "smb2.flags.response", FT_BOOLEAN, 8,
		TFS(&tfs_flags_response), SMB2_FLAGS_RESPONSE, "Whether this is an SMB2 Request or Response", HFILL }},
	{ &hf_smb2_tree_len,
		{ "Tree Name Length", "smb2.tree.name_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of the Tree name", HFILL }},
	{ &hf_smb2_fstype_len,
		{ "FS Type Length", "smb2.fstype.name_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of the fs type", HFILL }},
	{ &hf_smb2_filename_len,
		{ "File Name Length", "smb2.filename_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of the file name", HFILL }},

	{ &hf_smb2_tree,
		{ "Tree", "smb2.tree", FT_STRING, BASE_NONE,
		NULL, 0, "Name of the Tree/Share", HFILL }},
	{ &hf_smb2_fstype,
		{ "FS Type", "smb2.fstype", FT_STRING, BASE_NONE,
		NULL, 0, "Name of the FS Type", HFILL }},
	{ &hf_smb2_filename,
		{ "Filename", "smb2.filename", FT_STRING, BASE_NONE,
		NULL, 0, "Name of the file", HFILL }},
	{ &hf_smb2_search_len,
		{ "Search Name Length", "smb2.search.name_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of the search pattern", HFILL }},

	{ &hf_smb2_search,
		{ "Search", "smb2.search", FT_STRING, BASE_NONE,
		NULL, 0, "Search pattern", HFILL }},

	{ &hf_smb2_security_blob_len,
		{ "Security Blob Length", "smb2.security_blob_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Security blob length", HFILL }},

	{ &hf_smb2_find_response_size,
		{ "Size of Find Data", "smb2.find.response_size", FT_UINT32, BASE_DEC,
		NULL, 0, "Size of returned Find data", HFILL }},

	{ &hf_smb2_class,
		{ "Class", "smb2.class", FT_UINT8, BASE_HEX,
		VALS(smb2_class_vals), 0, "Info class", HFILL }},

	{ &hf_smb2_infolevel,
		{ "InfoLevel", "smb2.infolevel", FT_UINT8, BASE_HEX,
		NULL, 0, "Infolevel", HFILL }},
	{ &hf_smb2_write_length,
		{ "Write Length", "smb2.write_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Amount of data to write", HFILL }},

	{ &hf_smb2_security_blob,
		{ "Security Blob", "smb2.security_blob", FT_BYTES, BASE_HEX,
		NULL, 0, "Security blob", HFILL }},

	{ &hf_smb2_server_guid, 
	  { "Server Guid", "smb2.server_guid", FT_GUID, BASE_NONE, 
		NULL, 0, "Server GUID", HFILL }},

	{ &hf_smb2_create_timestamp,
		{ "Create", "smb2.create.time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when this object was created", HFILL }},

	{ &hf_smb2_fid,
		{ "File Id", "smb2.fid", FT_BYTES, BASE_HEX, 
		NULL, 0, "SMB2 File Id", HFILL }},

	{ &hf_smb2_write_data,
		{ "Write Data", "smb2.write_data", FT_BYTES, BASE_HEX, 
		NULL, 0, "SMB2 Data to be written", HFILL }},

	{ &hf_smb2_last_access_timestamp,
		{ "Last Access", "smb2.last_access.time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when this object was last accessed", HFILL }},

	{ &hf_smb2_last_write_timestamp,
		{ "Last Write", "smb2.last_write.time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when this object was last written to", HFILL }},

	{ &hf_smb2_last_change_timestamp,
		{ "Last Change", "smb2.last_change.time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when this object was last changed", HFILL }},

	{ &hf_smb2_file_info_12,
		{ "SMB2_FILE_INFO_12", "smb2.smb2_file_info_12", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_INFO_12 structure", HFILL }},

	{ &hf_smb2_file_info_22,
		{ "SMB2_FILE_INFO_22", "smb2.smb2_file_info_22", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_INFO_22 structure", HFILL }},

	{ &hf_smb2_file_info_0d,
		{ "SMB2_FILE_INFO_0d", "smb2.smb2_file_info_0d", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_INFO_0d structure", HFILL }},

	{ &hf_smb2_fs_info_01,
		{ "SMB2_FS_INFO_01", "smb2.smb2_fs_info_01", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FS_INFO_01 structure", HFILL }},

	{ &hf_smb2_fs_info_05,
		{ "SMB2_FS_INFO_05", "smb2.smb2_fs_info_05", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FS_INFO_05 structure", HFILL }},

	{ &hf_smb2_disposition_delete_on_close,
	  { "Delete on close", "smb2.disposition.delete_on_close", FT_BOOLEAN, 8,
		TFS(&tfs_disposition_delete_on_close), 0x01, "", HFILL }},


	{ &hf_smb2_unknown,
		{ "unknown", "smb2.unknown", FT_BYTES, BASE_HEX,
		NULL, 0, "Unknown bytes", HFILL }},

	{ &hf_smb2_unknown_timestamp,
		{ "Timestamp", "smb2.unknown.timestamp", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Unknown timestamp", HFILL }},
	};

	static gint *ett[] = {
		&ett_smb2,
		&ett_smb2_header,
		&ett_smb2_command,
		&ett_smb2_secblob,
		&ett_smb2_file_info_22,
		&ett_smb2_file_info_12,
		&ett_smb2_file_info_0d,
		&ett_smb2_fs_info_01,
		&ett_smb2_fs_info_05,
	};

	proto_smb2 = proto_register_protocol("SMB2 (Server Message Block Protocol version 2)",
	    "SMB2", "smb2");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_smb2, hf, array_length(hf));
}

void
proto_reg_handoff_smb2(void)
{
	gssapi_handle = find_dissector("gssapi");
	heur_dissector_add("netbios", dissect_smb2_heur, proto_smb2);
}
