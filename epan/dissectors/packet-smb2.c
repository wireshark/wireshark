/* packet-smb2.c
 * Routines for smb2 packet dissection
 * Ronnie Sahlberg 2005
 *
 * See http://wiki.ethereal.com/SMB2  for documentation of
 * this protocol.
 * If you edit this file, keep the wiki updated as well.
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
#include "packet-smb.h"
#include "packet-dcerpc-nt.h"
#include <string.h>



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
static int hf_smb2_flags_response = -1;
static int hf_smb2_response_buffer_offset = -1;
static int hf_smb2_security_blob_offset = -1;
static int hf_smb2_security_blob_len = -1;
static int hf_smb2_security_blob = -1;
static int hf_smb2_ioctl_out_data = -1;
static int hf_smb2_ioctl_in_data = -1;
static int hf_smb2_unknown = -1;
static int hf_smb2_unknown_timestamp = -1;
static int hf_smb2_create_timestamp = -1;
static int hf_smb2_create_flags = -1;
static int hf_smb2_create_flags_request_oplock = -1;
static int hf_smb2_create_flags_request_exclusive_oplock = -1;
static int hf_smb2_create_flags_grant_oplock = -1;
static int hf_smb2_create_flags_grant_exclusive_oplock = -1;
static int hf_smb2_close_flags = -1;
static int hf_smb2_last_access_timestamp = -1;
static int hf_smb2_last_write_timestamp = -1;
static int hf_smb2_last_change_timestamp = -1;
static int hf_smb2_current_time = -1;
static int hf_smb2_boot_time = -1;
static int hf_smb2_filename = -1;
static int hf_smb2_filename_len = -1;
static int hf_smb2_nlinks = -1;
static int hf_smb2_delete_pending = -1;
static int hf_smb2_is_directory = -1;
static int hf_smb2_file_id = -1;
static int hf_smb2_allocation_size = -1;
static int hf_smb2_end_of_file = -1;
static int hf_smb2_tree = -1;
static int hf_smb2_search = -1;
static int hf_smb2_find_response_size = -1;
static int hf_smb2_server_guid = -1;
static int hf_smb2_class = -1;
static int hf_smb2_infolevel = -1;
static int hf_smb2_max_response_size = -1;
static int hf_smb2_max_ioctl_in_size = -1;
static int hf_smb2_required_buffer_size = -1;
static int hf_smb2_response_size = -1;
static int hf_smb2_setinfo_size = -1;
static int hf_smb2_setinfo_offset = -1;
static int hf_smb2_file_basic_info = -1;
static int hf_smb2_file_standard_info = -1;
static int hf_smb2_file_internal_info = -1;
static int hf_smb2_file_ea_info = -1;
static int hf_smb2_file_access_info = -1;
static int hf_smb2_file_rename_info = -1;
static int hf_smb2_file_disposition_info = -1;
static int hf_smb2_file_position_info = -1;
static int hf_smb2_file_info_0f = -1;
static int hf_smb2_file_mode_info = -1;
static int hf_smb2_file_alignment_info = -1;
static int hf_smb2_file_all_info = -1;
static int hf_smb2_file_allocation_info = -1;
static int hf_smb2_file_endoffile_info = -1;
static int hf_smb2_file_alternate_name_info = -1;
static int hf_smb2_file_stream_info = -1;
static int hf_smb2_file_compression_info = -1;
static int hf_smb2_file_network_open_info = -1;
static int hf_smb2_file_attribute_tag_info = -1;
static int hf_smb2_fs_info_01 = -1;
static int hf_smb2_fs_info_03 = -1;
static int hf_smb2_fs_info_04 = -1;
static int hf_smb2_fs_info_05 = -1;
static int hf_smb2_fs_info_06 = -1;
static int hf_smb2_fs_info_07 = -1;
static int hf_smb2_fs_info_08 = -1;
static int hf_smb2_sec_info_00 = -1;
static int hf_smb2_fid = -1;
static int hf_smb2_write_length = -1;
static int hf_smb2_write_offset = -1;
static int hf_smb2_write_data = -1;
static int hf_smb2_read_length = -1;
static int hf_smb2_read_offset = -1;
static int hf_smb2_read_data = -1;
static int hf_smb2_disposition_delete_on_close = -1;
static int hf_smb2_create_disposition = -1;
static int hf_smb2_chain_offset = -1;
static int hf_smb2_chain_data = -1;
static int hf_smb2_data_offset = -1;
static int hf_smb2_data_length = -1;
static int hf_smb2_extrainfo = -1;
static int hf_smb2_create_action = -1;
static int hf_smb2_next_offset = -1;
static int hf_smb2_ea_size = -1;
static int hf_smb2_ea_flags = -1;
static int hf_smb2_ea_name_len = -1;
static int hf_smb2_ea_data_len = -1;
static int hf_smb2_ea_name = -1;
static int hf_smb2_ea_data = -1;
static int hf_smb2_buffer_code_len = -1;
static int hf_smb2_buffer_code_flags_dyn = -1;
static int hf_smb2_olb_offset = -1;
static int hf_smb2_olb_length = -1;
static int hf_smb2_tag = -1;
static int hf_smb2_impersonation_level = -1;
static int hf_smb2_ioctl_function = -1;
static int hf_smb2_ioctl_function_device = -1;
static int hf_smb2_ioctl_function_access = -1;
static int hf_smb2_ioctl_function_function = -1;
static int hf_smb2_ioctl_function_method = -1;

static gint ett_smb2 = -1;
static gint ett_smb2_olb = -1;
static gint ett_smb2_ea = -1;
static gint ett_smb2_header = -1;
static gint ett_smb2_command = -1;
static gint ett_smb2_secblob = -1;
static gint ett_smb2_file_basic_info = -1;
static gint ett_smb2_file_standard_info = -1;
static gint ett_smb2_file_internal_info = -1;
static gint ett_smb2_file_ea_info = -1;
static gint ett_smb2_file_access_info = -1;
static gint ett_smb2_file_position_info = -1;
static gint ett_smb2_file_mode_info = -1;
static gint ett_smb2_file_alignment_info = -1;
static gint ett_smb2_file_all_info = -1;
static gint ett_smb2_file_allocation_info = -1;
static gint ett_smb2_file_endoffile_info = -1;
static gint ett_smb2_file_alternate_name_info = -1;
static gint ett_smb2_file_stream_info = -1;
static gint ett_smb2_file_compression_info = -1;
static gint ett_smb2_file_network_open_info = -1;
static gint ett_smb2_file_attribute_tag_info = -1;
static gint ett_smb2_file_rename_info = -1;
static gint ett_smb2_file_disposition_info = -1;
static gint ett_smb2_file_info_0f = -1;
static gint ett_smb2_fs_info_01 = -1;
static gint ett_smb2_fs_info_03 = -1;
static gint ett_smb2_fs_info_04 = -1;
static gint ett_smb2_fs_info_05 = -1;
static gint ett_smb2_fs_info_06 = -1;
static gint ett_smb2_fs_info_07 = -1;
static gint ett_smb2_fs_info_08 = -1;
static gint ett_smb2_sec_info_00 = -1;
static gint ett_smb2_tid_tree = -1;
static gint ett_smb2_create_flags = -1;
static gint ett_smb2_chain_element = -1;
static gint ett_smb2_MxAc_buffer = -1;
static gint ett_smb2_ioctl_function = -1;

static dissector_handle_t gssapi_handle = NULL;

static heur_dissector_list_t smb2_heur_subdissector_list;

#define SMB2_CLASS_FILE_INFO	0x01
#define SMB2_CLASS_FS_INFO	0x02
#define SMB2_CLASS_SEC_INFO	0x03
static const value_string smb2_class_vals[] = {
	{ SMB2_CLASS_FILE_INFO,	"FILE_INFO"},
	{ SMB2_CLASS_FS_INFO,	"FS_INFO"},
	{ SMB2_CLASS_SEC_INFO,	"SEC_INFO"},
	{ 0, NULL }
};

#define SMB2_FILE_BASIC_INFO	0x04
#define SMB2_FILE_STANDARD_INFO	0x05
#define SMB2_FILE_INTERNAL_INFO	0x06
#define SMB2_FILE_EA_INFO	0x07
#define SMB2_FILE_ACCESS_INFO	0x08
#define SMB2_FILE_RENAME_INFO	0x0a
#define SMB2_FILE_DISPOSITION_INFO	0x0d
#define SMB2_FILE_POSITION_INFO	0x0e
#define SMB2_FILE_INFO_0f	0x0f
#define SMB2_FILE_MODE_INFO	0x10
#define SMB2_FILE_ALIGNMENT_INFO	0x11
#define SMB2_FILE_ALL_INFO	0x12
#define SMB2_FILE_ALLOCATION_INFO	0x13
#define SMB2_FILE_ENDOFFILE_INFO	0x14
#define SMB2_FILE_ALTERNATE_NAME_INFO	0x15
#define SMB2_FILE_STREAM_INFO	0x16
#define SMB2_FILE_COMPRESSION_INFO	0x1c
#define SMB2_FILE_NETWORK_OPEN_INFO	0x22
#define SMB2_FILE_ATTRIBUTE_TAG_INFO	0x23

#define SMB2_FS_INFO_01		0x01 
#define SMB2_FS_INFO_03		0x03 
#define SMB2_FS_INFO_04		0x04 
#define SMB2_FS_INFO_05		0x05 
#define SMB2_FS_INFO_06		0x06 
#define SMB2_FS_INFO_07		0x07 
#define SMB2_FS_INFO_08		0x08 

#define SMB2_SEC_INFO_00	0x00

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

/* For Tids of a specific conversation.
   This keeps track of tid->sharename mappings and other information about the
   tid.
   qqq
   We might need to refine this if it occurs that tids are reused on a single
   conversation.   we dont worry about that yet for simplicity
*/
static gint
smb2_tid_info_equal(gconstpointer k1, gconstpointer k2)
{
	smb2_tid_info_t *key1 = (smb2_tid_info_t *)k1;
	smb2_tid_info_t *key2 = (smb2_tid_info_t *)k2;
	return key1->tid==key2->tid;
}
static guint
smb2_tid_info_hash(gconstpointer k)
{
	smb2_tid_info_t *key = (smb2_tid_info_t *)k;
	guint32 hash;

	hash=key->tid;
	return hash;
}

static int dissect_smb2_file_info_0f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, smb2_info_t *si);


/* This is a helper to dissect the common string type
 * uint16 offset
 * uint16 length
 * ...
 * char *string
 *
 * This function is called twice, first to decode the offset/length and
 * second time to dissect the actual string.
 * It is done this way since there is no guarantee that we have the full packet and we dont
 * want to abort dissection too early if the packet ends somewhere between the 
 * length/offset and the actual buffer.
 *
 */
enum offset_length_buffer_offset_size {
	OLB_O_UINT16_S_UINT16,
	OLB_O_UINT16_S_UINT32,
	OLB_O_UINT32_S_UINT32,
	OLB_S_UINT32_O_UINT32
};
typedef struct _offset_length_buffer_t {
	guint32 off;
	guint32 len;
	int off_offset;
	int len_offset;
	enum offset_length_buffer_offset_size offset_size;
	int hfindex;
} offset_length_buffer_t;
static int
dissect_smb2_olb_length_offset(tvbuff_t *tvb, int offset, offset_length_buffer_t *olb,
			       enum offset_length_buffer_offset_size offset_size, int hfindex)
{
	olb->hfindex=hfindex;
	olb->offset_size=offset_size;
	switch(offset_size){
	case OLB_O_UINT16_S_UINT16:
		olb->off=tvb_get_letohs(tvb, offset);
		olb->off_offset=offset;
		offset += 2;
		olb->len=tvb_get_letohs(tvb, offset);
		olb->len_offset=offset;
		offset += 2;
		break;
	case OLB_O_UINT16_S_UINT32:
		olb->off=tvb_get_letohs(tvb, offset);
		olb->off_offset=offset;
		offset += 2;
		olb->len=tvb_get_letohl(tvb, offset);
		olb->len_offset=offset;
		offset += 4;
		break;
	case OLB_O_UINT32_S_UINT32:
		olb->off=tvb_get_letohl(tvb, offset);
		olb->off_offset=offset;
		offset += 4;
		olb->len=tvb_get_letohl(tvb, offset);
		olb->len_offset=offset;
		offset += 4;
		break;
	case OLB_S_UINT32_O_UINT32:
		olb->len=tvb_get_letohl(tvb, offset);
		olb->len_offset=offset;
		offset += 4;
		olb->off=tvb_get_letohl(tvb, offset);
		olb->off_offset=offset;
		offset += 4;
		break;
	}

	return offset;
}

#define OLB_TYPE_UNICODE_STRING		0x01
#define OLB_TYPE_ASCII_STRING		0x02
static const char *
dissect_smb2_olb_string(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, offset_length_buffer_t *olb, int type)
{
	int len, off;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	const char *name=NULL;
	guint16 bc;
	int offset;

	offset=olb->off;
	len=olb->len;
	off=olb->off;
	bc=tvb_length_remaining(tvb, offset);


	/* sanity check */
	tvb_ensure_bytes_exist(tvb, off, len);
	if(((off+len)<off)
	|| ((off+len)>(off+tvb_reported_length_remaining(tvb, off)))){
		proto_tree_add_text(tree, tvb, offset, tvb_length_remaining(tvb, offset),
				    "Invalid offset/length. Malformed packet");

		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, " [Malformed packet]");
		}

		return NULL;
	}


	switch(type){
	case OLB_TYPE_UNICODE_STRING:
		name = get_unicode_or_ascii_string(tvb, &off,
			TRUE, &len, TRUE, TRUE, &bc);
		if(!name){
			name="";
		}
		if(parent_tree){
			item = proto_tree_add_string(parent_tree, olb->hfindex, tvb, offset, len, name);
			tree = proto_item_add_subtree(item, ett_smb2_olb);
		}
		break;
	case OLB_TYPE_ASCII_STRING:
		name = get_unicode_or_ascii_string(tvb, &off,
			FALSE, &len, TRUE, TRUE, &bc);
		if(!name){
			name="";
		}
		if(parent_tree){
			item = proto_tree_add_string(parent_tree, olb->hfindex, tvb, offset, len, name);
			tree = proto_item_add_subtree(item, ett_smb2_olb);
		}
		break;
	}

	switch(olb->offset_size){
	case OLB_O_UINT16_S_UINT16:
		proto_tree_add_item(tree, hf_smb2_olb_offset, tvb, olb->off_offset, 2, TRUE);
		proto_tree_add_item(tree, hf_smb2_olb_length, tvb, olb->len_offset, 2, TRUE);
		break;
	case OLB_O_UINT16_S_UINT32:
		proto_tree_add_item(tree, hf_smb2_olb_offset, tvb, olb->off_offset, 2, TRUE);
		proto_tree_add_item(tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, TRUE);
		break;
	case OLB_O_UINT32_S_UINT32:
		proto_tree_add_item(tree, hf_smb2_olb_offset, tvb, olb->off_offset, 4, TRUE);
		proto_tree_add_item(tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, TRUE);
		break;
	case OLB_S_UINT32_O_UINT32:
		proto_tree_add_item(tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, TRUE);
		proto_tree_add_item(tree, hf_smb2_olb_offset, tvb, olb->off_offset, 4, TRUE);
		break;
	}		

	return name;
}

static void
dissect_smb2_olb_buffer(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb,
			offset_length_buffer_t *olb, smb2_info_t *si,
			void (*dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si))
{
	int len, off;
	proto_item *sub_item=NULL;
	proto_tree *sub_tree=NULL;
	tvbuff_t *sub_tvb=NULL;
	guint16 bc;
	int offset;

	offset=olb->off;
	len=olb->len;
	off=olb->off;
	bc=tvb_length_remaining(tvb, offset);

	/* sanity check */
	tvb_ensure_bytes_exist(tvb, off, len);
	if(((off+len)<off)
	|| ((off+len)>(off+tvb_reported_length_remaining(tvb, off)))){
		proto_tree_add_text(parent_tree, tvb, offset, tvb_length_remaining(tvb, offset),
				    "Invalid offset/length. Malformed packet");

		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, " [Malformed packet]");
		}

		return;
	}

	/* if we dont want/need a subtree */
	if(olb->hfindex==-1){
		sub_item=parent_tree;
		sub_tree=parent_tree;
	} else {
		if(parent_tree){
			sub_item = proto_tree_add_item(parent_tree, olb->hfindex, tvb, offset, len, TRUE);
			sub_tree = proto_item_add_subtree(sub_item, ett_smb2_olb);
		}
	}

	switch(olb->offset_size){
	case OLB_O_UINT16_S_UINT16:
		proto_tree_add_item(sub_tree, hf_smb2_olb_offset, tvb, olb->off_offset, 2, TRUE);
		proto_tree_add_item(sub_tree, hf_smb2_olb_length, tvb, olb->len_offset, 2, TRUE);
		break;
	case OLB_O_UINT16_S_UINT32:
		proto_tree_add_item(sub_tree, hf_smb2_olb_offset, tvb, olb->off_offset, 2, TRUE);
		proto_tree_add_item(sub_tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, TRUE);
		break;
	case OLB_O_UINT32_S_UINT32:
		proto_tree_add_item(sub_tree, hf_smb2_olb_offset, tvb, olb->off_offset, 4, TRUE);
		proto_tree_add_item(sub_tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, TRUE);
		break;
	case OLB_S_UINT32_O_UINT32:
		proto_tree_add_item(sub_tree, hf_smb2_olb_length, tvb, olb->len_offset, 4, TRUE);
		proto_tree_add_item(sub_tree, hf_smb2_olb_offset, tvb, olb->off_offset, 4, TRUE);
		break;
	}

	if (off == 0 || len == 0) {
		proto_item_append_text(sub_item, ": NO DATA");
		return;
	}

	if (!dissector) {
		return;
	}

	sub_tvb=tvb_new_subset(tvb, off, MIN((int)len, tvb_length_remaining(tvb, off)), len);

	dissector(sub_tvb, pinfo, sub_tree, si);

	return;
}

static int
dissect_smb2_olb_tvb_max_offset(int offset, offset_length_buffer_t *olb)
{
	if (olb->off == 0) {
		return offset;
	}
	return MAX(offset, (int)(olb->off + olb->len));
}

typedef struct _smb2_function {
       int (*request)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si);
       int (*response)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si);
} smb2_function;

#define SMB2_FLAGS_RESPONSE	0x01

static const true_false_string tfs_flags_response = {
	"This is a RESPONSE",
	"This is a REQUEST"
};


static const value_string smb2_ioctl_vals[] = {
  { 0, NULL }
};


static const value_string smb2_ioctl_device_vals[] = {
  { 0x0001, "BEEP" },
  { 0x0002, "CD_ROM" },
  { 0x0003, "CD_ROM_FILE_SYSTEM" },
  { 0x0004, "CONTROLLER" },
  { 0x0005, "DATALINK" },
  { 0x0006, "DFS" },
  { 0x0007, "DISK" },
  { 0x0008, "DISK_FILE_SYSTEM" },
  { 0x0009, "FILE_SYSTEM" },
  { 0x000a, "INPORT_PORT" },
  { 0x000b, "KEYBOARD" },
  { 0x000c, "MAILSLOT" },
  { 0x000d, "MIDI_IN" },
  { 0x000e, "MIDI_OUT" },
  { 0x000f, "MOUSE" },
  { 0x0010, "MULTI_UNC_PROVIDER" },
  { 0x0011, "NAMED_PIPE" },
  { 0x0012, "NETWORK" },
  { 0x0013, "NETWORK_BROWSER" },
  { 0x0014, "NETWORK_FILE_SYSTEM" },
  { 0x0015, "NULL" },
  { 0x0016, "PARALLEL_PORT" },
  { 0x0017, "PHYSICAL_NETCARD" },
  { 0x0018, "PRINTER" },
  { 0x0019, "SCANNER" },
  { 0x001a, "SERIAL_MOUSE_PORT" },
  { 0x001b, "SERIAL_PORT" },
  { 0x001c, "SCREEN" },
  { 0x001d, "SOUND" },
  { 0x001e, "STREAMS" },
  { 0x001f, "TAPE" },
  { 0x0020, "TAPE_FILE_SYSTEM" },
  { 0x0021, "TRANSPORT" },
  { 0x0022, "UNKNOWN" },
  { 0x0023, "VIDEO" },
  { 0x0024, "VIRTUAL_DISK" },
  { 0x0025, "WAVE_IN" },
  { 0x0026, "WAVE_OUT" },
  { 0x0027, "8042_PORT" },
  { 0x0028, "NETWORK_REDIRECTOR" },
  { 0x0029, "BATTERY" },
  { 0x002a, "BUS_EXTENDER" },
  { 0x002b, "MODEM" },
  { 0x002c, "VDM" },
  { 0x002d, "MASS_STORAGE" },
  { 0x002e, "SMB" },
  { 0x002f, "KS" },
  { 0x0030, "CHANGER" },
  { 0x0031, "SMARTCARD" },
  { 0x0032, "ACPI" },
  { 0x0033, "DVD" },
  { 0x0034, "FULLSCREEN_VIDEO" },
  { 0x0035, "DFS_FILE_SYSTEM" },
  { 0x0036, "DFS_VOLUME" },
  { 0x0037, "SERENUM" },
  { 0x0038, "TERMSRV" },
  { 0x0039, "KSEC" },
  { 0, NULL }
};

static const value_string smb2_ioctl_access_vals[] = {
  { 0x00, "FILE_ANY_ACCESS" },
  { 0x01, "FILE_READ_ACCESS" },
  { 0x02, "FILE_WRITE_ACCESS" },
  { 0x03, "FILE_READ_WRITE_ACCESS" },
  { 0, NULL }
};

static const value_string smb2_ioctl_method_vals[] = {
  { 0x00, "METHOD_BUFFERED" },
  { 0x01, "METHOD_IN_DIRECT" },
  { 0x02, "METHOD_OUT_DIRECT" },
  { 0x03, "METHOD_NEITHER" },
  { 0, NULL }
};

dissect_smb2_ioctl_function(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, smb2_info_t *si)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_ioctl_function, tvb, offset, 4, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_ioctl_function);
	}

	si->ioctl_function=tvb_get_letohl(tvb, offset);
	if(si->ioctl_function){
		/* device */
		proto_tree_add_item(tree, hf_smb2_ioctl_function_device, tvb, offset, 4, TRUE);
		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(
				pinfo->cinfo, COL_INFO, " %s",
				val_to_str((si->ioctl_function>>16)&0xffff, smb2_ioctl_device_vals,
				"Unknown (0x%08X)"));
		}

		/* access */
		proto_tree_add_item(tree, hf_smb2_ioctl_function_access, tvb, offset, 4, TRUE);

		/* function */
		proto_tree_add_item(tree, hf_smb2_ioctl_function_function, tvb, offset, 4, TRUE);
		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(
				pinfo->cinfo, COL_INFO, " Function:0x%04x",
				(si->ioctl_function>>2)&0x0fff);
		}

		/* method */
		proto_tree_add_item(tree, hf_smb2_ioctl_function_method, tvb, offset, 4, TRUE);
	}

	offset += 4;

	return offset;
}

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
dissect_smb2_fid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si, int mode)
{
	guint8 drep[4] = { 0x10, 0x00, 0x00, 0x00}; /* fake DREP struct */
	dcerpc_info di;	/* fake dcerpc_info struct */
	void *old_private_data;
	e_ctx_hnd policy_hnd;
	proto_item *hnd_item=NULL;
	char *fid_name;
	guint32 open_frame = 0, close_frame = 0;

	di.conformant_run=0;
	di.call_data=NULL;
	old_private_data=pinfo->private_data;
	pinfo->private_data=&di;

	switch(mode){
	case FID_MODE_OPEN:
		offset = dissect_nt_guid_hnd(tvb, offset, pinfo, tree, drep, hf_smb2_fid, &policy_hnd, &hnd_item, TRUE, FALSE);
		if(!pinfo->fd->flags.visited){
			if(si->saved && si->saved->private_data){
				fid_name = se_strdup_printf("File:%s", (char *)si->saved->private_data);
			} else {
				fid_name = se_strdup_printf("File: ");
			}
			dcerpc_smb_store_pol_name(&policy_hnd, pinfo,
						  fid_name);
		}
		break;
	case FID_MODE_CLOSE:
		offset = dissect_nt_guid_hnd(tvb, offset, pinfo, tree, drep, hf_smb2_fid, &policy_hnd, &hnd_item, FALSE, TRUE);
		break;
	case FID_MODE_USE:
		offset = dissect_nt_guid_hnd(tvb, offset, pinfo, tree, drep, hf_smb2_fid, &policy_hnd, &hnd_item, FALSE, FALSE);
		break;
	}

	pinfo->private_data=old_private_data;


	/* put the filename in col_info */
	if (dcerpc_smb_fetch_pol(&policy_hnd, &fid_name, &open_frame, &close_frame, pinfo->fd->num)) {
		if(fid_name){
			if(hnd_item){
				proto_item_append_text(hnd_item, " %s", fid_name);
			}
			if (check_col(pinfo->cinfo, COL_INFO)){
				col_append_fstr(pinfo->cinfo, COL_INFO, " %s", fid_name);
			}
		}
	}

	return offset;
}


/* this info level is unique to SMB2 and differst from the corresponding 
 * SMB_FILE_ALL_INFO in SMB
 */
static int
dissect_smb2_file_all_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int length;
	const char *name="";
	guint16 bc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_all_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_all_info);
	}

	/* create time */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

	/* last access */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

	/* last write */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

	/* last change */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

	/* File Attributes */
	offset = dissect_file_attributes(tvb, tree, offset, 4);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, FALSE);
	offset += 4;

	/* allocation size */
	proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, TRUE);
	offset += 8;

	/* end of file */
	proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, TRUE);
	offset += 8;

	/* number of links */
	proto_tree_add_item(tree, hf_smb2_nlinks, tvb, offset, 4, TRUE);
	offset += 4;

	/* delete pending */
	proto_tree_add_item(tree, hf_smb2_delete_pending, tvb, offset, 1, TRUE);
	offset += 1;

	/* is directory */
	proto_tree_add_item(tree, hf_smb2_is_directory, tvb, offset, 1, TRUE);
	offset += 1;

	/* padding */
	offset += 2;

	/* file id */
	proto_tree_add_item(tree, hf_smb2_file_id, tvb, offset, 8, TRUE);
	offset += 8;

	/* ea size */
	proto_tree_add_item(tree, hf_smb2_ea_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* access mask */
	offset = dissect_smb_access_mask(tvb, tree, offset);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, FALSE);
	offset += 16;

	/* file name length */
	length=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 2, TRUE);
	offset += 2;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, FALSE);
	offset += 2;

	/* file name */
	if(length){
		bc=tvb_length_remaining(tvb, offset);
		name = get_unicode_or_ascii_string(tvb, &offset,
			TRUE, &length, TRUE, TRUE, &bc);
		if(name){
			proto_tree_add_string(tree, hf_smb2_filename, tvb,
				offset, length, name);
		}

	}
	offset += length;


	return offset;
}


static int
dissect_smb2_file_allocation_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_allocation_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_allocation_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_ALLOCATION_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_endoffile_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_endoffile_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_endoffile_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_ENDOFFILE_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_alternate_name_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_alternate_name_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_alternate_name_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_ALTERNATE_NAME_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}


static int
dissect_smb2_file_basic_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_basic_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_basic_info);
	}

	/* create time */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

	/* last access */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

	/* last write */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

	/* last change */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

	/* File Attributes */
	offset = dissect_file_attributes(tvb, tree, offset, 4);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

static int
dissect_smb2_file_standard_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_standard_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_standard_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_STANDARD_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}
static int
dissect_smb2_file_internal_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_internal_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_internal_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_INTERNAL_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}
static int
dissect_smb2_file_mode_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_mode_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_mode_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_MODE_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}
static int
dissect_smb2_file_alignment_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_alignment_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_alignment_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_ALIGNMENT_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}
static int
dissect_smb2_file_position_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_position_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_position_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_POSITION_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_access_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_access_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_access_info);
	}

	/* access mask */
	offset = dissect_smb_access_mask(tvb, tree, offset);

	return offset;
}

static int
dissect_smb2_file_ea_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_ea_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_ea_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_EA_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_stream_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_stream_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_stream_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_STREAM_INFO(tvb, pinfo, tree, offset, &bc, &trunc, TRUE);

	return offset;
}

static int
dissect_smb2_file_compression_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_compression_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_compression_info);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_COMPRESSION_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_network_open_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_network_open_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_network_open_info);
	}


	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_NETWORK_OPEN_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static int
dissect_smb2_file_attribute_tag_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;
	gboolean trunc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_attribute_tag_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_attribute_tag_info);
	}


	bc=tvb_length_remaining(tvb, offset);
	offset = dissect_qfi_SMB_FILE_ATTRIBUTE_TAG_INFO(tvb, pinfo, tree, offset, &bc, &trunc);

	return offset;
}

static const true_false_string tfs_disposition_delete_on_close = {
	"DELETE this file when closed",
	"Normal access, do not delete on close"
};

static int
dissect_smb2_file_disposition_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_disposition_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_disposition_info);
	}

	/* file disposition */
	proto_tree_add_item(tree, hf_smb2_disposition_delete_on_close, tvb, offset, 1, TRUE);

	return offset;
}

static int
dissect_smb2_file_info_0f(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint32 next_offset;
	guint8 ea_name_len, ea_data_len;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_info_0f, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_info_0f);
	}

	while(1){
		int length;
		const char *name="";
		const char *data="";
		guint16 bc;
		int start_offset=offset;
		proto_item *ea_item=NULL;
		proto_tree *ea_tree=NULL;

		if(tree){
			ea_item = proto_tree_add_text(tree, tvb, offset, -1, "EA:");
			ea_tree = proto_item_add_subtree(ea_item, ett_smb2_ea);
		}

		/* next offset */
		next_offset=tvb_get_letohl(tvb, offset);
		proto_tree_add_item(ea_tree, hf_smb2_next_offset, tvb, offset, 4, TRUE);
		offset += 4;

		/* EA flags */
		proto_tree_add_item(ea_tree, hf_smb2_ea_flags, tvb, offset, 1, TRUE);
		offset += 1;

		/* EA Name Length */
		ea_name_len=tvb_get_guint8(tvb, offset);
		proto_tree_add_item(ea_tree, hf_smb2_ea_name_len, tvb, offset, 1, TRUE);
		offset += 1;

		/* EA Data Length */
		ea_data_len=tvb_get_guint8(tvb, offset);
		proto_tree_add_item(ea_tree, hf_smb2_ea_data_len, tvb, offset, 1, TRUE);
		offset += 1;

		/* some unknown bytes */
		proto_tree_add_item(ea_tree, hf_smb2_unknown, tvb, offset, 1, TRUE);
		offset += 1;

		/* ea name */
		length=ea_name_len;
		if(length){
			bc=tvb_length_remaining(tvb, offset);
			name = get_unicode_or_ascii_string(tvb, &offset,
				FALSE, &length, TRUE, TRUE, &bc);
			if(name){
				proto_tree_add_string(ea_tree, hf_smb2_ea_name, tvb,
					offset, length, name);
			}
		}
		offset += ea_name_len;

		/* separator byte */
		offset += 1;

		/* ea data */
		length=ea_data_len;
		if(length){
			bc=tvb_length_remaining(tvb, offset);
			data = get_unicode_or_ascii_string(tvb, &offset,
				FALSE, &length, TRUE, TRUE, &bc);
			if(data){
				proto_tree_add_string(ea_tree, hf_smb2_ea_data, tvb,
					offset, length, data);
			}
		}
		offset += ea_data_len;


		if(ea_item){
			proto_item_append_text(ea_item, " %s := %s", name, data);
		}
		proto_item_set_len(ea_item, offset-start_offset);


		if(!next_offset){
			break;
		}
		if(next_offset>256){
			break;
		}

		offset = start_offset+next_offset;
	}

	return offset;
}

static int
dissect_smb2_file_rename_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int length;
	const char *name="";
	guint16 bc;


	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_file_rename_info, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_file_rename_info);
	}

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, FALSE);
	offset += 16;

	/* file name length */
	length=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_filename_len, tvb, offset, 2, TRUE);
	offset += 2;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, FALSE);
	offset += 2;

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
			col_append_fstr(pinfo->cinfo, COL_INFO, " NewName:%s",
			name);
		}
	}
	offset += length;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

static int
dissect_smb2_sec_info_00(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_sec_info_00, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_sec_info_00);
	}

	/* security descriptor */
	offset = dissect_nt_sec_desc(tvb, offset, pinfo, tree, NULL, TRUE, tvb_length_remaining(tvb, offset), NULL);

	return offset;
}

static int
dissect_smb2_fs_info_05(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_05, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_05);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset=dissect_qfsi_FS_ATTRIBUTE_INFO(tvb, pinfo, tree, offset, &bc, TRUE);

	return offset;
}

static int
dissect_smb2_fs_info_06(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_06, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_06);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset=dissect_nt_quota(tvb, tree, offset, &bc);

	return offset;
}

static int
dissect_smb2_fs_info_08(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_08, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_08);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset=dissect_qfsi_FS_OBJECTID_INFO(tvb, pinfo, tree, offset, &bc);

	return offset;
}

static int
dissect_smb2_fs_info_07(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_07, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_07);
	}

	bc=tvb_length_remaining(tvb, offset);
	offset=dissect_qfsi_FS_FULL_SIZE_INFO(tvb, pinfo, tree, offset, &bc);

	return offset;
}

static int
dissect_smb2_fs_info_01(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_01, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_01);
	}


	bc=tvb_length_remaining(tvb, offset);
	offset=dissect_qfsi_FS_VOLUME_INFO(tvb, pinfo, tree, offset, &bc, TRUE);

	return offset;
}

static int
dissect_smb2_fs_info_03(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_03, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_03);
	}


	bc=tvb_length_remaining(tvb, offset);
	offset=dissect_qfsi_FS_SIZE_INFO(tvb, pinfo, tree, offset, &bc);

	return offset;
}

static int
dissect_smb2_fs_info_04(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, smb2_info_t *si _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 bc;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_fs_info_04, tvb, offset, -1, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_fs_info_04);
	}


	bc=tvb_length_remaining(tvb, offset);
	offset=dissect_qfsi_FS_DEVICE_INFO(tvb, pinfo, tree, offset, &bc);

	return offset;
}

static int
dissect_smb2_create_flags(proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, hf_smb2_create_flags, tvb, offset, 2, TRUE);
		tree = proto_item_add_subtree(item, ett_smb2_create_flags);
	}

	proto_tree_add_item(tree, hf_smb2_create_flags_request_exclusive_oplock, tvb, offset, 2, TRUE);
	proto_tree_add_item(tree, hf_smb2_create_flags_request_oplock, tvb, offset, 2, TRUE);
	proto_tree_add_item(tree, hf_smb2_create_flags_grant_exclusive_oplock, tvb, offset, 2, TRUE);
	proto_tree_add_item(tree, hf_smb2_create_flags_grant_oplock, tvb, offset, 2, TRUE);


	offset += 2;
	return offset;
}

static int
dissect_smb2_buffercode(proto_tree *tree, tvbuff_t *tvb, int offset, guint16 *length)
{
	guint16 buffer_code;

	/* dissect the first 2 bytes of the command PDU */
	buffer_code = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb2_buffer_code_len, tvb, offset, 2, buffer_code&0xfffe);
	proto_tree_add_item(tree, hf_smb2_buffer_code_flags_dyn, tvb, offset, 2, TRUE);
	offset += 2;

	if(length){
		*length=buffer_code&0xfffe;
	}
	
	return offset;
}

static void
dissect_smb2_secblob(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si _U_)
{
	call_dissector(gssapi_handle, tvb, pinfo, tree);
	return;
}

static int
dissect_smb2_session_setup_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	offset_length_buffer_t s_olb;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);
	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 8, FALSE);
	offset += 8;

	/* security blob offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &s_olb, OLB_O_UINT16_S_UINT16, hf_smb2_security_blob);

	/* the security blob itself */
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &s_olb, si, dissect_smb2_secblob);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &s_olb);

	return offset;
}

static int
dissect_smb2_session_setup_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	offset_length_buffer_t s_olb;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);
	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	/* security blob offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &s_olb, OLB_O_UINT16_S_UINT16, hf_smb2_security_blob);

	/* the security blob itself */
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &s_olb, si, dissect_smb2_secblob);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &s_olb);

	return offset;
}

static int
dissect_smb2_tree_connect_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	offset_length_buffer_t olb;
	const char *buf;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	/* tree  offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &olb, OLB_O_UINT16_S_UINT16, hf_smb2_tree);

	/* tree string */
	buf = dissect_smb2_olb_string(pinfo, tree, tvb, &olb, OLB_TYPE_UNICODE_STRING);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &olb);

	/* treelen  +1 is overkill here if the string is unicode,   
	 * but who ever has more than a handful of TCON in a trace anyways
	 */
	if(!pinfo->fd->flags.visited && si->saved && buf && olb.len){
		si->saved->private_data=se_alloc(olb.len+1);
		g_snprintf((char *)si->saved->private_data,olb.len+1,"%s",buf);
	}

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, " Tree:%s", buf);
	}


	return offset;
}
static int
dissect_smb2_tree_connect_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);
	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	if(!pinfo->fd->flags.visited && si->saved && si->saved->private_data) {
		smb2_tid_info_t *tid, tid_key;


		tid_key.tid=si->tid;
		tid=g_hash_table_lookup(si->conv->tids, &tid_key);
		if(tid){
			g_hash_table_remove(si->conv->tids, &tid_key);
		}
		tid=se_alloc(sizeof(smb2_tid_info_t));
		tid->tid=si->tid;
		tid->name=(char *)si->saved->private_data;
		tid->flags=0;
		if(strlen(tid->name)>=4){
			if(!strcmp(tid->name+strlen(tid->name)-4, "IPC$")){
				tid->flags|=SMB2_FLAGS_TID_IS_IPC;
			} else {
				tid->flags|=SMB2_FLAGS_TID_IS_NOT_IPC;
			}
		} else {
			tid->flags|=SMB2_FLAGS_TID_IS_NOT_IPC;
		}

		g_hash_table_insert(si->conv->tids, tid, tid);

		si->saved->private_data=NULL;
	}

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 8, TRUE);
	offset += 8;

	/* this is some sort of access mask */
	offset = dissect_smb_access_mask(tvb, tree, offset);

	return offset;
}

static int
dissect_smb2_tree_disconnect_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
dissect_smb2_tree_disconnect_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
dissect_smb2_logoff_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
dissect_smb2_logoff_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
dissect_smb2_keepalive_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
dissect_smb2_keepalive_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
dissect_smb2_notify_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);
	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* completion filter */
	offset = dissect_nt_notify_completion_filter(tvb, tree, offset);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	return offset;
}

static int
dissect_smb2_notify_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	switch(si->status){
	case 0x00000103: /* STATUS_PENDING */
	case 0xc0000120: /* STATUS_CANCELLED */
		/* some unknown bytes */
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
		offset += 4;
		/* bug */
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 1, TRUE);
		offset += 1;
		return offset;
	case 0x0000010c: /* STATUS_NOTIFY_ENUM_DIR */
		/* some unknown bytes */
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
		offset += 4;
		return offset;
	}

	/* we dont know what this is */
	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, tvb_length_remaining(tvb, offset), TRUE);
	offset += tvb_length_remaining(tvb, offset);
	return offset;
}

static int
dissect_smb2_find_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t olb;
	const char *buf;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);
	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* search pattern  offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &olb, OLB_O_UINT16_S_UINT16, hf_smb2_search);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	/* search pattern */
	buf = dissect_smb2_olb_string(pinfo, tree, tvb, &olb, OLB_TYPE_UNICODE_STRING);
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, " Pattern:%s",buf);
	}

	offset = dissect_smb2_olb_tvb_max_offset(offset, &olb);

	return offset;
}

static int
dissect_smb2_find_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	guint32 len;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* response buffer offset */
	proto_tree_add_item(tree, hf_smb2_response_buffer_offset, tvb, offset, 2, TRUE);
	offset += 2;

	/* length of response data */
	len=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_find_response_size, tvb, offset, 4, TRUE);
	offset += 4;

/*qqq*/
	return offset;
}

static int
dissect_smb2_negotiate_protocol_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	offset_length_buffer_t s_olb;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);
	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;


	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	/* server GUID */
	proto_tree_add_item(tree, hf_smb2_server_guid, tvb, offset, 16, TRUE);
	offset += 16;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
	offset += 16;

	/* current time */
	dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_current_time);
	offset += 8;

	/* boot time */
	dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_boot_time);
	offset += 8;

	/* security blob offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &s_olb, OLB_O_UINT16_S_UINT16, hf_smb2_security_blob);

	/* the security blob itself */
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &s_olb, si, dissect_smb2_secblob);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	offset = dissect_smb2_olb_tvb_max_offset(offset, &s_olb);

	return offset;
}

static void
dissect_smb2_getinfo_parameters(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si)
{
	switch(si->saved->class){
	case SMB2_CLASS_FILE_INFO:
		switch(si->saved->infolevel){
		default:
			/* we dont handle this infolevel yet */
			proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
			offset += tvb_length_remaining(tvb, offset);
		}
		break;
	case SMB2_CLASS_FS_INFO:
		switch(si->saved->infolevel){
		default:
			/* we dont handle this infolevel yet */
			proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
			offset += tvb_length_remaining(tvb, offset);
		}
		break;
	case SMB2_CLASS_SEC_INFO:
		switch(si->saved->infolevel){
		case SMB2_SEC_INFO_00:
			dissect_security_information_mask(tvb, tree, offset+8);
			break;
		default:
			/* we dont handle this infolevel yet */
			proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
			offset += tvb_length_remaining(tvb, offset);
		}
		break;
	default:
		/* we dont handle this class yet */
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
	}
}


static int
dissect_smb2_getinfo_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* class */
	if(si->saved){
		si->saved->class=tvb_get_guint8(tvb, offset);
	}
	proto_tree_add_item(tree, hf_smb2_class, tvb, offset, 1, TRUE);
	offset += 1;

	/* infolevel */
	if(si->saved){
		si->saved->infolevel=tvb_get_guint8(tvb, offset);
	}
	proto_tree_add_item(tree, hf_smb2_infolevel, tvb, offset, 1, TRUE);
	offset += 1;


	if (si->saved && check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, " Class:0x%02x Level:0x%02x", si->saved->class, si->saved->infolevel);
	}

	/* max response size */
	proto_tree_add_item(tree, hf_smb2_max_response_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* parameters */
	if(si->saved){
		dissect_smb2_getinfo_parameters(tvb, pinfo, tree, offset, si);
	} else {
		/* some unknown bytes */
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
	}
	offset += 16;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	return offset;
}

static void
dissect_smb2_infolevel(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si, guint8 class, guint8 infolevel)
{

	switch(class){
	case SMB2_CLASS_FILE_INFO:
		switch(infolevel){
		case SMB2_FILE_BASIC_INFO:
			dissect_smb2_file_basic_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_STANDARD_INFO:
			dissect_smb2_file_standard_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_INTERNAL_INFO:
			dissect_smb2_file_internal_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_EA_INFO:
			dissect_smb2_file_ea_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_ACCESS_INFO:
			dissect_smb2_file_access_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_RENAME_INFO:
			dissect_smb2_file_rename_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_DISPOSITION_INFO:
			dissect_smb2_file_disposition_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_POSITION_INFO:
			dissect_smb2_file_position_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_INFO_0f:
			dissect_smb2_file_info_0f(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_MODE_INFO:
			dissect_smb2_file_mode_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_ALIGNMENT_INFO:
			dissect_smb2_file_alignment_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_ALL_INFO:
			dissect_smb2_file_all_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_ALLOCATION_INFO:
			dissect_smb2_file_allocation_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_ENDOFFILE_INFO:
			dissect_smb2_file_endoffile_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_ALTERNATE_NAME_INFO:
			dissect_smb2_file_alternate_name_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_STREAM_INFO:
			dissect_smb2_file_stream_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_COMPRESSION_INFO:
			dissect_smb2_file_compression_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_NETWORK_OPEN_INFO:
			dissect_smb2_file_network_open_info(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FILE_ATTRIBUTE_TAG_INFO:
			dissect_smb2_file_attribute_tag_info(tvb, pinfo, tree, offset, si);
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
			dissect_smb2_fs_info_01(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FS_INFO_03:
			dissect_smb2_fs_info_03(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FS_INFO_04:
			dissect_smb2_fs_info_04(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FS_INFO_05:
			dissect_smb2_fs_info_05(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FS_INFO_06:
			dissect_smb2_fs_info_06(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FS_INFO_07:
			dissect_smb2_fs_info_07(tvb, pinfo, tree, offset, si);
			break;
		case SMB2_FS_INFO_08:
			dissect_smb2_fs_info_08(tvb, pinfo, tree, offset, si);
			break;
		default:
			/* we dont handle this infolevel yet */
			proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, tvb_length_remaining(tvb, offset), TRUE);
			offset += tvb_length_remaining(tvb, offset);
		}
		break;
	case SMB2_CLASS_SEC_INFO:
		switch(infolevel){
		case SMB2_SEC_INFO_00:
			dissect_smb2_sec_info_00(tvb, pinfo, tree, offset, si);
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

static void
dissect_smb2_getinfo_response_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	/* data */
	if(si->saved){
		dissect_smb2_infolevel(tvb, pinfo, tree, 0, si, si->saved->class, si->saved->infolevel);
	} else {
		/* some unknown bytes */
		proto_tree_add_item(tree, hf_smb2_unknown, tvb, 0, tvb_length(tvb), FALSE);
	}

	return;
}


static int
dissect_smb2_getinfo_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	guint8 class=0;
	guint8 infolevel=0;
	guint16 len;
	offset_length_buffer_t olb;

	/* class/infolevel */
	if(si->saved){
		proto_item *item;

		class=si->saved->class;
		item=proto_tree_add_uint(tree, hf_smb2_class, tvb, 0, 0, class);
		PROTO_ITEM_SET_GENERATED(item);

		infolevel=si->saved->infolevel;
		item=proto_tree_add_uint(tree, hf_smb2_infolevel, tvb, 0, 0, infolevel);
		PROTO_ITEM_SET_GENERATED(item);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, &len);

	/* response buffer offset  and size */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &olb, OLB_O_UINT16_S_UINT32, -1);

	/* if we get BUFFER_TOO_SMALL there will not be any data there, only
	 * a guin32 specifying how big the buffer needs to be
	 */
	if(si->status==0xc0000023){
		proto_tree_add_item(tree, hf_smb2_required_buffer_size, tvb, offset, 4, TRUE);
		offset += 4;

		return offset;
	}


	/* response data*/
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &olb, si, dissect_smb2_getinfo_response_data);

	return offset;
}

static int
dissect_smb2_close_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* close flags */
	proto_tree_add_item(tree, hf_smb2_close_flags, tvb, offset, 2, TRUE);
	offset += 2;

	/* padding */
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_CLOSE);

	return offset;
}

static int
dissect_smb2_close_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	guint16 len;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, &len);

	/* close flags */
	proto_tree_add_item(tree, hf_smb2_close_flags, tvb, offset, 2, TRUE);
	offset += 2;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	/* If there was an error, the response will be just 8 bytes */
	if((len==8)&&(si->status)){
		return offset;
	}


	/* create time */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

	/* last access */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

	/* last write */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

	/* last change */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

	/* allocation size */
	proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, TRUE);
	offset += 8;

	/* end of file */
	proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, TRUE);
	offset += 8;

	/* File Attributes */
	offset = dissect_file_attributes(tvb, tree, offset, 4);

	return offset;
}

static int
dissect_smb2_flush_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 6, TRUE);
	offset += 6;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	return offset;
}

static int
dissect_smb2_flush_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}


static int
dissect_smb2_lock_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 6, TRUE);
	offset += 6;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
	offset += 16;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 8, TRUE);
	offset += 8;

	return offset;
}

static int
dissect_smb2_lock_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}
static int
dissect_smb2_cancel_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}


static int
dissect_file_data_dcerpc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, int offset, guint32 datalen, smb2_info_t *si)
{
	int tvblen;
	int result;

	tvbuff_t *dcerpc_tvb;
	tvblen = tvb_length_remaining(tvb, offset);
	dcerpc_tvb = tvb_new_subset(tvb, offset, MIN((int)datalen, tvb_length_remaining(tvb, offset)), datalen);

	/* dissect the full PDU */
	result = dissector_try_heuristic(smb2_heur_subdissector_list, dcerpc_tvb, pinfo, si->top_tree);


	offset += datalen;

	return offset;
}

	
static int
dissect_smb2_write_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	guint32 length;
	guint64 off;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* data offset */
	proto_tree_add_item(tree, hf_smb2_data_offset, tvb, offset, 2, TRUE);
	offset += 2;

	/* length */
	length=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_write_length, tvb, offset, 4, TRUE);
	offset += 4;

	/* offset */
	off=tvb_get_letoh64(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_write_offset, tvb, offset, 8, TRUE);
	offset += 8;

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, " Len:%d Off:%" PRIu64, length, off);
	}

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
	offset += 16;


	/* data or dcerpc ?*/
	if(length && si->tree && si->tree->flags&SMB2_FLAGS_TID_IS_IPC ){
		offset = dissect_file_data_dcerpc(tvb, pinfo, tree, offset, length, si);
		return offset;
	}

	/* just ordinary data */
	proto_tree_add_item(tree, hf_smb2_write_data, tvb, offset, length, TRUE);
	offset += MIN(length,(guint32)tvb_length_remaining(tvb, offset));

	return offset;
}


static int
dissect_smb2_write_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);
	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	/* length */
	proto_tree_add_item(tree, hf_smb2_write_length, tvb, offset, 4, TRUE);
	offset += 4;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 9, TRUE);
	offset += 9;

	return offset;
}

static void
dissect_smb2_ioctl_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, smb2_info_t *si)
{
	dissect_file_data_dcerpc(tvb, pinfo, parent_tree, 0, tvb_length(tvb), si);

	return;
}


static int
dissect_smb2_ioctl_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t o_olb;
	offset_length_buffer_t i_olb;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	/* ioctl function */
	offset = dissect_smb2_ioctl_function(tvb, pinfo, tree, offset, si);

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* out buffer offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &o_olb, OLB_O_UINT32_S_UINT32, hf_smb2_ioctl_out_data);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 4, TRUE);
	offset += 4;

	/* in buffer offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &i_olb, OLB_O_UINT32_S_UINT32, hf_smb2_ioctl_in_data);

	/* max ioctl in size */
	proto_tree_add_item(tree, hf_smb2_max_ioctl_in_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 8, TRUE);
	offset += 8;

	/* try to decode these blobs in the order they were encoded
	 * so that for "short" packets we will dissect as much as possible
	 * before aborting with "short packet"
	 */
	if(i_olb.off>o_olb.off){
		/* out buffer */
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &o_olb, si, dissect_smb2_ioctl_data);
		/* in buffer */
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &i_olb, si, NULL);
	} else {
		/* in buffer */
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &i_olb, si, NULL);
		/* out buffer */
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &o_olb, si, dissect_smb2_ioctl_data);
	}

	offset = dissect_smb2_olb_tvb_max_offset(offset, &o_olb);
	offset = dissect_smb2_olb_tvb_max_offset(offset, &i_olb);

	return offset;
}

static int
dissect_smb2_ioctl_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t o_olb;
	offset_length_buffer_t i_olb;
	guint16 len;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, &len);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	/* ioctl function */
	offset = dissect_smb2_ioctl_function(tvb, pinfo, tree, offset, si);

	/* If there was an error, the response will be just 8 bytes */
	if((len==8)&&(si->status)){
		return offset;
	}


	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* in buffer offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &i_olb, OLB_O_UINT32_S_UINT32, hf_smb2_ioctl_in_data);

	/* out buffer offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &o_olb, OLB_O_UINT32_S_UINT32, hf_smb2_ioctl_out_data);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 8, TRUE);
	offset += 8;

	/* try to decode these blobs in the order they were encoded
	 * so that for "short" packets we will dissect as much as possible
	 * before aborting with "short packet"
	 */
	if(i_olb.off>o_olb.off){
		/* out buffer */
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &o_olb, si, dissect_smb2_ioctl_data);
		/* in buffer */
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &i_olb, si, dissect_smb2_ioctl_data);
	} else {
		/* in buffer */
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &i_olb, si, dissect_smb2_ioctl_data);
		/* out buffer */
		dissect_smb2_olb_buffer(pinfo, tree, tvb, &o_olb, si, dissect_smb2_ioctl_data);
	}

	offset = dissect_smb2_olb_tvb_max_offset(offset, &i_olb);
	offset = dissect_smb2_olb_tvb_max_offset(offset, &o_olb);

	return offset;
}


static int
dissect_smb2_read_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	guint32 len;
	guint64 off;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);
	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 2, TRUE);
	offset += 2;

	/* length */
	len=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_read_length, tvb, offset, 4, TRUE);
	offset += 4;

	/* offset */
	off=tvb_get_letoh64(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_read_offset, tvb, offset, 8, TRUE);
	offset += 8;

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, " Len:%d Off:%" PRIu64, len, off);
	}

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 16, TRUE);
	offset += 16;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 1, TRUE);
	offset += 1;

	return offset;
}


static int
dissect_smb2_read_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si _U_)
{
	guint32 length;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* data offset */
	proto_tree_add_item(tree, hf_smb2_data_offset, tvb, offset, 2, TRUE);
	offset += 2;

	/* length  might even be 64bits if they are ambitious*/
	length=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_read_length, tvb, offset, 4, TRUE);
	offset += 4;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 8, TRUE);
	offset += 8;

	/* data or dcerpc ?*/
	if(length && si->tree && si->tree->flags&SMB2_FLAGS_TID_IS_IPC ){
		offset = dissect_file_data_dcerpc(tvb, pinfo, tree, offset, length, si);
		return offset;
	}

	/* data */
	proto_tree_add_item(tree, hf_smb2_read_data, tvb, offset, length, TRUE);
	offset += MIN(length,(guint32)tvb_length_remaining(tvb, offset));

	return offset;
}

static void
dissect_smb2_ExtA_buffer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si)
{
	proto_item *item=NULL;
	if (tree) {
		item = proto_tree_get_parent(tree);
		proto_item_append_text(item, ": SMB2_FILE_INFO_0f");
	}
	dissect_smb2_file_info_0f(tvb, pinfo, tree, 0, si);
	return;
}

static void
dissect_smb2_MxAc_buffer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, smb2_info_t *si _U_)
{
	int offset=0;
	proto_item *item=NULL;
	proto_item *sub_item=NULL;
	proto_tree *sub_tree=NULL;

	if (tree) {
		item = proto_tree_get_parent(tree);
	}

	if (tvb_length_remaining(tvb, offset) == 0) {
		if (item) {
			proto_item_append_text(item, ": NO DATA");
		}
		return;
	}

	if (item) {
		proto_item_append_text(item, ": MxAc INFO");
		sub_item = proto_tree_add_text(tree, tvb, offset, -1, "MxAc INFO");
		sub_tree = proto_item_add_subtree(sub_item, ett_smb2_MxAc_buffer);
	}

	proto_tree_add_item(sub_tree, hf_smb2_unknown, tvb, offset, 4, FALSE);
	offset += 4;

	offset = dissect_smb_access_mask(tvb, sub_tree, offset);

	return;
}

static void
dissect_smb2_create_extra_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, smb2_info_t *si)
{
	offset_length_buffer_t tag_olb;
	offset_length_buffer_t data_olb;
	const char *tag;
	guint16 chain_offset;
	int offset=0;
	int len=-1;
	void (*dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, smb2_info_t *si);
	proto_item *sub_item=NULL;
	proto_tree *sub_tree=NULL;
	proto_item *parent_item=NULL;

	chain_offset=tvb_get_letohl(tvb, offset);
	if (chain_offset) {
		len = chain_offset;
	}

	if(parent_tree){
		sub_item = proto_tree_add_text(parent_tree, tvb, offset, len, "Chain Element");
		sub_tree = proto_item_add_subtree(sub_item, ett_smb2_chain_element);
		parent_item = proto_tree_get_parent(parent_tree);
	}

	/* chain offset */
	proto_tree_add_item(sub_tree, hf_smb2_chain_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* tag  offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &tag_olb, OLB_O_UINT16_S_UINT32, hf_smb2_tag);
	
	/* data  offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &data_olb, OLB_O_UINT16_S_UINT32, hf_smb2_chain_data);

	/* tag string */
	tag = dissect_smb2_olb_string(pinfo, sub_tree, tvb, &tag_olb, OLB_TYPE_ASCII_STRING);

	proto_item_append_text(parent_item, " %s", tag);
	proto_item_append_text(sub_item, ": %s", tag);

	/* data */
	dissector = NULL;
	if(!strcmp(tag, "ExtA")){
		dissector = dissect_smb2_ExtA_buffer;
	} else if(!strcmp(tag, "MxAc")){
		dissector = dissect_smb2_MxAc_buffer;
	}

	dissect_smb2_olb_buffer(pinfo, sub_tree, tvb, &data_olb, si, dissector);

	if(chain_offset){
		tvbuff_t *chain_tvb;
		chain_tvb=tvb_new_subset(tvb, chain_offset, tvb_length_remaining(tvb, chain_offset), tvb_reported_length_remaining(tvb, chain_offset));

		/* next extra info */
		dissect_smb2_create_extra_info(chain_tvb, pinfo, parent_tree, si);
	}
	return;
}

static int
dissect_smb2_create_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t f_olb, e_olb;
	const char *fname;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* create flags */
	offset = dissect_smb2_create_flags(tree, tvb, offset);

	/* impersonation level */
	proto_tree_add_item(tree, hf_smb2_impersonation_level, tvb, offset, 4, TRUE);
	offset += 4;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 8, TRUE);
	offset += 8;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 8, TRUE);
	offset += 8;

	/* access mask */
	offset = dissect_smb_access_mask(tvb, tree, offset);

	/* File Attributes */
	offset = dissect_file_attributes(tvb, tree, offset, 4);

	/* share access */
	offset = dissect_nt_share_access(tvb, tree, offset);

	/* create disposition */
	proto_tree_add_item(tree, hf_smb2_create_disposition, tvb, offset, 4, TRUE);
	offset += 4;

	/* create options */
	offset = dissect_nt_create_options(tvb, tree, offset);

	/* filename  offset/length */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &f_olb, OLB_O_UINT16_S_UINT16, hf_smb2_filename);

	/* extrainfo offset */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &e_olb, OLB_O_UINT32_S_UINT32, hf_smb2_extrainfo);

	/* filename string */
	fname = dissect_smb2_olb_string(pinfo, tree, tvb, &f_olb, OLB_TYPE_UNICODE_STRING);
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, " File:%s", fname);
	}

	/* save the name if it looks sane */
	if(!pinfo->fd->flags.visited){
		if(si->saved && si->saved->private_data){
			g_free(si->saved->private_data);
			si->saved->private_data=NULL;
		}
		if(si->saved && f_olb.len && (f_olb.len<256)){
			si->saved->private_data=g_malloc(f_olb.len+1);
			g_snprintf(si->saved->private_data, f_olb.len+1, "%s", fname);
		}
	}


	/* If extrainfo_offset is non-null then this points to another 
	 * buffer. The offset is relative to the start of the smb packet
	 */
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &e_olb, si, dissect_smb2_create_extra_info);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &f_olb);
	offset = dissect_smb2_olb_tvb_max_offset(offset, &e_olb);

	return offset;
}

static int
dissect_smb2_create_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	offset_length_buffer_t e_olb;
	guint16 len;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, &len);

	/* create flags */
	offset = dissect_smb2_create_flags(tree, tvb, offset);

	/* create action */
	proto_tree_add_item(tree, hf_smb2_create_action, tvb, offset, 4, TRUE);
	offset += 4;

	/* If there was an error, the response will be just 8 bytes */
	if((len==8)&&(si->status)){
		return offset;
	}


	/* create time */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_create_timestamp);

	/* last access */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_access_timestamp);

	/* last write */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_write_timestamp);

	/* last change */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_smb2_last_change_timestamp);

	/* allocation size */
	proto_tree_add_item(tree, hf_smb2_allocation_size, tvb, offset, 8, TRUE);
	offset += 8;

	/* end of file */
	proto_tree_add_item(tree, hf_smb2_end_of_file, tvb, offset, 8, TRUE);
	offset += 8;

	/* File Attributes */
	offset = dissect_file_attributes(tvb, tree, offset, 4);

	/* padding */
	offset += 4;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_OPEN);

	/* extrainfo offset */
	offset = dissect_smb2_olb_length_offset(tvb, offset, &e_olb, OLB_O_UINT32_S_UINT32, hf_smb2_extrainfo);

	/* If extrainfo_offset is non-null then this points to another 
	 * buffer. The offset is relative to the start of the smb packet
	 */
	dissect_smb2_olb_buffer(pinfo, tree, tvb, &e_olb, si, dissect_smb2_create_extra_info);

	offset = dissect_smb2_olb_tvb_max_offset(offset, &e_olb);

	/* free si->saved->private_data   we dont need it any more */
	if(si->saved && si->saved->private_data){
		g_free(si->saved->private_data);
		si->saved->private_data=NULL;
	}

	return offset;
}


static int
dissect_smb2_setinfo_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si)
{
	guint32 setinfo_size;
	guint16 setinfo_offset;

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	/* class/level only meaningful in requests */
	if(!si->response){
		/* class */
		if(si->saved){
			si->saved->class=tvb_get_guint8(tvb, offset);
		}
		proto_tree_add_item(tree, hf_smb2_class, tvb, offset, 1, TRUE);
		/* infolevel */
		if(si->saved){
			si->saved->infolevel=tvb_get_guint8(tvb, offset+1);
		}
		proto_tree_add_item(tree, hf_smb2_infolevel, tvb, offset+1, 1, TRUE);
	}
	offset += 2;

	if (si->saved && check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, " Class:0x%02x Level:0x%02x", si->saved->class, si->saved->infolevel);
	}

	/* size */
	setinfo_size=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_setinfo_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* offset */
	setinfo_offset=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_smb2_setinfo_offset, tvb, offset, 2, TRUE);
	offset += 2;

	/* some unknown bytes */
	proto_tree_add_item(tree, hf_smb2_unknown, tvb, offset, 6, TRUE);
	offset += 6;

	/* fid */
	offset = dissect_smb2_fid(tvb, pinfo, tree, offset, si, FID_MODE_USE);

	/* data */
	if(si->saved)
	  dissect_smb2_infolevel(tvb, pinfo, tree, setinfo_offset, si, si->saved->class, si->saved->infolevel);
	offset = setinfo_offset + setinfo_size;

	return offset;
}

static int
dissect_smb2_setinfo_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, smb2_info_t *si)
{
	/* class/infolevel */
	if(si->saved){
		guint8 class=0;
		guint8 infolevel=0;
		proto_item *item;

		class=si->saved->class;
		item=proto_tree_add_uint(tree, hf_smb2_class, tvb, 0, 0, class);
		PROTO_ITEM_SET_GENERATED(item);

		infolevel=si->saved->infolevel;
		item=proto_tree_add_uint(tree, hf_smb2_infolevel, tvb, 0, 0, infolevel);
		PROTO_ITEM_SET_GENERATED(item);
	}

	/* buffer code */
	offset = dissect_smb2_buffercode(tree, tvb, offset, NULL);

	return offset;
}

/* names here are just until we find better names for these functions */
const value_string smb2_cmd_vals[] = {
  { 0x00, "NegotiateProtocol" },
  { 0x01, "SessionSetupAndX" },
  { 0x02, "Logoff" },
  { 0x03, "TreeConnect" },
  { 0x04, "TreeDisconnect" },
  { 0x05, "Create" },
  { 0x06, "Close" },
  { 0x07, "Flush" },
  { 0x08, "Read" },
  { 0x09, "Write" },
  { 0x0A, "Lock" },
  { 0x0B, "Ioctl" },
  { 0x0C, "Cancel" },
  { 0x0D, "KeepAlive" },
  { 0x0E, "Find" },
  { 0x0F, "Notify" },
  { 0x10, "GetInfo" },
  { 0x11, "SetInfo" },
  { 0x12, "Break" },
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
  /* 0x02 Logoff*/
	{dissect_smb2_logoff_request, 
	 dissect_smb2_logoff_response},
  /* 0x03 TreeConnect*/  
	{dissect_smb2_tree_connect_request,
	 dissect_smb2_tree_connect_response},
  /* 0x04 TreeDisconnect*/
	{dissect_smb2_tree_disconnect_request,
	 dissect_smb2_tree_disconnect_response},
  /* 0x05 Create*/  
	{dissect_smb2_create_request,
	 dissect_smb2_create_response},
  /* 0x06 Close*/  
	{dissect_smb2_close_request,
	 dissect_smb2_close_response},
  /* 0x07 Flush*/
	{dissect_smb2_flush_request,
	 dissect_smb2_flush_response},
  /* 0x08 Read*/  
	{dissect_smb2_read_request,
	 dissect_smb2_read_response},
  /* 0x09 Writew*/  
	{dissect_smb2_write_request,
	 dissect_smb2_write_response},
  /* 0x0a Lock */
	{dissect_smb2_lock_request,
	 dissect_smb2_lock_response},
  /* 0x0b Ioctl*/
	{dissect_smb2_ioctl_request,
	 dissect_smb2_ioctl_response},
  /* 0x0c Cancel*/  
	{dissect_smb2_cancel_request,
	 NULL},
  /* 0x0d KeepAlive*/
	{dissect_smb2_keepalive_request,
	 dissect_smb2_keepalive_response},
  /* 0x0e Find*/  
	{dissect_smb2_find_request,
	 dissect_smb2_find_response},
  /* 0x0f Notify*/  
	{dissect_smb2_notify_request,
	 dissect_smb2_notify_response},
  /* 0x10 GetInfo*/  
	{dissect_smb2_getinfo_request,
	 dissect_smb2_getinfo_response},
  /* 0x11 SetInfo*/  
	{dissect_smb2_setinfo_request,
	 dissect_smb2_setinfo_response},
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
dissect_smb2_command(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, smb2_info_t *si)
{
	int (*cmd_dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, smb2_info_t *si);
	proto_item *cmd_item;
	proto_tree *cmd_tree;

	cmd_item = proto_tree_add_text(tree, tvb, offset, -1,
			"%s %s (0x%02x)",
			decode_smb2_name(si->opcode),
			si->response?"Response":"Request",
			si->opcode);
	cmd_tree = proto_item_add_subtree(cmd_item, ett_smb2_command);


	cmd_dissector=si->response?
		smb2_dissector[si->opcode&0xff].response:
		smb2_dissector[si->opcode&0xff].request;
	if(cmd_dissector){
		offset=(*cmd_dissector)(tvb, pinfo, cmd_tree, offset, si);
	} else {
		proto_tree_add_item(cmd_tree, hf_smb2_unknown, tvb, offset, -1, FALSE);
		offset=tvb_length(tvb);
	}

	return offset;
}

static int
dissect_smb2_tid(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, smb2_info_t *si)
{
	proto_item *tid_item=NULL;
	proto_tree *tid_tree=NULL;
	smb2_tid_info_t tid_key;

	/* Tree ID */
	si->tid=tvb_get_letohl(tvb, offset);
	tid_item=proto_tree_add_item(tree, hf_smb2_tid, tvb, offset, 4, TRUE);
	if(tree){
		tid_tree=proto_item_add_subtree(tid_item, ett_smb2_tid_tree);
	}

	/* see if we can find the name for this tid */
	tid_key.tid=si->tid;
	si->tree=g_hash_table_lookup(si->conv->tids, &tid_key);
	if(si->tree){
		proto_tree_add_string(tid_tree, hf_smb2_tree, tvb, offset, 4, si->tree->name);
	}

	offset += 4;

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
	guint16 header_len;
	conversation_t *conversation;
	smb2_saved_info_t *ssi=NULL, ssi_key;
	smb2_info_t *si;

	si=ep_alloc(sizeof(smb2_info_t));
	si->conv=NULL;
	si->saved=NULL;
	si->tree=NULL;
	si->top_tree=parent_tree;

	/* find which conversation we are part of and get the data for that
	 * conversation
	 */
	conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,  pinfo->srcport, pinfo->destport, 0);
	if(!conversation){
		/* OK this is a new conversation so lets create it */
		conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
			pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	}
	si->conv=conversation_get_proto_data(conversation, proto_smb2);
	if(!si->conv){
		/* no smb2_into_t structure for this conversation yet,
		 * create it.
		 */
		si->conv=se_alloc(sizeof(smb2_conv_info_t));
		/* qqq this leaks memory for now since we never free
		   the hashtables */
		si->conv->matched= g_hash_table_new(smb2_saved_info_hash_matched,
			smb2_saved_info_equal_matched);
		si->conv->unmatched= g_hash_table_new(smb2_saved_info_hash_unmatched,
			smb2_saved_info_equal_unmatched);
		si->conv->tids= g_hash_table_new(smb2_tid_info_hash,
			smb2_tid_info_equal);

		conversation_add_proto_data(conversation, proto_smb2, si->conv);
	}


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
	si->status=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(header_tree, hf_smb2_nt_status, tvb, offset, 4, TRUE);
	offset += 4;


	/* opcode */
	si->opcode=tvb_get_guint8(tvb, offset);
	proto_tree_add_item(header_tree, hf_smb2_cmd, tvb, offset, 2, TRUE);
	offset += 2;

	/* some unknown bytes */
	proto_tree_add_item(header_tree, hf_smb2_unknown, tvb, offset, 2, FALSE);
	offset += 2;

	/* flags */
	si->response=tvb_get_guint8(tvb, offset)&SMB2_FLAGS_RESPONSE;
	proto_tree_add_item(header_tree, hf_smb2_flags_response, tvb, offset, 1, FALSE);
	offset += 1;

	/* some unknown bytes */
	proto_tree_add_item(header_tree, hf_smb2_unknown, tvb, offset, 7, FALSE);
	offset += 7;

	/* command sequence number*/
	si->seqnum=tvb_get_letoh64(tvb, offset);
	ssi_key.seqnum=si->seqnum;
	proto_tree_add_item(header_tree, hf_smb2_seqnum, tvb, offset, 8, TRUE);
	offset += 8;

	/* Process ID */
	proto_tree_add_item(header_tree, hf_smb2_pid, tvb, offset, 4, TRUE);
	offset += 4;

	/* Tree ID */
	offset = dissect_smb2_tid(pinfo, header_tree, tvb, offset, si);

	/* User ID */
	proto_tree_add_item(header_tree, hf_smb2_uid, tvb, offset, 8, TRUE);
	offset += 8;

	/* some unknown bytes */
	proto_tree_add_item(header_tree, hf_smb2_unknown, tvb, offset, 4, FALSE);
	offset += 4;

	/* some unknown bytes */
	proto_tree_add_item(header_tree, hf_smb2_unknown, tvb, offset, 12, FALSE);
	offset += 12;

	proto_item_set_len(header_item, offset-old_offset);



	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s",
			decode_smb2_name(si->opcode),
			si->response?"Response":"Request");
		if(si->status){
			col_append_fstr(
				pinfo->cinfo, COL_INFO, ", Error: %s",
				val_to_str(si->status, NT_errors,
				"Unknown (0x%08X)"));
		}
	}


	if(!pinfo->fd->flags.visited){
		/* see if we can find this seqnum in the unmatched table */
		ssi=g_hash_table_lookup(si->conv->unmatched, &ssi_key);

		if(!si->response){
			/* This is a request */
			if(ssi){
				/* this is a request and we already found 
				 * an older ssi so just delete the previous 
				 * one 
				 */
				g_hash_table_remove(si->conv->unmatched, ssi);
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
				ssi->private_data=NULL;
				ssi->frame_req=pinfo->fd->num;
				ssi->frame_res=0;
				ssi->req_time=pinfo->fd->abs_ts;
				g_hash_table_insert(si->conv->unmatched, ssi, ssi);
			}
		} else {
			/* This is a response */
			if(ssi){
				/* just  set the response frame and move it to the matched table */
				ssi->frame_res=pinfo->fd->num;
				g_hash_table_remove(si->conv->unmatched, ssi);
				g_hash_table_insert(si->conv->matched, ssi, ssi);
			}
		}
	} else {
		/* see if we can find this seqnum in the matched table */
		ssi=g_hash_table_lookup(si->conv->matched, &ssi_key);
		/* if we couldnt find it in the matched table, it might still
		 * be in the unmatched table
		 */
		if(!ssi){
			ssi=g_hash_table_lookup(si->conv->unmatched, &ssi_key);
		}
	}

	if(ssi){
		if(!si->response){
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
	si->saved=ssi;

	/* Decode the payload */
	dissect_smb2_command(pinfo, tree, tvb, offset, si);
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
		{ "User Id", "smb2.uid", FT_UINT64, BASE_HEX,
		NULL, 0, "SMB2 User Id", HFILL }},
	{ &hf_smb2_end_of_file,
		{ "End Of File", "smb2.eof", FT_UINT64, BASE_DEC,
		NULL, 0, "SMB2 End Of File/File size", HFILL }},
	{ &hf_smb2_nlinks,
		{ "Number of Links", "smb2.nlinks", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of links to this object", HFILL }},
	{ &hf_smb2_file_id,
		{ "File Id", "smb2.file_id", FT_UINT64, BASE_HEX,
		NULL, 0, "SMB2 File Id", HFILL }},
	{ &hf_smb2_allocation_size,
		{ "Allocation Size", "smb2.allocation_size", FT_UINT64, BASE_DEC,
		NULL, 0, "SMB2 Allocation Size for this object", HFILL }},
	{ &hf_smb2_max_response_size,
		{ "Max Response Size", "smb2.max_response_size", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 Maximum response size", HFILL }},
	{ &hf_smb2_setinfo_size,
		{ "Setinfo Size", "smb2.setinfo_size", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 setinfo size", HFILL }},
	{ &hf_smb2_setinfo_offset,
		{ "Setinfo Offset", "smb2.setinfo_offset", FT_UINT16, BASE_HEX,
		NULL, 0, "SMB2 setinfo offset", HFILL }},
	{ &hf_smb2_max_ioctl_in_size,
		{ "Max Ioctl In Size", "smb2.max_ioctl_in_size", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 Maximum ioctl in size", HFILL }},
	{ &hf_smb2_response_size,
		{ "Response Size", "smb2.response_size", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 response size", HFILL }},
	{ &hf_smb2_required_buffer_size,
		{ "Required Buffer Size", "smb2.required_size", FT_UINT32, BASE_DEC,
		NULL, 0, "SMB2 required buffer size", HFILL }},
	{ &hf_smb2_pid,
		{ "Process Id", "smb2.pid", FT_UINT32, BASE_HEX,
		NULL, 0, "SMB2 Process Id", HFILL }},
	{ &hf_smb2_flags_response,
		{ "Response", "smb2.flags.response", FT_BOOLEAN, 8,
		TFS(&tfs_flags_response), SMB2_FLAGS_RESPONSE, "Whether this is an SMB2 Request or Response", HFILL }},
	{ &hf_smb2_tree,
		{ "Tree", "smb2.tree", FT_STRING, BASE_NONE,
		NULL, 0, "Name of the Tree/Share", HFILL }},
	{ &hf_smb2_filename,
		{ "Filename", "smb2.filename", FT_STRING, BASE_NONE,
		NULL, 0, "Name of the file", HFILL }},
	{ &hf_smb2_filename_len,
		{ "Filename Length", "smb2.filename.len", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of the file name", HFILL }},

	{ &hf_smb2_search,
		{ "Search Pattern", "smb2.search", FT_STRING, BASE_NONE,
		NULL, 0, "Search pattern", HFILL }},

	{ &hf_smb2_security_blob_len,
		{ "Security Blob Length", "smb2.security_blob_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Security blob length", HFILL }},

	{ &hf_smb2_security_blob_offset,
		{ "Security Blob Offset", "smb2.security_blob_offset", FT_UINT16, BASE_HEX,
		NULL, 0, "Offset into the SMB2 PDU of the blob", HFILL }},

	{ &hf_smb2_response_buffer_offset,
		{ "Response Buffer Offset", "smb2.response_buffer_offset", FT_UINT16, BASE_HEX,
		NULL, 0, "Offset of the response buffer", HFILL }},

	{ &hf_smb2_data_offset,
		{ "Data Offset", "smb2.data_offset", FT_UINT16, BASE_HEX,
		NULL, 0, "Offset to data", HFILL }},

	{ &hf_smb2_find_response_size,
		{ "Size of Find Data", "smb2.find.response_size", FT_UINT32, BASE_DEC,
		NULL, 0, "Size of returned Find data", HFILL }},

	{ &hf_smb2_ea_size,
		{ "EA Size", "smb2.ea_size", FT_UINT32, BASE_DEC,
		NULL, 0, "Size of EA data", HFILL }},

	{ &hf_smb2_class,
		{ "Class", "smb2.class", FT_UINT8, BASE_HEX,
		VALS(smb2_class_vals), 0, "Info class", HFILL }},

	{ &hf_smb2_infolevel,
		{ "InfoLevel", "smb2.infolevel", FT_UINT8, BASE_HEX,
		NULL, 0, "Infolevel", HFILL }},

	{ &hf_smb2_write_length,
		{ "Write Length", "smb2.write_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Amount of data to write", HFILL }},

	{ &hf_smb2_write_offset,
		{ "Write Offset", "smb2.write_offset", FT_UINT64, BASE_DEC,
		NULL, 0, "At which offset to write the data", HFILL }},

	{ &hf_smb2_read_length,
		{ "Read Length", "smb2.read_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Amount of data to read", HFILL }},

	{ &hf_smb2_read_offset,
		{ "Read Offset", "smb2.read_offset", FT_UINT64, BASE_DEC,
		NULL, 0, "At which offset to read the data", HFILL }},

	{ &hf_smb2_security_blob,
		{ "Security Blob", "smb2.security_blob", FT_BYTES, BASE_HEX,
		NULL, 0, "Security blob", HFILL }},

	{ &hf_smb2_ioctl_out_data,
		{ "Out Data", "smb2.ioctl.out", FT_NONE, BASE_NONE,
		NULL, 0, "Ioctl Out", HFILL }},

	{ &hf_smb2_ioctl_in_data,
		{ "In Data", "smb2.ioctl.in", FT_NONE, BASE_NONE,
		NULL, 0, "Ioctl In", HFILL }},

	{ &hf_smb2_server_guid, 
	  { "Server Guid", "smb2.server_guid", FT_GUID, BASE_NONE, 
		NULL, 0, "Server GUID", HFILL }},

	{ &hf_smb2_create_timestamp,
		{ "Create", "smb2.create.time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when this object was created", HFILL }},

	{ &hf_smb2_fid,
		{ "File Id", "smb2.fid", FT_GUID, BASE_NONE, 
		NULL, 0, "SMB2 File Id", HFILL }},

	{ &hf_smb2_write_data,
		{ "Write Data", "smb2.write_data", FT_BYTES, BASE_HEX, 
		NULL, 0, "SMB2 Data to be written", HFILL }},

	{ &hf_smb2_read_data,
		{ "Read Data", "smb2.read_data", FT_BYTES, BASE_HEX, 
		NULL, 0, "SMB2 Data that is read", HFILL }},

	{ &hf_smb2_last_access_timestamp,
		{ "Last Access", "smb2.last_access.time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when this object was last accessed", HFILL }},

	{ &hf_smb2_last_write_timestamp,
		{ "Last Write", "smb2.last_write.time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when this object was last written to", HFILL }},

	{ &hf_smb2_last_change_timestamp,
		{ "Last Change", "smb2.last_change.time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Time when this object was last changed", HFILL }},

	{ &hf_smb2_file_all_info,
		{ "SMB2_FILE_ALL_INFO", "smb2.smb2_file_all_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_ALL_INFO structure", HFILL }},

	{ &hf_smb2_file_allocation_info,
		{ "SMB2_FILE_ALLOCATION_INFO", "smb2.smb2_file_allocation_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_ALLOCATION_INFO structure", HFILL }},

	{ &hf_smb2_file_endoffile_info,
		{ "SMB2_FILE_ENDOFFILE_INFO", "smb2.smb2_file_endoffile_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_ENDOFFILE_INFO structure", HFILL }},

	{ &hf_smb2_file_alternate_name_info,
		{ "SMB2_FILE_ALTERNATE_NAME_INFO", "smb2.smb2_file_alternate_name_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_ALTERNATE_NAME_INFO structure", HFILL }},

	{ &hf_smb2_file_stream_info,
		{ "SMB2_FILE_STREAM_INFO", "smb2.smb2_file_stream_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_STREAM_INFO structure", HFILL }},

	{ &hf_smb2_file_compression_info,
		{ "SMB2_FILE_COMPRESSION_INFO", "smb2.smb2_file_compression_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_COMPRESSION_INFO structure", HFILL }},

	{ &hf_smb2_file_basic_info,
		{ "SMB2_FILE_BASIC_INFO", "smb2.smb2_file_basic_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_BASIC_INFO structure", HFILL }},

	{ &hf_smb2_file_standard_info,
		{ "SMB2_FILE_STANDARD_INFO", "smb2.smb2_file_standard_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_STANDARD_INFO structure", HFILL }},

	{ &hf_smb2_file_internal_info,
		{ "SMB2_FILE_INTERNAL_INFO", "smb2.smb2_file_internal_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_INTERNAL_INFO structure", HFILL }},

	{ &hf_smb2_file_mode_info,
		{ "SMB2_FILE_MODE_INFO", "smb2.smb2_file_mode_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_MODE_INFO structure", HFILL }},

	{ &hf_smb2_file_alignment_info,
		{ "SMB2_FILE_ALIGNMENT_INFO", "smb2.smb2_file_alignment_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_ALIGNMENT_INFO structure", HFILL }},

	{ &hf_smb2_file_position_info,
		{ "SMB2_FILE_POSITION_INFO", "smb2.smb2_file_position_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_POSITION_INFO structure", HFILL }},

	{ &hf_smb2_file_access_info,
		{ "SMB2_FILE_ACCESS_INFO", "smb2.smb2_file_access_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_ACCESS_INFO structure", HFILL }},

	{ &hf_smb2_file_ea_info,
		{ "SMB2_FILE_EA_INFO", "smb2.smb2_file_ea_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_EA_INFO structure", HFILL }},

	{ &hf_smb2_file_network_open_info,
		{ "SMB2_FILE_NETWORK_OPEN_INFO", "smb2.smb2_file_network_open_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_NETWORK_OPEN_INFO structure", HFILL }},

	{ &hf_smb2_file_attribute_tag_info,
		{ "SMB2_FILE_ATTRIBUTE_TAG_INFO", "smb2.smb2_file_attribute_tag_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_ATTRIBUTE_TAG_INFO structure", HFILL }},

	{ &hf_smb2_file_disposition_info,
		{ "SMB2_FILE_DISPOSITION_INFO", "smb2.smb2_file_disposition_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_DISPOSITION_INFO structure", HFILL }},

	{ &hf_smb2_file_info_0f,
		{ "SMB2_FILE_INFO_0f", "smb2.smb2_file_info_0f", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_INFO_0f structure", HFILL }},

	{ &hf_smb2_file_rename_info,
		{ "SMB2_FILE_RENAME_INFO", "smb2.smb2_file_rename_info", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FILE_RENAME_INFO structure", HFILL }},

	{ &hf_smb2_fs_info_01,
		{ "SMB2_FS_INFO_01", "smb2.smb2_fs_info_01", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FS_INFO_01 structure", HFILL }},

	{ &hf_smb2_fs_info_03,
		{ "SMB2_FS_INFO_03", "smb2.smb2_fs_info_03", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FS_INFO_03 structure", HFILL }},

	{ &hf_smb2_fs_info_04,
		{ "SMB2_FS_INFO_04", "smb2.smb2_fs_info_04", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FS_INFO_04 structure", HFILL }},

	{ &hf_smb2_fs_info_05,
		{ "SMB2_FS_INFO_05", "smb2.smb2_fs_info_05", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FS_INFO_05 structure", HFILL }},

	{ &hf_smb2_fs_info_06,
		{ "SMB2_FS_INFO_06", "smb2.smb2_fs_info_06", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FS_INFO_06 structure", HFILL }},

	{ &hf_smb2_fs_info_07,
		{ "SMB2_FS_INFO_07", "smb2.smb2_fs_info_07", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FS_INFO_07 structure", HFILL }},

	{ &hf_smb2_fs_info_08,
		{ "SMB2_FS_INFO_08", "smb2.smb2_fs_info_08", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_FS_INFO_08 structure", HFILL }},

	{ &hf_smb2_sec_info_00,
		{ "SMB2_SEC_INFO_00", "smb2.smb2_sec_info_00", FT_NONE, BASE_NONE,
		NULL, 0, "SMB2_SEC_INFO_00 structure", HFILL }},

	{ &hf_smb2_disposition_delete_on_close,
	  { "Delete on close", "smb2.disposition.delete_on_close", FT_BOOLEAN, 8,
		TFS(&tfs_disposition_delete_on_close), 0x01, "", HFILL }},


	{ &hf_smb2_create_disposition,
		{ "Disposition", "smb2.create.disposition", FT_UINT32, BASE_DEC,
		VALS(create_disposition_vals), 0, "Create disposition, what to do if the file does/does not exist", HFILL }},

	{ &hf_smb2_create_action,
		{ "Create Action", "smb2.create.action", FT_UINT32, BASE_DEC,
		VALS(oa_open_vals), 0, "Create Action", HFILL }},

	{ &hf_smb2_extrainfo,
		{ "ExtraInfo", "smb2.create.extrainfo", FT_NONE, BASE_NONE,
		NULL, 0, "Create ExtraInfo", HFILL }},

	{ &hf_smb2_chain_offset,
		{ "Chain Offset", "smb2.create.chain_offset", FT_UINT32, BASE_HEX,
		NULL, 0, "Offset to next entry in chain or 0", HFILL }},

	{ &hf_smb2_chain_data,
		{ "Data", "smb2.create.chain_data", FT_NONE, BASE_NONE,
		NULL, 0, "Chain Data", HFILL }},

	{ &hf_smb2_data_length,
		{ "Data Length", "smb2.create.data_length", FT_UINT32, BASE_DEC,
		NULL, 0, "Length Data or 0", HFILL }},

	{ &hf_smb2_next_offset,
		{ "Next Offset", "smb2.next_offset", FT_UINT32, BASE_DEC,
		NULL, 0, "Offset to next buffer or 0", HFILL }},

	{ &hf_smb2_current_time,
		{ "Current Time", "smb2.current_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Current Time at server", HFILL }},

	{ &hf_smb2_boot_time,
		{ "Boot Time", "smb2.boot_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Boot Time at server", HFILL }},

	{ &hf_smb2_ea_flags,
		{ "EA Flags", "smb2.ea.flags", FT_UINT8, BASE_HEX,
		NULL, 0, "EA Flags", HFILL }},

	{ &hf_smb2_ea_name_len,
		{ "EA Name Length", "smb2.ea.name_len", FT_UINT8, BASE_DEC,
		NULL, 0, "EA Name Length", HFILL }},

	{ &hf_smb2_ea_data_len,
		{ "EA Data Length", "smb2.ea.data_len", FT_UINT8, BASE_DEC,
		NULL, 0, "EA Data Length", HFILL }},

	{ &hf_smb2_delete_pending,
		{ "Delete Pending", "smb2.delete_pending", FT_UINT8, BASE_DEC,
		NULL, 0, "Delete Pending", HFILL }},

	{ &hf_smb2_is_directory,
		{ "Is Directory", "smb2.is_directory", FT_UINT8, BASE_DEC,
		NULL, 0, "Is this a directory?", HFILL }},

	{ &hf_smb2_create_flags,
		{ "Create Flags", "smb2.create.flags", FT_UINT16, BASE_HEX,
		NULL, 0, "Create flags", HFILL }},

	{ &hf_smb2_create_flags_request_oplock,
		{ "Request Oplock", "smb2.create_flags.request_oplock", FT_BOOLEAN, 16,
		NULL, 0x0100, "", HFILL }},

	{ &hf_smb2_create_flags_request_exclusive_oplock,
		{ "Request Exclusive Oplock", "smb2.create_flags.request_exclusive_oplock", FT_BOOLEAN, 16,
		NULL, 0x0800, "", HFILL }},

	{ &hf_smb2_create_flags_grant_oplock,
		{ "Grant Oplock", "smb2.create_flags.grant_oplock", FT_BOOLEAN, 16,
		NULL, 0x0001, "", HFILL }},

	{ &hf_smb2_create_flags_grant_exclusive_oplock,
		{ "Grant Exclusive Oplock", "smb2.create_flags.grant_exclusive_oplock", FT_BOOLEAN, 16,
		NULL, 0x0008, "", HFILL }},

	{ &hf_smb2_close_flags,
		{ "Close Flags", "smb2.close.flags", FT_UINT16, BASE_HEX,
		NULL, 0, "close flags", HFILL }},

	{ &hf_smb2_buffer_code_len,
		{ "Length", "smb2.buffer_code.length", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of fixed portion of PDU", HFILL }},

	{ &hf_smb2_olb_length,
		{ "Length", "smb2.olb.length", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of the buffer", HFILL }},

	{ &hf_smb2_olb_offset,
		{ "Offset", "smb2.olb.offset", FT_UINT32, BASE_HEX,
		NULL, 0, "Offset to the buffer", HFILL }},

	{ &hf_smb2_buffer_code_flags_dyn,
		{ "Dynamic Part", "smb2.buffer_code.dynamic", FT_BOOLEAN, 16,
		NULL, 0x0001, "Whether a dynamic length blob follows", HFILL }},

	{ &hf_smb2_ea_data,
		{ "EA Data", "smb2.ea.data", FT_STRING, BASE_NONE,
		NULL, 0, "EA Data", HFILL }},

	{ &hf_smb2_ea_name,
		{ "EA Name", "smb2.ea.name", FT_STRING, BASE_NONE,
		NULL, 0, "EA Name", HFILL }},

	{ &hf_smb2_impersonation_level,
		{ "Impersonation", "smb2.impersonation.level", FT_UINT32, BASE_DEC,
		VALS(impersonation_level_vals), 0, "Impersonation level", HFILL }},

	{ &hf_smb2_ioctl_function,
		{ "Function", "smb2.ioctl.function", FT_UINT32, BASE_HEX,
		VALS(smb2_ioctl_vals), 0, "Ioctl function", HFILL }},

	{ &hf_smb2_ioctl_function_device,
		{ "Device", "smb2.ioctl.function.device", FT_UINT32, BASE_HEX,
		VALS(smb2_ioctl_device_vals), 0xffff0000, "Device for Ioctl", HFILL }},

	{ &hf_smb2_ioctl_function_access,
		{ "Access", "smb2.ioctl.function.access", FT_UINT32, BASE_HEX,
		VALS(smb2_ioctl_access_vals), 0x0000c000, "Access for Ioctl", HFILL }},

	{ &hf_smb2_ioctl_function_function,
		{ "Function", "smb2.ioctl.function.function", FT_UINT32, BASE_HEX,
		NULL, 0x00003ffc, "Function for Ioctl", HFILL }},

	{ &hf_smb2_ioctl_function_method,
		{ "Method", "smb2.ioctl.function.method", FT_UINT32, BASE_HEX,
		VALS(smb2_ioctl_method_vals), 0x00000003, "Method for Ioctl", HFILL }},

	{ &hf_smb2_tag,
		{ "Tag", "smb2.tag", FT_STRING, BASE_NONE,
		NULL, 0, "Tag of chain entry", HFILL }},

	{ &hf_smb2_unknown,
		{ "unknown", "smb2.unknown", FT_BYTES, BASE_HEX,
		NULL, 0, "Unknown bytes", HFILL }},

	{ &hf_smb2_unknown_timestamp,
		{ "Timestamp", "smb2.unknown.timestamp", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Unknown timestamp", HFILL }},
	};

	static gint *ett[] = {
		&ett_smb2,
		&ett_smb2_ea,
		&ett_smb2_olb,
		&ett_smb2_header,
		&ett_smb2_command,
		&ett_smb2_secblob,
		&ett_smb2_file_basic_info,
		&ett_smb2_file_standard_info,
		&ett_smb2_file_internal_info,
		&ett_smb2_file_ea_info,
		&ett_smb2_file_access_info,
		&ett_smb2_file_rename_info,
		&ett_smb2_file_disposition_info,
		&ett_smb2_file_position_info,
		&ett_smb2_file_info_0f,
		&ett_smb2_file_mode_info,
		&ett_smb2_file_alignment_info,
		&ett_smb2_file_all_info,
		&ett_smb2_file_allocation_info,
		&ett_smb2_file_endoffile_info,
		&ett_smb2_file_alternate_name_info,
		&ett_smb2_file_stream_info,
		&ett_smb2_file_compression_info,
		&ett_smb2_file_network_open_info,
		&ett_smb2_file_attribute_tag_info,
		&ett_smb2_fs_info_01,
		&ett_smb2_fs_info_03,
		&ett_smb2_fs_info_04,
		&ett_smb2_fs_info_05,
		&ett_smb2_fs_info_06,
		&ett_smb2_fs_info_07,
		&ett_smb2_fs_info_08,
		&ett_smb2_sec_info_00,
		&ett_smb2_tid_tree,
		&ett_smb2_create_flags,
		&ett_smb2_chain_element,
		&ett_smb2_MxAc_buffer,
		&ett_smb2_ioctl_function,
	};

	proto_smb2 = proto_register_protocol("SMB2 (Server Message Block Protocol version 2)",
	    "SMB2", "smb2");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_smb2, hf, array_length(hf));

	register_heur_dissector_list("smb2_heur_subdissectors", &smb2_heur_subdissector_list);
}

void
proto_reg_handoff_smb2(void)
{
	gssapi_handle = find_dissector("gssapi");
	heur_dissector_add("netbios", dissect_smb2_heur, proto_smb2);
}
