/* packet-dcerpc-srvsvc.c
 * Routines for SMB \\PIPE\\srvsvc packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 * Copyright 2002, Richard Sharpe <rsharpe@ns.aus.com>
 *   decode srvsvc calls where Samba knows them ...
 *
 * $Id: packet-dcerpc-srvsvc.c,v 1.19 2002/06/16 11:55:46 sahlberg Exp $
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
#include "packet-dcerpc-srvsvc.h"
#include "packet-dcerpc-nt.h"
#include "packet-smb-common.h"
#include "smb.h"

/*
 * Some private space for srvsvc
 */
typedef struct _srvsvc_info {
  guint32 switch_value;
  guint32 num_entries;
  guint32 num_pointers;
} srvsvc_info;

static int proto_dcerpc_srvsvc = -1;
static int hf_srvsvc_server = -1;
static int hf_srvsvc_user = -1;
static int hf_srvsvc_chrdev = -1;
static int hf_srvsvc_chrdev_time = -1;
static int hf_srvsvc_chrdev_status = -1;
static int hf_srvsvc_info_level = -1;
static int hf_srvsvc_info = -1;
static int hf_srvsvc_rc = -1;
static int hf_srvsvc_platform_id = -1;
static int hf_srvsvc_ver_major = -1;
static int hf_srvsvc_ver_minor = -1;
static int hf_srvsvc_server_type = -1;
static int hf_srvsvc_server_comment = -1;
static int hf_srvsvc_users = -1;
static int hf_srvsvc_hidden = -1;
static int hf_srvsvc_announce = -1;
static int hf_srvsvc_ann_delta = -1;
static int hf_srvsvc_licences = -1;
static int hf_srvsvc_user_path = -1;
static int hf_srvsvc_share = -1;
static int hf_srvsvc_share_info = -1;
static int hf_srvsvc_share_comment = -1;
static int hf_srvsvc_share_type = -1;
static int hf_srvsvc_switch_value = -1;
static int hf_srvsvc_num_entries = -1;
static int hf_srvsvc_num_pointers = -1;
static int hf_srvsvc_preferred_len = -1;
static int hf_srvsvc_enum_handle = -1;
static int hf_srvsvc_unknown_long = -1;
static int hf_srvsvc_unknown_bytes = -1;
static int hf_srvsvc_unknown_string = -1;

static gint ett_dcerpc_srvsvc = -1;
static gint ett_srvsvc_server_info = -1;
static gint ett_srvsvc_share_info = -1;
static gint ett_srvsvc_share_info_1 = -1;



static e_uuid_t uuid_dcerpc_srvsvc = {
        0x4b324fc8, 0x1670, 0x01d3,
        { 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88 }
};

static guint16 ver_dcerpc_srvsvc = 3;

static int
srvsvc_dissect_ENUM_HANDLE(tvbuff_t *tvb, int offset, 
			   packet_info *pinfo, proto_tree *tree, 
			   char *drep)
{

  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			      hf_srvsvc_enum_handle, 0);
  return offset;

}

static int
srvsvc_dissect_pointer_UNICODE_STRING(tvbuff_t *tvb, int offset, 
				      packet_info *pinfo, proto_tree *tree, 
				      char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset = dissect_ndr_nt_UNICODE_STRING_str(tvb, offset, pinfo, tree, 
						   drep);
	return offset;
}





/*
 * IDL typedef struct {
 * IDL   [string] [unique] wchar_t *dev;
 * IDL } CHARDEV_INFO_0;
 */
static int
srvsvc_dissect_CHARDEV_INFO_0(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Char Device",
		hf_srvsvc_chrdev, 0);
	
	return offset;
}
static int
srvsvc_dissect_CHARDEV_INFO_0_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEV_INFO_0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] CHARDEV_INFO_0 *devs;
 * IDL } CHARDEV_INFO_0_CONTAINER;
 */
static int
srvsvc_dissect_CHARDEV_INFO_0_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_CHARDEV_INFO_0_array, NDR_POINTER_UNIQUE,
		"CHARDEV_INFO_0 array:", -1, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   [string] [unique] wchar_t *dev;
 * IDL   long status;
 * IDL   [string] [unique] wchar_t *user;
 * IDL   long time;
 * IDL } CHARDEV_INFO_1;
 */
static int
srvsvc_dissect_CHARDEV_INFO_1(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Char Device",
		hf_srvsvc_chrdev, 0);
	
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_chrdev_status, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "User",
		hf_srvsvc_user, 0);

	/* XXX dont know how to decode this time field */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_chrdev_time, 0);

	return offset;
}
static int
srvsvc_dissect_CHARDEV_INFO_1_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEV_INFO_1);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] CHARDEV_INFO_1 *devs;
 * IDL } CHARDEV_INFO_1_CONTAINER;
 */
static int
srvsvc_dissect_CHARDEV_INFO_1_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_CHARDEV_INFO_1_array, NDR_POINTER_UNIQUE,
		"CHARDEV_INFO_1 array:", -1, 3);

	return offset;
}

/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(0)] [unique] CHARDEV_INFO_0_CONTAINER *dev0;
 * IDL   [case(1)] [unique] CHARDEV_INFO_1_CONTAINER *dev1;
 * IDL } CHARDEV_ENUM_UNION;
 */
static int
srvsvc_dissect_CHARDEV_ENUM_UNION(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	guint32 level;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEV_INFO_0_CONTAINER,
			NDR_POINTER_UNIQUE, "CHARDEV_INFO_0_CONTAINER:",
			-1, 0);
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEV_INFO_1_CONTAINER,
			NDR_POINTER_UNIQUE, "CHARDEV_INFO_1_CONTAINER:",
			-1, 0);
		break;
	}

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long Level;
 * IDL   CHARDEV_ENUM_UNION devs;
 * IDL } CHARDEV_ENUM_STRUCT;
 */
static int
srvsvc_dissect_CHARDEV_ENUM_STRUCT(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = srvsvc_dissect_CHARDEV_ENUM_UNION(tvb, offset, pinfo, tree, drep);

	return offset;
}

/* XXX dont know the out parameters. only the in parameters.
 *
 * IDL long NetrCharDevEnum(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [ref] CHARDEV_ENUM_STRUCT *devs,
 * IDL      [in] long PreferredMaximumLength,
 * IDL      [in] [unique] long *ResumeHandle
 * IDL );
*/
static int
srvsvc_dissect_netrchardevenum_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Server",
		hf_srvsvc_server, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_CHARDEV_ENUM_STRUCT,
		NDR_POINTER_REF, "CHARDEV_ENUM_STRUCT",
		-1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_preferred_len, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_ENUM_HANDLE,
		NDR_POINTER_UNIQUE, "Enum Handle", -1, 0);

	return offset;
}


/* new functions in order and with idl above this line */




/*
  IDL typedef struct {
  IDL    [unique] [string] wchar_t *share;
  IDL    long type;
  IDL    [unique] [string] wchar_t *comment;
  IDL } SHARE_INFO_1_item
*/
static int
srvsvc_dissect_SHARE_INFO_1_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
  
	dcerpc_info *di;

	di=pinfo->private_data;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "Share");
		tree = proto_item_add_subtree(item, ett_srvsvc_share_info_1);
	}

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
		"Share", hf_srvsvc_share, di->levels);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_share_type, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
		"Comment", hf_srvsvc_share_comment, 0);

	return offset;
}

static int
srvsvc_dissect_SRV_INFO_100_struct(tvbuff_t *tvb, int offset, 
				   packet_info *pinfo, proto_tree *tree, 
				   char *drep)
{

  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
			      hf_srvsvc_platform_id, NULL);

  offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
			       srvsvc_dissect_pointer_UNICODE_STRING,
			       NDR_POINTER_UNIQUE, "Server",
			       hf_srvsvc_server, 0);

  return offset;

}

static int
srvsvc_dissect_pointer_comment_UNICODE_STRING(tvbuff_t *tvb, int offset, 
					      packet_info *pinfo, 
					      proto_tree *tree, 
					      char *drep)
{
  offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			       srvsvc_dissect_pointer_UNICODE_STRING,
			       NDR_POINTER_UNIQUE, "Comment",
			       hf_srvsvc_server_comment, 0);

  return offset;

}

static int
srvsvc_dissect_SRV_INFO_101_struct(tvbuff_t *tvb, int offset, 
				   packet_info *pinfo, proto_tree *tree, 
				   char *drep)
{
  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
			      hf_srvsvc_platform_id, NULL);

  offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
			       srvsvc_dissect_pointer_UNICODE_STRING,
			       NDR_POINTER_PTR, "Server",
			       hf_srvsvc_server, 0);

  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
			      hf_srvsvc_ver_major, NULL);

  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
			      hf_srvsvc_ver_minor, NULL);

  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			      hf_srvsvc_server_type, NULL);

  offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
			       srvsvc_dissect_pointer_UNICODE_STRING,
			       NDR_POINTER_UNIQUE, "Comment",
			       hf_srvsvc_server_comment, 0);

  return offset;

}

/* Seems silly to cut and paste, but that is what I have done ... */
static int
srvsvc_dissect_SRV_INFO_102_struct(tvbuff_t *tvb, int offset, 
				   packet_info *pinfo, proto_tree *tree, 
				   char *drep)
{
  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
			      hf_srvsvc_platform_id, NULL);

  offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
			       srvsvc_dissect_pointer_UNICODE_STRING,
			       NDR_POINTER_PTR, "Server",
			       hf_srvsvc_server, 0);

  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
			      hf_srvsvc_ver_major, NULL);

  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
			      hf_srvsvc_ver_minor, NULL);

  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			      hf_srvsvc_server_type, NULL);

  offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
			       srvsvc_dissect_pointer_UNICODE_STRING,
			       NDR_POINTER_UNIQUE, "Comment",
			       hf_srvsvc_server_comment, 0);

  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
			      hf_srvsvc_users, NULL);

  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
			      hf_srvsvc_hidden, NULL);

  offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
			       srvsvc_dissect_pointer_UNICODE_STRING,
			       NDR_POINTER_UNIQUE, "User Path",
			       hf_srvsvc_user_path, 0);

  return offset;

}

static int
srvsvc_dissect_SVR_INFO_CTR(tvbuff_t *tvb, int offset, 
			    packet_info *pinfo, proto_tree *tree, 
			    char *drep)
{
  proto_item *item = NULL;
  proto_tree *stree = NULL;
  int old_offset = offset;
  guint level;

  if (tree) {
    item = proto_tree_add_text(tree, tvb, offset, -1, "Server Info:");
    stree = proto_item_add_subtree(item, ett_srvsvc_server_info);
  }

  /* [out] LONG switch_value */
  offset = dissect_ndr_uint32(tvb, offset, pinfo, stree, drep, 
			      hf_srvsvc_info_level, &level);

  /* [OUT] LONG pointer to info struct */

  switch (level) {
  case 100:
    offset = dissect_ndr_pointer(tvb, offset, pinfo, stree, drep,
				 srvsvc_dissect_SRV_INFO_100_struct,
				 NDR_POINTER_UNIQUE, "Info Level 100", -1, 0);

      break;

  case 101:
    offset = dissect_ndr_pointer(tvb, offset, pinfo, stree, drep,
				 srvsvc_dissect_SRV_INFO_101_struct,
				 NDR_POINTER_UNIQUE, "Info Level 101", -1, 0);

    break;

  case 102:
    offset = dissect_ndr_pointer(tvb, offset, pinfo, stree, drep,
				 srvsvc_dissect_SRV_INFO_102_struct,
				 NDR_POINTER_UNIQUE, "Info Level 102", -1, 0);

    break;

  }
 
  /* XXX - Should set the field here too ...*/
  proto_item_set_len(item, offset - old_offset);
  return offset;

}

static int
srvsvc_dissect_net_srv_get_info_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
  /* [in] UNICODE_STRING_2 *srv*/

  offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			       srvsvc_dissect_pointer_UNICODE_STRING,
			       NDR_POINTER_UNIQUE, "Server",
			       hf_srvsvc_server, 0);

  /* [in] ULONG level */ 
  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
			      hf_srvsvc_info_level, NULL);


  return offset;
}

static int
srvsvc_dissect_net_srv_get_info_reply(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{

  offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			       srvsvc_dissect_SVR_INFO_CTR, NDR_POINTER_REF,
			       "Info", hf_srvsvc_info, 0);

  /* [out] LONG response_code */
  offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep, 
			    hf_srvsvc_rc, NULL);

  return offset;
}

static int
srvsvc_dissect_net_share_get_info_rqst(tvbuff_t *tvb, int offset, 
				       packet_info *pinfo, proto_tree *tree, 
				       char *drep)
{
  /* [IN] UNICODE_STRING_2 *srv */
  offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			       srvsvc_dissect_pointer_UNICODE_STRING,
			       NDR_POINTER_UNIQUE, "Server",
			       hf_srvsvc_server, 0);

  /*
   * Construct a label for the string ...
   * [IN, REF] UNICODE_STRING_2 *share
   */
  offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			       srvsvc_dissect_pointer_UNICODE_STRING,
			       NDR_POINTER_REF, "Share",
			       hf_srvsvc_share, 0);

  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
			       hf_srvsvc_info_level, NULL);

  return offset;
}

static int
srvsvc_dissect_net_share_get_info_reply(tvbuff_t *tvb, int offset, 
					packet_info *pinfo, proto_tree *tree, 
					char *drep)
{
  int level;
  dcerpc_info *di = pinfo->private_data;

  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			      hf_srvsvc_info_level, &level);

  di->private_data = &level; /* Pass this on */

  offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			       srvsvc_dissect_SHARE_INFO_1_item, 
			       NDR_POINTER_UNIQUE, "Info", -1, 1);

  offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
			    hf_srvsvc_rc, NULL);
  return offset;
}


/*
  IDL typedef struct {
  IDL   long element_x;
  IDL   [size_is(element_x)] [unique] byte *element_y;
  IDL } TYPE_4;
*/
static int
srvsvc_dissect_TYPE_4_data(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint32 len;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* this call is to make ethereal eat the array header for the conformant run */
		offset =dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, NULL);

		return offset;
	}
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_unknown_long, &len);

	proto_tree_add_item(tree, hf_srvsvc_unknown_bytes, tvb, offset, len,
		FALSE);
	offset += len;

	return len;
}
static int
srvsvc_dissect_TYPE_4(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_TYPE_4_data, NDR_POINTER_UNIQUE,
		"unknown TYPE_4", -1, -1);

	return offset;
}

/*
  IDL typedef struct {
  IDL   long element_5;
  IDL   [size_is(element_5)] [unique] byte *element_6;
  IDL } TYPE_3;
*/
static int
srvsvc_dissect_TYPE_3_data(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint32 len;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* this call is to make ethereal eat the array header for the conformant run */
		offset =dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, NULL);

		return offset;
	}
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_unknown_long, &len);

	proto_tree_add_item(tree, hf_srvsvc_unknown_bytes, tvb, offset, len,
		FALSE);
	offset += len;

	return len;
}
static int
srvsvc_dissect_TYPE_3(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_TYPE_3_data, NDR_POINTER_UNIQUE,
		"unknown TYPE_3", -1, -1);

	return offset;
}

static int
srvsvc_dissect_SHARE_INFO_1_array(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1_item);


	return offset;
}
/*
  IDL typedef struct {
  IDL   long num_shares;
  IDL   [size_is(element_x)] [unique] SHARE_INFO_1_item *shares;
  IDL } SHARE_INFO_1;
*/
static int
srvsvc_dissect_SHARE_INFO_1(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SHARE_INFO_1_array, NDR_POINTER_UNIQUE,
		"SHARE_INFO_1 array:", -1, 3);

	return offset;
}
/*
  IDL typedef struct {
  IDL   long element_x;
  IDL   [size_is(element_x)] [unique] byte *element_y;
  IDL } TYPE_37;
*/
static int
srvsvc_dissect_TYPE_37_data(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint32 len;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* this call is to make ethereal eat the array header for the conformant run */
		offset =dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, NULL);

		return offset;
	}
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_unknown_long, &len);

	proto_tree_add_item(tree, hf_srvsvc_unknown_bytes, tvb, offset, len,
		FALSE);
	offset += len;

	return offset;
}
static int
srvsvc_dissect_TYPE_37(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_TYPE_37_data, NDR_POINTER_UNIQUE,
		"unknown TYPE_37", -1, -1);

	return offset;
}

/*
  IDL typedef struct {
  IDL   long element_x;
  IDL   [size_is(element_x)] [unique] byte *element_y;
  IDL } TYPE_38;
*/
static int
srvsvc_dissect_TYPE_38_data(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	guint32 len;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* this call is to make ethereal eat the array header for the conformant run */
		offset =dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, NULL);

		return offset;
	}
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_unknown_long, &len);

	proto_tree_add_item(tree, hf_srvsvc_unknown_bytes, tvb, offset, len,
		FALSE);
	offset += len;

	return offset;
}
static int
srvsvc_dissect_TYPE_38(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_unknown_long, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_TYPE_38_data, NDR_POINTER_UNIQUE,
		"unknown TYPE_38", -1, -1);

	return offset;
}

/*
 IDL typedef [switch_type(long)] union {
 IDL   [case(0)] [unique] TYPE_3 *element_168;
 IDL   [case(1)] [unique] SHARE_INFO_1 *element_169;
 IDL   [case(2)] [unique] TYPE_37 *element_170;
 IDL   [case(502)] [unique] TYPE_38 *element_171;
 IDL   [case(501)] [unique] TYPE_4 *element_172;
 IDL } SHARE_INFO;
*/
static int
srvsvc_dissect_SHARE_INFO(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, char *drep)
{
	guint32 level;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_TYPE_3,
			NDR_POINTER_UNIQUE, "TYPE_3:",
			-1, 0);
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1:",
			-1, 1);
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_TYPE_37,
			NDR_POINTER_UNIQUE, "TYPE_37:",
			-1, 0);
		break;
	case 502:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_TYPE_38,
			NDR_POINTER_UNIQUE, "TYPE_38:",
			-1, 0);
		break;
	case 501:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_TYPE_4,
			NDR_POINTER_UNIQUE, "TYPE_4:",
			-1, 0);
		break;
	}

	return offset;
}

static int
srvsvc_dissect_netshareenum_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
  offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			       srvsvc_dissect_pointer_UNICODE_STRING,
			       NDR_POINTER_UNIQUE, "Share",
			       hf_srvsvc_share, 0);

  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			      hf_srvsvc_info_level, 0);

  offset = srvsvc_dissect_SHARE_INFO(tvb, offset, pinfo, tree, drep);

  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			      hf_srvsvc_preferred_len, 0);

  offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			       srvsvc_dissect_ENUM_HANDLE,
			       NDR_POINTER_UNIQUE, "Enum Handle", -1, 0);

  return offset;
}

static int
srvsvc_dissect_netshareenum_reply(tvbuff_t *tvb, int offset, 
				      packet_info *pinfo, proto_tree *tree, 
				      char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO,
			NDR_POINTER_REF, "SHARE_INFO", -1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_ENUM_HANDLE,
			NDR_POINTER_UNIQUE, "Enum Handle", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

static dcerpc_sub_dissector dcerpc_srvsvc_dissectors[] = {
	{SRV_NETRCHARDEVENUM,		"NetrCharDevEnum",
		srvsvc_dissect_netrchardevenum_rqst,
		NULL},
	{SRV_NETRCHARDEVGETINFO,	"NetrCharDevGetInfo", NULL, NULL},
	{SRV_NETRCHARDEVCONTROL,	"NetrCharDevControl", NULL, NULL},
	{SRV_NETRCHARDEVQENUM,		"NetrCharDevQEnum", NULL, NULL},
	{SRV_NETRCHARDEVQGETINFO,	"NetrCharDevQGetInfo", NULL, NULL},
	{SRV_NETRCHARDEVQSETINFO,	"NetrCharDevQSetInfo", NULL, NULL},
	{SRV_NETRCHARDEVQPURGE,		"NetrCharDevQPurge", NULL, NULL},
	{SRV_NETRCHARDEVQPURGESELF,	"NetrCharDevQPurgeSelf", NULL, NULL},
	{SRV_NETRCONNECTIONENUM,	"NetrConnectionEnum", NULL, NULL},
	{SRV_NETRFILEENUM,		"NetrFileEnum", NULL, NULL},
	{SRV_NETRFILEGETINFO,		"NetrFileGetInfo", NULL, NULL},
	{SRV_NETRFILECLOSE,		"NetrFileClose", NULL, NULL},
	{SRV_NETRSESSIONENUM,		"NetrSessionEnum", NULL, NULL},
	{SRV_NETRSESSIONDEL,		"NetrSessionDel", NULL, NULL},
	{SRV_NETRSHAREADD,		"NetrShareAdd", NULL, NULL},
	{SRV_NETRSHAREENUM,		"NetrShareEnum",
		srvsvc_dissect_netshareenum_rqst,
		srvsvc_dissect_netshareenum_reply},
	{SRV_NETRSHAREGETINFO,		"NetrShareGetInfo",
		srvsvc_dissect_net_share_get_info_rqst,
		srvsvc_dissect_net_share_get_info_reply},
	{SRV_NETRSHARESETINFO,		"NetrShareSetInfo", NULL, NULL},
	{SRV_NETRSHAREDEL,		"NetrShareDel", NULL, NULL},
	{SRV_NETRSHAREDELSTICKY,	"NetrShareDelSticky", NULL, NULL},
	{SRV_NETRSHARECHECK,		"NetrShareCheck", NULL, NULL},
	{SRV_NETRSERVERGETINFO,		"NetrServerGetInfo",
		srvsvc_dissect_net_srv_get_info_rqst, 
		srvsvc_dissect_net_srv_get_info_reply},
	{SRV_NETRSERVERSETINFO,		"NetrServerSetInfo", NULL, NULL},
	{SRV_NETRSERVERDISKENUM,	"NetrServerDiskEnum", NULL, NULL},
	{SRV_NETRSERVERSTATISTICSGET,	"NetrServerStatisticsGet", NULL, NULL},
	{SRV_NETRSERVERTRANSPORTADD,	"NetrServerTransportAdd", NULL, NULL},
	{SRV_NETRSERVERTRANSPORTENUM,	"NetrServerTransportEnum", NULL, NULL},
	{SRV_NETRSERVERTRANSPORTDEL,	"NetrServerTransportDel", NULL, NULL},
	{SRV_NETRREMOTETOD,		"NetrRemoteTOD", NULL, NULL},
	{SRV_NETRSERVERSETSERVICEBITS,	"NetrServerSetServiceBits", NULL, NULL},
	{SRV_NETRPRPATHTYPE,		"NetrpPathType", NULL, NULL},
	{SRV_NETRPRPATHCANONICALIZE,	"NetrpPathCanonicalize", NULL, NULL},
	{SRV_NETRPRPATHCOMPARE,		"NetrpPathCompare", NULL, NULL},
	{SRV_NETRPRNAMEVALIDATE,	"NetrpNameValidate", NULL, NULL},
	{SRV_NETRPRNAMECANONICALIZE,	"NetrpNameCanonicalize", NULL, NULL},
	{SRV_NETRPRNAMECOMPARE,		"NetrpNameCompare", NULL, NULL},
	{SRV_NETRSHAREENUMSTICKY,	"NetrShareEnumSticky", NULL, NULL},
	{SRV_NETRSHAREDELSTART,		"NetrShareDelStart", NULL, NULL},
	{SRV_NETRSHAREDELCOMMIT,	"NetrShareDelCommit", NULL, NULL},
	{SRV_NETRPGETFILESECURITY,	"NetrpGetFileSecurity", NULL, NULL},
	{SRV_NETRPSETFILESECURITY,	"NetrpSetFileSecurity", NULL, NULL},
	{SRV_NETRSERVERTRANSPORTADDEX,	"NetrServerTransportAddEx", NULL, NULL},
	{SRV_NETRSERVERSETSERVICEBITS2,	"NetrServerSetServiceBits2", NULL, NULL},
	{0, NULL, NULL, NULL}
};

static const value_string platform_id_vals[] = {
	{ 300, "DOS" },
	{ 400, "OS/2" },
	{ 500, "Windows NT" },
	{ 600, "OSF" },
	{ 700, "VMS" },
	{ 0,   NULL }
};

void 
proto_register_dcerpc_srvsvc(void)
{
        static hf_register_info hf[] = {
	  { &hf_srvsvc_server,
	    { "Server", "srvsvc.server", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Server Name", HFILL}},
	  { &hf_srvsvc_chrdev,
	    { "Char Device", "srvsvc.chrdev", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Char Device Name", HFILL}},
	  { &hf_srvsvc_user,
	    { "User", "srvsvc.user", FT_STRING, BASE_NONE,
	    NULL, 0x0, "User Name", HFILL}},
	  { &hf_srvsvc_chrdev_status,
	    { "Status", "srvsvc.chrdev_status", FT_UINT32, BASE_HEX,
	    NULL, 0x0, "Char Device Status", HFILL}},
	  { &hf_srvsvc_chrdev_time,
	    { "Time", "srvsvc.chrdev_time", FT_UINT32, BASE_DEC,
	    NULL, 0x0, "Char Device Time?", HFILL}},
	  { &hf_srvsvc_info_level,
	    { "Info Level", "svrsvc.info_level", FT_UINT32, 
	    BASE_DEC, NULL, 0x0, "Info Level", HFILL}},
	  { &hf_srvsvc_info,
	    { "Info Structure", "srvsvc.info_struct", FT_BYTES,
	    BASE_HEX, NULL, 0x0, "Info Structure", HFILL}},
	  { &hf_srvsvc_rc,
	    { "Return code", "srvsvc.rc", FT_UINT32, 
	      BASE_HEX, VALS(NT_errors), 0x0, "Return Code", HFILL}},

	  { &hf_srvsvc_platform_id,
	    { "Platform ID", "srvsvc.info.platform_id", FT_UINT32,
	      BASE_DEC, VALS(platform_id_vals), 0x0, "Platform ID", HFILL}},
	  { &hf_srvsvc_ver_major,
	    { "Major Version", "srvsvc.version.major", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Major Version", HFILL}},
	  { &hf_srvsvc_ver_minor,
	    { "Minor Version", "srvsvc.version.minor", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Minor Version", HFILL}},
	  /* XXX - Should break this out. We know it from browsing. */
	  { &hf_srvsvc_server_type,
	    { "Server Type", "srvsvc.server.type", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Server Type", HFILL}},
	  { &hf_srvsvc_server_comment, 
	    { "Server Comment", "srvsvc.server.comment", FT_STRING,
	      BASE_NONE, NULL, 0x0, "Server Comment String", HFILL}},
	  { &hf_srvsvc_users,
	    { "Users", "srvsvc.users", FT_UINT32,
	      BASE_DEC, NULL, 0x0 , "User Count", HFILL}},
	  { &hf_srvsvc_hidden,
	    { "Hidden", "srvsvc.hidden", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Hidden", HFILL}},
	  { &hf_srvsvc_announce,
	    { "Announce", "srvsvc.announce", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Announce", HFILL }},
	  { &hf_srvsvc_ann_delta,
	    { "Announce Delta", "srvsvc.ann_delta", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Announce Delta", HFILL}},
	  { &hf_srvsvc_licences,
	    { "Licences", "srvsvc.licences", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Licences", HFILL}},
	  { &hf_srvsvc_user_path,
	    { "User Path", "srvsvc.user_path", FT_STRING,
	      BASE_NONE, NULL, 0x0, "User Path", HFILL}},
	  { &hf_srvsvc_share, 
	    { "Share", "srvsvc.share", FT_STRING,
	      BASE_NONE, NULL, 0x0, "Share", HFILL}},
	  { &hf_srvsvc_share_info,
	    { "Share Info", "srvsvc.share_info", FT_BYTES,
	      BASE_HEX, NULL, 0x0, "Share Info", HFILL}},
	  { &hf_srvsvc_share_comment,
	    { "Share Comment", "srvsvc.share_comment", FT_STRING,
	      BASE_NONE, NULL, 0x0, "Share Comment", HFILL}},
	  { &hf_srvsvc_share_type,
	    { "Share Type", "srvsvc.share_type", FT_UINT32, 
	      BASE_HEX, VALS(share_type_vals), 0x0, "Share Type", HFILL}},
	  { &hf_srvsvc_switch_value,
	    { "Switch Value", "srvsvc.switch_val", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Switch Value", HFILL}},
	  { &hf_srvsvc_num_entries,
	    { "Number of entries", "srvsvc.share.num_entries", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of Entries", HFILL}},
	  { &hf_srvsvc_num_pointers,
	    { "Pointer entries", "srvsvc.share.pointer_entries", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Pointer Entries", HFILL}},
	  { &hf_srvsvc_preferred_len,
	    { "Preferred length", "srvsvc.preferred_len", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Preferred Length", HFILL}},
	  { &hf_srvsvc_enum_handle, 
	    { "Enumeration handle", "srvsvc.enum_hnd", FT_BYTES,
	      BASE_HEX, NULL, 0x0, "Enumeration Handle", HFILL}},
          { &hf_srvsvc_unknown_long,
            { "Unknown long", "srvsvc.unknown.long", FT_UINT32, BASE_HEX, 
              NULL, 0x0, "Unknown long. If you know what this is, contact ethereal developers.", HFILL }},
          { &hf_srvsvc_unknown_bytes,
            { "Unknown bytes", "srvsvc.unknown.bytes", FT_BYTES, BASE_HEX, 
              NULL, 0x0, "Unknown bytes. If you know what this is, contact ethereal developers.", HFILL }},
          { &hf_srvsvc_unknown_string,
            { "Unknown string", "srvsvc.unknown.string", FT_STRING, BASE_HEX, 
              NULL, 0x0, "Unknown string. If you know what this is, contact ethereal developers.", HFILL }},
	};

        static gint *ett[] = {
                &ett_dcerpc_srvsvc,
		&ett_srvsvc_server_info,
		&ett_srvsvc_share_info,
		&ett_srvsvc_share_info_1
        };

        proto_dcerpc_srvsvc = proto_register_protocol(
                "Microsoft Server Service", "SRVSVC", "srvsvc");

	proto_register_field_array(proto_dcerpc_srvsvc, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_srvsvc(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_srvsvc, ett_dcerpc_srvsvc, 
                         &uuid_dcerpc_srvsvc, ver_dcerpc_srvsvc, 
                         dcerpc_srvsvc_dissectors);
}
