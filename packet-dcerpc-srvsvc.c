/* packet-dcerpc-srvsvc.c
 * Routines for SMB \\PIPE\\srvsvc packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 * Copyright 2002, Richard Sharpe <rsharpe@ns.aus.com>
 *   decode srvsvc calls where Samba knows them ...
 *
 * $Id: packet-dcerpc-srvsvc.c,v 1.26 2002/06/19 09:59:42 sahlberg Exp $
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
#include "packet-dcerpc-lsa.h"
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
static int hf_srvsvc_reserved = -1;
static int hf_srvsvc_server = -1;
static int hf_srvsvc_transport = -1;
static int hf_srvsvc_session = -1;
static int hf_srvsvc_session_num_opens = -1;
static int hf_srvsvc_session_time = -1;
static int hf_srvsvc_session_idle_time = -1;
static int hf_srvsvc_session_user_flags = -1;
static int hf_srvsvc_qualifier = -1;
static int hf_srvsvc_computer = -1;
static int hf_srvsvc_user = -1;
static int hf_srvsvc_path = -1;
static int hf_srvsvc_share_passwd = -1;
static int hf_srvsvc_file_id = -1;
static int hf_srvsvc_perm = -1;
static int hf_srvsvc_file_num_locks = -1;
static int hf_srvsvc_con_id = -1;
static int hf_srvsvc_max_uses = -1;
static int hf_srvsvc_cur_uses = -1;
static int hf_srvsvc_con_time = -1;
static int hf_srvsvc_con_type = -1;
static int hf_srvsvc_con_num_opens = -1;
static int hf_srvsvc_con_num_users = -1;
static int hf_srvsvc_chrqpri = -1;
static int hf_srvsvc_chrqnumusers = -1;
static int hf_srvsvc_chrqnumahead = -1;
static int hf_srvsvc_chrdev = -1;
static int hf_srvsvc_chrdevq = -1;
static int hf_srvsvc_chrdev_time = -1;
static int hf_srvsvc_chrdev_status = -1;
static int hf_srvsvc_chrdev_opcode = -1;
static int hf_srvsvc_info_level = -1;
static int hf_srvsvc_info = -1;
static int hf_srvsvc_rc = -1;
static int hf_srvsvc_platform_id = -1;
static int hf_srvsvc_ver_major = -1;
static int hf_srvsvc_ver_minor = -1;
static int hf_srvsvc_server_type = -1;
static int hf_srvsvc_client_type = -1;
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
static int hf_srvsvc_parm_error = -1;
static int hf_srvsvc_enum_handle = -1;
static int hf_srvsvc_unknown_long = -1;
static int hf_srvsvc_unknown_bytes = -1;
static int hf_srvsvc_unknown_string = -1;

static gint ett_dcerpc_srvsvc = -1;
static gint ett_srvsvc_server_info = -1;
static gint ett_srvsvc_share_info = -1;
static gint ett_srvsvc_share_info_1 = -1;
static gint ett_srvsvc_share_info_2 = -1;
static gint ett_srvsvc_share_info_502 = -1;



static e_uuid_t uuid_dcerpc_srvsvc = {
        0x4b324fc8, 0x1670, 0x01d3,
        { 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88 }
};

static guint16 ver_dcerpc_srvsvc = 3;

static int
srvsvc_dissect_pointer_long(tvbuff_t *tvb, int offset, 
                             packet_info *pinfo, proto_tree *tree, 
                             char *drep)
{
	dcerpc_info *di;

	di=pinfo->private_data;
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     di->hf_index, NULL);
	return offset;
}

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


/* XXX dont know the out parameters. only the in parameters.
 *
 * IDL long NetrCharDevEnum(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *DevName,
 * IDL      [in] long Level 
 * IDL );
*/
static int
srvsvc_dissect_netrchardevgetinfo_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Server",
		hf_srvsvc_server, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_REF, "Char Device",
		hf_srvsvc_chrdev, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	return offset;
}
/* XXX dont know the out parameters. only the in parameters.
 *
 * IDL long NetrCharDevControl(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *DevName,
 * IDL      [in] long Opcode 
 * IDL );
*/
static int
srvsvc_dissect_netrchardevcontrol_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Server",
		hf_srvsvc_server, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_REF, "Char Device",
		hf_srvsvc_chrdev, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_chrdev_opcode, 0);

	return offset;
}



/*
 * IDL typedef struct {
 * IDL   [string] [unique] wchar_t *dev;
 * IDL } CHARDEVQ_INFO_0;
 */
static int
srvsvc_dissect_CHARDEVQ_INFO_0(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Char QDevice",
		hf_srvsvc_chrdev, 0);
	
	return offset;
}
static int
srvsvc_dissect_CHARDEVQ_INFO_0_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEVQ_INFO_0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] CHARDEVQ_INFO_0 *devs;
 * IDL } CHARDEVQ_INFO_0_CONTAINER;
 */
static int
srvsvc_dissect_CHARDEVQ_INFO_0_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_CHARDEVQ_INFO_0_array, NDR_POINTER_UNIQUE,
		"CHARDEVQ_INFO_0 array:", -1, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   [string] [unique] wchar_t *dev;
 * IDL   long priority;
 * IDL   [string] [unique] wchar_t *devs;
 * IDL   long num_users;
 * IDL   long num_ahead;
 * IDL } CHARDEVQ_INFO_1;
 */
static int
srvsvc_dissect_CHARDEVQ_INFO_1(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Char Device",
		hf_srvsvc_chrdev, 0);
	
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_chrqpri, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Char Devices",
		hf_srvsvc_chrdevq, 0);
	
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_chrqnumusers, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_chrqnumahead, 0);

	return offset;
}
static int
srvsvc_dissect_CHARDEVQ_INFO_1_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEVQ_INFO_1);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] CHARDEVQ_INFO_1 *devs;
 * IDL } CHARDEVQ_INFO_1_CONTAINER;
 */
static int
srvsvc_dissect_CHARDEVQ_INFO_1_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_CHARDEVQ_INFO_1_array, NDR_POINTER_UNIQUE,
		"CHARDEVQ_INFO_1 array:", -1, 3);

	return offset;
}

/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(0)] [unique] CHARDEVQ_INFO_0_CONTAINER *dev0;
 * IDL   [case(1)] [unique] CHARDEVQ_INFO_1_CONTAINER *dev1;
 * IDL } CHARDEVQ_ENUM_UNION;
 */
static int
srvsvc_dissect_CHARDEVQ_ENUM_UNION(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	guint32 level;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEVQ_INFO_0_CONTAINER,
			NDR_POINTER_UNIQUE, "CHARDEVQ_INFO_0_CONTAINER:",
			-1, 0);
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEVQ_INFO_1_CONTAINER,
			NDR_POINTER_UNIQUE, "CHARDEVQ_INFO_1_CONTAINER:",
			-1, 0);
		break;
	}

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long Level;
 * IDL   CHARDEVQ_ENUM_UNION devs;
 * IDL } CHARDEVQ_ENUM_STRUCT;
 */
static int
srvsvc_dissect_CHARDEVQ_ENUM_STRUCT(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = srvsvc_dissect_CHARDEVQ_ENUM_UNION(tvb, offset, pinfo, tree, drep);

	return offset;
}

/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(0)] [unique] CHARDEVQ_INFO_0 *dev0;
 * IDL   [case(1)] [unique] CHARDEVQ_INFO_1 *dev1;
 * IDL } CHARDEVQ_INFO;
 */
static int
srvsvc_dissect_CHARDEVQ_INFO(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	guint32 level;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEVQ_INFO_0,
			NDR_POINTER_UNIQUE, "CHARDEVQ_INFO_0:",
			-1, 0);
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEVQ_INFO_1,
			NDR_POINTER_UNIQUE, "CHARDEVQ_INFO_1:",
			-1, 0);
		break;
	}

	return offset;
}


/* XXX dont know the out parameters. only the in parameters.
 *
 * IDL long NetrCharDevQEnum(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [unique] wchar_t *UserName,
 * IDL      [in] [ref] CHARDEVQ_ENUM_STRUCT *devs,
 * IDL      [in] long PreferredMaximumLength,
 * IDL      [in] [unique] long *ResumeHandle
 * IDL );
*/
static int
srvsvc_dissect_netrchardevqenum_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Server",
		hf_srvsvc_server, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "User",
		hf_srvsvc_user, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_CHARDEVQ_ENUM_STRUCT,
		NDR_POINTER_REF, "CHARDEVQ_ENUM_STRUCT",
		-1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_preferred_len, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_ENUM_HANDLE,
		NDR_POINTER_UNIQUE, "Enum Handle", -1, 0);

	return offset;
}

/* XXX dont know the out parameters. only the in parameters.
 *
 * IDL long NetrCharDevQGetInfo(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *QueueName,
 * IDL      [in] [string] [ref] wchar_t *UserName,
 * IDL      [in] long Level
 * IDL );
*/
static int
srvsvc_dissect_netrchardevqgetinfo_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Server",
		hf_srvsvc_server, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_REF, "Device Queue",
		hf_srvsvc_chrdevq, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_REF, "User",
		hf_srvsvc_user, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
		hf_srvsvc_info_level, NULL);

	return offset;
}

/* XXX dont know the out parameters. only the in parameters.
 *
 * IDL long NetrCharDevQSetInfo(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *QueueName,
 * IDL      [in] long Level,
 * IDL      [in] [ref] CHARDEVQ_INFO *dev,
 * IDL      [in] [unique] long *ParmError
 * IDL );
*/
static int
srvsvc_dissect_netrchardevqsetinfo_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Server",
		hf_srvsvc_server, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_REF, "Device Queue",
		hf_srvsvc_chrdevq, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, 
		hf_srvsvc_info_level, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_CHARDEVQ_INFO,
		NDR_POINTER_REF, "CHARDEVQ_INFO",
		-1, 0);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_pointer_long, NDR_POINTER_UNIQUE,
			"Parameter Error:", hf_srvsvc_parm_error, 0);

	return offset;
}

/* XXX dont know the out parameters. only the in parameters.
 *
 * IDL long NetrCharDevQPurge(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *QueueName
 * IDL );
*/
static int
srvsvc_dissect_netrchardevqpurge_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Server",
		hf_srvsvc_server, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_REF, "Device Queue",
		hf_srvsvc_chrdevq, 0);

	return offset;
}

/* XXX dont know the out parameters. only the in parameters.
 *
 * IDL long NetrCharDevQPurge(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *QueueName
 * IDL      [in] [string] [ref] wchar_t *ComputerName
 * IDL );
*/
static int
srvsvc_dissect_netrchardevqpurgeself_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Server",
		hf_srvsvc_server, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_REF, "Device Queue",
		hf_srvsvc_chrdevq, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_REF, "Computer",
		hf_srvsvc_computer, 0);

	return offset;
}



/*
 * IDL typedef struct {
 * IDL   long con_id;
 * IDL } CONNECT_INFO_0;
 */
static int
srvsvc_dissect_CONNECT_INFO_0(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_con_id, NULL);
	
	return offset;
}
static int
srvsvc_dissect_CONNECT_INFO_0_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CONNECT_INFO_0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] CONNECT_INFO_0 *cons;
 * IDL } CONNECT_INFO_0_CONTAINER;
 */
static int
srvsvc_dissect_CONNECT_INFO_0_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_CONNECT_INFO_0_array, NDR_POINTER_UNIQUE,
		"CONNECT_INFO_0 array:", -1, 0);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   long conid;
 * IDL   long type;
 * IDL   long num_opens;
 * IDL   long num_users;
 * IDL   long time;
 * IDL   [string] [unique] wchar_t *username;
 * IDL   [string] [unique] wchar_t *share;
 * IDL } CONNECT_INFO_1;
 */
static int
srvsvc_dissect_CONNECT_INFO_1(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_con_id, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_con_type, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_con_num_opens, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_con_num_users, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_con_time, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "User",
		hf_srvsvc_user, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Share",
		hf_srvsvc_share, 0);

	return offset;
}
static int
srvsvc_dissect_CONNECT_INFO_1_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CONNECT_INFO_1);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] CONNECT_INFO_0 *cons;
 * IDL } CONNECT_INFO_1_CONTAINER;
 */
static int
srvsvc_dissect_CONNECT_INFO_1_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_CONNECT_INFO_1_array, NDR_POINTER_UNIQUE,
		"CONNECT_INFO_1 array:", -1, 0);

	return offset;
}


/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(0)] [unique] CONNECT_INFO_0_CONTAINER *con0;
 * IDL   [case(1)] [unique] CONNECT_INFO_1_CONTAINER *con1;
 * IDL } CONNECT_ENUM_UNION;
 */
static int
srvsvc_dissect_CONNECT_ENUM_UNION(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	guint32 level;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CONNECT_INFO_0_CONTAINER,
			NDR_POINTER_UNIQUE, "CONNECT_INFO_0_CONTAINER:",
			-1, 0);
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CONNECT_INFO_1_CONTAINER,
			NDR_POINTER_UNIQUE, "CONNECT_INFO_1_CONTAINER:",
			-1, 0);
		break;
	}

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   long Level;
 * IDL   CONNECT_ENUM_UNION devs;
 * IDL } CONNECT_ENUM_STRUCT;
 */
static int
srvsvc_dissect_CONNECT_ENUM_STRUCT(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = srvsvc_dissect_CONNECT_ENUM_UNION(tvb, offset, pinfo, tree, drep);

	return offset;
}


/* XXX dont know the out parameters. only the in parameters.
 *
 * IDL long NetrConnectionEnum(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [unique] wchar_t *Qualifier,
 * IDL      [in] [ref] CONNECT_ENUM_STRUCT *con,
 * IDL      [in] long MaxLen,
 * IDL      [in] [unique] long *ResumeHandle
 * IDL );
*/
static int
srvsvc_dissect_netrconnectionenum_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Server",
		hf_srvsvc_server, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Qualifier",
		hf_srvsvc_qualifier, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_CONNECT_ENUM_STRUCT,
		NDR_POINTER_REF, "CONNECT_ENUM_STRUCT:",
		-1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_preferred_len, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_ENUM_HANDLE,
		NDR_POINTER_UNIQUE, "Enum Handle", -1, 0);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   long fileid;
 * IDL } FILE_INFO_2;
 */
static int
srvsvc_dissect_FILE_INFO_2(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_file_id, NULL);
	
	return offset;
}
static int
srvsvc_dissect_FILE_INFO_2_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_FILE_INFO_2);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] FILE_INFO_2 *files;
 * IDL } FILE_INFO_2_CONTAINER;
 */
static int
srvsvc_dissect_FILE_INFO_2_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_FILE_INFO_2_array, NDR_POINTER_UNIQUE,
		"FILE_INFO_2 array:", -1, 0);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   long file_id;
 * IDL   long permissions;
 * IDL   long num_locks;
 * IDL   [string] [unique] wchar_t *pathname;
 * IDL   [string] [unique] wchar_t *username;
 * IDL } FILE_INFO_3;
 */
static int
srvsvc_dissect_FILE_INFO_3(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_file_id, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_perm, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_file_num_locks, NULL);
	
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Path",
		hf_srvsvc_path, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "User",
		hf_srvsvc_user, 0);

	return offset;
}
static int
srvsvc_dissect_FILE_INFO_3_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_FILE_INFO_3);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] FILE_INFO_3 *files;
 * IDL } FILE_INFO_3_CONTAINER;
 */
static int
srvsvc_dissect_FILE_INFO_3_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_FILE_INFO_3_array, NDR_POINTER_UNIQUE,
		"CHARDEV_INFO_3 array:", -1, 0);

	return offset;
}


/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(2)] [unique] FILE_INFO_2_CONTAINER *file0;
 * IDL   [case(3)] [unique] FILE_INFO_3_CONTAINER *file1;
 * IDL } FILE_ENUM_UNION;
 */
static int
srvsvc_dissect_FILE_ENUM_UNION(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	guint32 level;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_FILE_INFO_2_CONTAINER,
			NDR_POINTER_UNIQUE, "FILE_INFO_2_CONTAINER:",
			-1, 0);
		break;
	case 3:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_FILE_INFO_3_CONTAINER,
			NDR_POINTER_UNIQUE, "FILE_INFO_3_CONTAINER:",
			-1, 0);
		break;
	}

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   long Level;
 * IDL   FILE_ENUM_UNION files;
 * IDL } FILE_ENUM_STRUCT;
 */
static int
srvsvc_dissect_FILE_ENUM_STRUCT(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = srvsvc_dissect_FILE_ENUM_UNION(tvb, offset, pinfo, tree, drep);

	return offset;
}


/* XXX dont know the out parameters. only the in parameters.
 *
 * IDL long NetrFileEnum(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [unique] wchar_t *Path,
 * IDL      [in] [string] [unique] wchar_t *UserName,
 * IDL      [in] [ref] FILE_ENUM_STRUCT *file,
 * IDL      [in] long MaxLen,
 * IDL      [in] [unique] long *ResumeHandle
 * IDL );
*/
static int
srvsvc_dissect_netrfileenum_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Server",
		hf_srvsvc_server, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Path",
		hf_srvsvc_path, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "User",
		hf_srvsvc_user, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_FILE_ENUM_STRUCT,
		NDR_POINTER_REF, "FILE_ENUM_STRUCT:",
		-1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_preferred_len, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_ENUM_HANDLE,
		NDR_POINTER_UNIQUE, "Enum Handle", -1, 0);

	return offset;
}


/* XXX dont know the out parameters. only the in parameters.
 *
 * IDL long NetrFileGetInfo(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long fileid,
 * IDL      [in] long level,
 * IDL );
*/
static int
srvsvc_dissect_netrfilegetinfo_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Server",
		hf_srvsvc_server, 0);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_file_id, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	return offset;
}


/* XXX dont know the out parameters. only the in parameters.
 *
 * IDL long NetrFileClose(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long fileid,
 * IDL );
*/
static int
srvsvc_dissect_netrfileclose_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Server",
		hf_srvsvc_server, 0);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_file_id, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   [string] [unique] wchar_t *ses;
 * IDL } SESSION_INFO_0;
 */
static int
srvsvc_dissect_SESSION_INFO_0(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Session",
		hf_srvsvc_session, 0);
	
	return offset;
}
static int
srvsvc_dissect_SESSION_INFO_0_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SESSION_INFO_0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] SESSION_INFO_0 *ses;
 * IDL } SESSION_INFO_0_CONTAINER;
 */
static int
srvsvc_dissect_SESSION_INFO_0_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SESSION_INFO_0_array, NDR_POINTER_UNIQUE,
		"SESSION_INFO_0 array:", -1, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   [string] [unique] wchar_t *ses;
 * IDL   [string] [unique] wchar_t *user;
 * IDL   long num_open;
 * IDL   long time;
 * IDL   long idle_time;
 * IDL   long user_flags
 * IDL } SESSION_INFO_1;
 */
static int
srvsvc_dissect_SESSION_INFO_1(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Session",
		hf_srvsvc_session, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "User",
		hf_srvsvc_user, 0);
	
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_num_opens, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_time, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_idle_time, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_user_flags, NULL);

	return offset;
}
static int
srvsvc_dissect_SESSION_INFO_1_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SESSION_INFO_1);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] SESSION_INFO_1 *ses;
 * IDL } SESSION_INFO_1_CONTAINER;
 */
static int
srvsvc_dissect_SESSION_INFO_1_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SESSION_INFO_1_array, NDR_POINTER_UNIQUE,
		"SESSION_INFO_1 array:", -1, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   [string] [unique] wchar_t *ses;
 * IDL   [string] [unique] wchar_t *user;
 * IDL   long num_open;
 * IDL   long time;
 * IDL   long idle_time;
 * IDL   long user_flags
 * IDL   [string] [unique] wchar_t *clienttype;
 * IDL } SESSION_INFO_2;
 */
static int
srvsvc_dissect_SESSION_INFO_2(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Session",
		hf_srvsvc_session, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "User",
		hf_srvsvc_user, 0);
	
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_num_opens, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_time, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_idle_time, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_user_flags, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Client Type:",
		hf_srvsvc_client_type, 0);

	return offset;
}
static int
srvsvc_dissect_SESSION_INFO_2_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SESSION_INFO_2);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] SESSION_INFO_2 *ses;
 * IDL } SESSION_INFO_2_CONTAINER;
 */
static int
srvsvc_dissect_SESSION_INFO_2_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SESSION_INFO_2_array, NDR_POINTER_UNIQUE,
		"SESSION_INFO_2 array:", -1, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   [string] [unique] wchar_t *ses;
 * IDL   [string] [unique] wchar_t *user;
 * IDL   long time;
 * IDL   long idle_time;
 * IDL } SESSION_INFO_10;
 */
static int
srvsvc_dissect_SESSION_INFO_10(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Session",
		hf_srvsvc_session, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "User",
		hf_srvsvc_user, 0);
	
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_time, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_idle_time, NULL);

	return offset;
}
static int
srvsvc_dissect_SESSION_INFO_10_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SESSION_INFO_10);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] SESSION_INFO_10 *ses;
 * IDL } SESSION_INFO_10_CONTAINER;
 */
static int
srvsvc_dissect_SESSION_INFO_10_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SESSION_INFO_10_array, NDR_POINTER_UNIQUE,
		"SESSION_INFO_10 array:", -1, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   [string] [unique] wchar_t *ses;
 * IDL   [string] [unique] wchar_t *user;
 * IDL   long num_open;
 * IDL   long time;
 * IDL   long idle_time;
 * IDL   long user_flags
 * IDL   [string] [unique] wchar_t *clienttype;
 * IDL   [string] [unique] wchar_t *transport;
 * IDL } SESSION_INFO_502;
 */
static int
srvsvc_dissect_SESSION_INFO_502(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Session",
		hf_srvsvc_session, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "User",
		hf_srvsvc_user, 0);
	
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_num_opens, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_time, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_idle_time, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_user_flags, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Client Type:",
		hf_srvsvc_client_type, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Transport:",
		hf_srvsvc_transport, 0);

	return offset;
}
static int
srvsvc_dissect_SESSION_INFO_502_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SESSION_INFO_502);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] SESSION_INFO_502 *ses;
 * IDL } SESSION_INFO_502_CONTAINER;
 */
static int
srvsvc_dissect_SESSION_INFO_502_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SESSION_INFO_502_array, NDR_POINTER_UNIQUE,
		"SESSION_INFO_502 array:", -1, 0);

	return offset;
}

/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(0)] [unique] SESSION_INFO_0_CONTAINER *ses0;
 * IDL   [case(1)] [unique] SESSION_INFO_1_CONTAINER *ses1;
 * IDL   [case(2)] [unique] SESSION_INFO_2_CONTAINER *ses2;
 * IDL   [case(10)] [unique] SESSION_INFO_10_CONTAINER *ses10;
 * IDL   [case(502)] [unique] SESSION_INFO_502_CONTAINER *ses502;
 * IDL } SESSION_ENUM_UNION;
 */
static int
srvsvc_dissect_SESSION_ENUM_UNION(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	guint32 level;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SESSION_INFO_0_CONTAINER,
			NDR_POINTER_UNIQUE, "SESSION_INFO_0_CONTAINER:",
			-1, 0);
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SESSION_INFO_1_CONTAINER,
			NDR_POINTER_UNIQUE, "SESSION_INFO_1_CONTAINER:",
			-1, 0);
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SESSION_INFO_2_CONTAINER,
			NDR_POINTER_UNIQUE, "SESSION_INFO_2_CONTAINER:",
			-1, 0);
		break;
	case 10:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SESSION_INFO_10_CONTAINER,
			NDR_POINTER_UNIQUE, "SESSION_INFO_10_CONTAINER:",
			-1, 0);
		break;
	case 502:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SESSION_INFO_502_CONTAINER,
			NDR_POINTER_UNIQUE, "SESSION_INFO_502_CONTAINER:",
			-1, 0);
		break;
	}

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long Level;
 * IDL   SESSION_ENUM_UNION ses;
 * IDL } SESSION_ENUM_STRUCT;
 */
static int
srvsvc_dissect_SESSION_ENUM_STRUCT(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = srvsvc_dissect_SESSION_ENUM_UNION(tvb, offset, pinfo, tree, drep);

	return offset;
}


/* XXX dont know the out parameters. only the in parameters.
 *
 * IDL long NetrSessionEnum(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [unique] wchar_t *ClientName,
 * IDL      [in] [string] [unique] wchar_t *UserName,
 * IDL      [in] [ref] SESSION_ENUM_STRUCT *ses,
 * IDL      [in] long maxlen,
 * IDL      [in] [unique] long *resumehandle,
 * IDL );
*/
static int
srvsvc_dissect_netrsessionenum_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Server",
		hf_srvsvc_server, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Computer",
		hf_srvsvc_computer, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "User",
		hf_srvsvc_user, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_SESSION_ENUM_STRUCT,
		NDR_POINTER_REF, "SESSION_ENUM_STRUCT",
		-1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_preferred_len, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_ENUM_HANDLE,
		NDR_POINTER_UNIQUE, "Enum Handle", -1, 0);

	return offset;
}

/* XXX dont know the out parameters. only the in parameters.
 *
 * IDL long NetrSessionDel(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *ClientName,
 * IDL      [in] [string] [ref] wchar_t *UserName,
 * IDL );
*/
static int
srvsvc_dissect_netrsessiondel_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Server",
		hf_srvsvc_server, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_REF, "Computer",
		hf_srvsvc_computer, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_REF, "User",
		hf_srvsvc_user, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   [string] [unique] wchar_t *share;
 * IDL } SHARE_INFO_0;
 */
static int
srvsvc_dissect_SHARE_INFO_0(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Share",
		hf_srvsvc_share, 0);

	return offset;
}
static int
srvsvc_dissect_SHARE_INFO_0_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] SHARE_INFO_0 *shares;
 * IDL } SHARE_INFO_0_CONTAINER;
 */
static int
srvsvc_dissect_SHARE_INFO_0_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SHARE_INFO_0_array, NDR_POINTER_UNIQUE,
		"SHARE_INFO_0 array:", -1, 0);

	return offset;
}

/*
  IDL typedef struct {
  IDL    [unique] [string] wchar_t *share;
  IDL    long type;
  IDL    [unique] [string] wchar_t *comment;
  IDL } SHARE_INFO_1;
*/
static int
srvsvc_dissect_SHARE_INFO_1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, char *drep)
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
srvsvc_dissect_SHARE_INFO_1_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] SHARE_INFO_1 *shares;
 * IDL } SHARE_INFO_1_CONTAINER;
 */
static int
srvsvc_dissect_SHARE_INFO_1_CONTAINER(tvbuff_t *tvb, int offset, 
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
  IDL    [unique] [string] wchar_t *share;
  IDL    long type;
  IDL    [unique] [string] wchar_t *comment;
  IDL    long permissions;
  IDL    long max_uses;
  IDL    long current_uses;
  IDL    [unique] [string] wchar_t *path;
  IDL    [unique] [string] wchar_t *passwd;
  IDL } SHARE_INFO_2;
*/
static int
srvsvc_dissect_SHARE_INFO_2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
  
	dcerpc_info *di;

	di=pinfo->private_data;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "Share");
		tree = proto_item_add_subtree(item, ett_srvsvc_share_info_2);
	}

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
		"Share", hf_srvsvc_share, di->levels);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_share_type, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
		"Comment", hf_srvsvc_share_comment, 0);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_perm, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_max_uses, NULL);
	
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_cur_uses, NULL);
	
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Path",
		hf_srvsvc_path, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Passwd",
		hf_srvsvc_share_passwd, 0);

	return offset;
}
static int
srvsvc_dissect_SHARE_INFO_2_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_2);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] SHARE_INFO_2 *shares;
 * IDL } SHARE_INFO_2_CONTAINER;
 */
static int
srvsvc_dissect_SHARE_INFO_2_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SHARE_INFO_2_array, NDR_POINTER_UNIQUE,
		"SHARE_INFO_2 array:", -1, 0);

	return offset;
}

/*
  IDL typedef struct {
  IDL    [unique] [string] wchar_t *share;
  IDL    long type;
  IDL    [unique] [string] wchar_t *comment;
  IDL    long permissions;
  IDL    long max_uses;
  IDL    long current_uses;
  IDL    [unique] [string] wchar_t *path;
  IDL    [unique] [string] wchar_t *passwd;
  IDL    long reserved;
  IDL    SECDESC [unique] *securitysecriptor; 4byte-len followed by bytestring
  IDL } SHARE_INFO_502;
*/
static int
srvsvc_dissect_SHARE_INFO_502(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, char *drep)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
  
	dcerpc_info *di;

	di=pinfo->private_data;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "Share");
		tree = proto_item_add_subtree(item, ett_srvsvc_share_info_502);
	}

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
		"Share", hf_srvsvc_share, di->levels);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_share_type, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
		"Comment", hf_srvsvc_share_comment, 0);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_perm, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_max_uses, NULL);
	
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_cur_uses, NULL);
	
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Path",
		hf_srvsvc_path, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Passwd",
		hf_srvsvc_share_passwd, 0);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_reserved, NULL);
	
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			lsa_dissect_LSA_SECURITY_DESCRIPTOR_data, NDR_POINTER_UNIQUE,
			"LSA SECURITY DESCRIPTOR data:", -1, 0);

	return offset;
}
static int
srvsvc_dissect_SHARE_INFO_502_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_502);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] SHARE_INFO_502 *shares;
 * IDL } SHARE_INFO_502_CONTAINER;
 */
static int
srvsvc_dissect_SHARE_INFO_502_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SHARE_INFO_502_array, NDR_POINTER_UNIQUE,
		"SHARE_INFO_502 array:", -1, 0);

	return offset;
}

/*
  IDL typedef struct {
  IDL    [unique] [string] wchar_t *comment;
  IDL } SHARE_INFO_1004;
*/
static int
srvsvc_dissect_SHARE_INFO_1004(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_pointer_UNICODE_STRING, NDR_POINTER_UNIQUE,
		"Comment", hf_srvsvc_share_comment, 0);

	return offset;
}
static int
srvsvc_dissect_SHARE_INFO_1004_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1004);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] SHARE_INFO_1004 *shares;
 * IDL } SHARE_INFO_1004_CONTAINER;
 */
static int
srvsvc_dissect_SHARE_INFO_1004_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SHARE_INFO_1004_array, NDR_POINTER_UNIQUE,
		"SHARE_INFO_1004 array:", -1, 0);

	return offset;
}

/*
  IDL typedef struct {
  IDL    long max_uses;
  IDL } SHARE_INFO_1006;
*/
static int
srvsvc_dissect_SHARE_INFO_1006(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, char *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_max_uses, NULL);
	
	return offset;
}
static int
srvsvc_dissect_SHARE_INFO_1006_array(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1006);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] SHARE_INFO_1006 *shares;
 * IDL } SHARE_INFO_1006_CONTAINER;
 */
static int
srvsvc_dissect_SHARE_INFO_1006_CONTAINER(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SHARE_INFO_1006_array, NDR_POINTER_UNIQUE,
		"SHARE_INFO_1006 array:", -1, 0);

	return offset;
}


/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(0)] [unique] SHARE_INFO_0 *share0;
 * IDL   [case(1)] [unique] SHARE_INFO_1 *share1;
 * IDL   [case(2)] [unique] SHARE_INFO_2 *share2;
 * IDL   [case(502)] [unique] SHARE_INFO_502 *share502;
 * IDL   [case(1004)] [unique] SHARE_INFO_1004 *share1004;
 * IDL   [case(1006)] [unique] SHARE_INFO_1006 *share1006;
 * IDL } SHARE_INFO_UNION;
 */
static int
srvsvc_dissect_SHARE_INFO_UNION(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	guint32 level;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_0,
			NDR_POINTER_UNIQUE, "SHARE_INFO_0:",
			-1, 0);
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1:",
			-1, 0);
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_2,
			NDR_POINTER_UNIQUE, "SHARE_INFO_2:",
			-1, 0);
		break;
	case 502:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_502,
			NDR_POINTER_UNIQUE, "SHARE_INFO_502:",
			-1, 0);
		break;
	case 1004:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1004,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1004:",
			-1, 0);
		break;
	case 1006:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1006,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1006:",
			-1, 0);
		break;
	}

	return offset;
}


/* XXX dont know the out parameters. only the in parameters.
 *
 * IDL long NetrShareAdd(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long Level,
 * IDL      [in] [ref] SHARE_INFO_UNION *share,
 * IDL      [in] [unique] ParmError
 * IDL );
*/
static int
srvsvc_dissect_netrshareadd_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_pointer_UNICODE_STRING,
		NDR_POINTER_UNIQUE, "Server",
		hf_srvsvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep, 
		srvsvc_dissect_SHARE_INFO_UNION,
		NDR_POINTER_REF, "SHARE_INFO_UNION:",
		-1, 0);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_pointer_long, NDR_POINTER_UNIQUE,
			"Parameter Error:", hf_srvsvc_parm_error, 0);

	return offset;
}

/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(0)] [unique] SHARE_INFO_0_CONTAINER *share0;
 * IDL   [case(1)] [unique] SHARE_INFO_1_CONTAINER *share1;
 * IDL   [case(2)] [unique] SHARE_INFO_2_CONTAINER *share2;
 * IDL   [case(502)] [unique] SHARE_INFO_502_CONTAINER *share502;
 * IDL   [case(1004)] [unique] SHARE_INFO_1004_CONTAINER *share1004;
 * IDL   [case(1006)] [unique] SHARE_INFO_1006_CONTAINER *share1006;
 * IDL } SHARE_ENUM_UNION;
 */
static int
srvsvc_dissect_SHARE_ENUM_UNION(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	guint32 level;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_0_CONTAINER,
			NDR_POINTER_UNIQUE, "SHARE_INFO_0_CONTAINER:",
			-1, 0);
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1_CONTAINER,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1_CONTAINER:",
			-1, 0);
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_2_CONTAINER,
			NDR_POINTER_UNIQUE, "SHARE_INFO_2_CONTAINER:",
			-1, 0);
		break;
	case 502:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_502_CONTAINER,
			NDR_POINTER_UNIQUE, "SHARE_INFO_502_CONTAINER:",
			-1, 0);
		break;
	case 1004:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1004_CONTAINER,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1004_CONTAINER:",
			-1, 0);
		break;
	case 1006:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1006_CONTAINER,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1006_CONTAINER:",
			-1, 0);
		break;
	}

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long Level;
 * IDL   SHARE_ENUM_UNION shares;
 * IDL } SHARE_ENUM_STRUCT;
 */
static int
srvsvc_dissect_SHARE_ENUM_STRUCT(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = srvsvc_dissect_SHARE_ENUM_UNION(tvb, offset, pinfo, tree, drep);

	return offset;
}

/*
 * IDL long NetrShareEnum(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [out] [ref] SHARE_ENUM_STRUCT *share,
 * IDL      [in] long MaxLen,
 * IDL      [out] long Entries,
 * IDL      [in] [out] [unique] *ResumeHandle
 * IDL );
 */
static int
srvsvc_dissect_netrshareenum_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_pointer_UNICODE_STRING,
			NDR_POINTER_UNIQUE, "Server",
			hf_srvsvc_server, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_ENUM_STRUCT,
			NDR_POINTER_REF, "Shares",
			-1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_preferred_len, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_ENUM_HANDLE,
			NDR_POINTER_UNIQUE, "Enum Handle", -1, 0);

	return offset;
}

static int
srvsvc_dissect_netrshareenum_reply(tvbuff_t *tvb, int offset, 
				      packet_info *pinfo, proto_tree *tree, 
				      char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_ENUM_STRUCT,
			NDR_POINTER_REF, "Shares",
			-1, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_ENUM_HANDLE,
			NDR_POINTER_UNIQUE, "Enum Handle", -1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrShareGetInfo(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *ShareName,
 * IDL      [in] long Level,
 * IDL      [out] [ref] SHARE_INFO_UNION *share
 * IDL );
 */
static int
srvsvc_dissect_netrsharegetinfo_rqst(tvbuff_t *tvb, int offset, 
				     packet_info *pinfo, proto_tree *tree, 
				     char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_pointer_UNICODE_STRING,
			NDR_POINTER_UNIQUE, "Server",
			hf_srvsvc_server, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_pointer_UNICODE_STRING,
			NDR_POINTER_UNIQUE, "Share",
			hf_srvsvc_share, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	return offset;
}

static int
srvsvc_dissect_netrsharegetinfo_reply(tvbuff_t *tvb, int offset, 
				      packet_info *pinfo, proto_tree *tree, 
				      char *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_UNION,
			NDR_POINTER_REF, "Share",
			-1, 0);

	offset = dissect_ntstatus(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}









/* new functions in order and with idl above this line */








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

static dcerpc_sub_dissector dcerpc_srvsvc_dissectors[] = {
	{SRV_NETRCHARDEVENUM,		"NetrCharDevEnum",
		srvsvc_dissect_netrchardevenum_rqst,
		NULL},
	{SRV_NETRCHARDEVGETINFO,	"NetrCharDevGetInfo",
		srvsvc_dissect_netrchardevgetinfo_rqst,
		NULL},
	{SRV_NETRCHARDEVCONTROL,	"NetrCharDevControl",
		srvsvc_dissect_netrchardevcontrol_rqst,
		NULL},
	{SRV_NETRCHARDEVQENUM,		"NetrCharDevQEnum",
		srvsvc_dissect_netrchardevqenum_rqst,
		NULL},
	{SRV_NETRCHARDEVQGETINFO,	"NetrCharDevQGetInfo",
		srvsvc_dissect_netrchardevqgetinfo_rqst,
		NULL},
	{SRV_NETRCHARDEVQSETINFO,	"NetrCharDevQSetInfo",
		srvsvc_dissect_netrchardevqsetinfo_rqst,
		NULL},
	{SRV_NETRCHARDEVQPURGE,		"NetrCharDevQPurge",
		srvsvc_dissect_netrchardevqpurge_rqst,
		NULL},
	{SRV_NETRCHARDEVQPURGESELF,	"NetrCharDevQPurgeSelf",
		srvsvc_dissect_netrchardevqpurgeself_rqst,
		NULL},
	{SRV_NETRCONNECTIONENUM,	"NetrConnectionEnum",
		srvsvc_dissect_netrconnectionenum_rqst,
		NULL},
	{SRV_NETRFILEENUM,		"NetrFileEnum",
		srvsvc_dissect_netrfileenum_rqst,
		NULL},
	{SRV_NETRFILEGETINFO,		"NetrFileGetInfo",
		srvsvc_dissect_netrfilegetinfo_rqst,
		NULL},
	{SRV_NETRFILECLOSE,		"NetrFileClose",
		srvsvc_dissect_netrfileclose_rqst,
		NULL},
	{SRV_NETRSESSIONENUM,		"NetrSessionEnum",
		srvsvc_dissect_netrsessionenum_rqst,
		NULL},
	{SRV_NETRSESSIONDEL,		"NetrSessionDel",
		srvsvc_dissect_netrsessiondel_rqst,
		NULL},
	{SRV_NETRSHAREADD,		"NetrShareAdd",
		srvsvc_dissect_netrshareadd_rqst,
		NULL},
	{SRV_NETRSHAREENUM,		"NetrShareEnum",
		srvsvc_dissect_netrshareenum_rqst,
		srvsvc_dissect_netrshareenum_reply},
	{SRV_NETRSHAREGETINFO,		"NetrShareGetInfo",
		srvsvc_dissect_netrsharegetinfo_rqst,
		srvsvc_dissect_netrsharegetinfo_reply},
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
	  { &hf_srvsvc_transport,
	    { "Transport", "srvsvc.transport", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Transport Name", HFILL}},
	  { &hf_srvsvc_session,
	    { "Session", "srvsvc.session", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Session Name", HFILL}},
	  { &hf_srvsvc_qualifier,
	    { "Qualifier", "srvsvc.qualifier", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Connection Qualifier", HFILL}},
	  { &hf_srvsvc_computer,
	    { "Computer", "srvsvc.computer", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Computer Name", HFILL}},
	  { &hf_srvsvc_chrdev,
	    { "Char Device", "srvsvc.chrdev", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Char Device Name", HFILL}},
	  { &hf_srvsvc_chrdevq,
	    { "Device Queue", "srvsvc.chrdevq", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Char Device Queue Name", HFILL}},
	  { &hf_srvsvc_user,
	    { "User", "srvsvc.user", FT_STRING, BASE_NONE,
	    NULL, 0x0, "User Name", HFILL}},
	  { &hf_srvsvc_path,
	    { "Path", "srvsvc.path", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Path", HFILL}},
	  { &hf_srvsvc_share_passwd,
	    { "Share Passwd", "srvsvc.share_passwd", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Password for this share", HFILL}},
	  { &hf_srvsvc_chrdev_status,
	    { "Status", "srvsvc.chrdev_status", FT_UINT32, BASE_HEX,
	    NULL, 0x0, "Char Device Status", HFILL}},
	  { &hf_srvsvc_chrqpri,
	    { "Priority", "srvsvc.chrqdev_pri", FT_UINT32, BASE_HEX,
	    NULL, 0x0, "Char QDevice Priority", HFILL}},
	  { &hf_srvsvc_chrqnumusers,
	    { "Num Users", "srvsvc.chrqdev_numusers", FT_UINT32, BASE_DEC,
	    NULL, 0x0, "Char QDevice Number Of Users", HFILL}},
	  { &hf_srvsvc_chrqnumahead,
	    { "Num Ahead", "srvsvc.chrqdev_numahead", FT_UINT32, BASE_DEC,
	    NULL, 0x0, "", HFILL}},
	  { &hf_srvsvc_chrdev_opcode,
	    { "Opcode", "srvsvc.chrdev_opcode", FT_UINT32, BASE_HEX,
	    NULL, 0x0, "Opcode to apply to the Char Device", HFILL}},
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
	  { &hf_srvsvc_client_type,
	    { "Client Type", "srvsvc.Client.type", FT_STRING,
	      BASE_NONE, NULL, 0x0, "Client Type", HFILL}},
	  { &hf_srvsvc_server_comment, 
	    { "Server Comment", "srvsvc.server.comment", FT_STRING,
	      BASE_NONE, NULL, 0x0, "Server Comment String", HFILL}},
	  { &hf_srvsvc_users,
	    { "Users", "srvsvc.users", FT_UINT32,
	      BASE_DEC, NULL, 0x0 , "User Count", HFILL}},
	  { &hf_srvsvc_hidden,
	    { "Hidden", "srvsvc.hidden", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Hidden", HFILL}},
	  { &hf_srvsvc_reserved,
	    { "Reserved", "srvsvc.reserved", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Announce", HFILL }},
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
	  { &hf_srvsvc_file_id,
	    { "File ID", "srvsvc.file_id", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "File ID", HFILL}},
	  { &hf_srvsvc_perm,
	    { "Permissions", "srvsvc.perm", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Permissions", HFILL}},
	  { &hf_srvsvc_file_num_locks,
	    { "Num Locks", "srvsvc.file_num_locks", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of locks for file", HFILL}},
	  { &hf_srvsvc_con_id,
	    { "Connection ID", "srvsvc.con_id", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Connection ID", HFILL}},
	  { &hf_srvsvc_max_uses,
	    { "Max Uses", "srvsvc.max_uses", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Max Uses", HFILL}},
	  { &hf_srvsvc_cur_uses,
	    { "Current Uses", "srvsvc.cur_uses", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Current Uses", HFILL}},
	  { &hf_srvsvc_con_num_opens,
	    { "Num Opens", "srvsvc.con_num_opens", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Num Opens", HFILL}},
	  { &hf_srvsvc_session_num_opens,
	    { "Num Opens", "srvsvc.session.num_opens", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Num Opens", HFILL}},
	  { &hf_srvsvc_session_time,
	    { "Time", "srvsvc.session.time", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Time", HFILL}},
	  { &hf_srvsvc_session_idle_time,
	    { "Idle Time", "srvsvc.session.idle_time", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Idle Time", HFILL}},
	  { &hf_srvsvc_session_user_flags,
	    { "User Flags", "srvsvc.session.user_flags", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "User Flags", HFILL}},
	  { &hf_srvsvc_con_num_users,
	    { "Num Users", "srvsvc.con_num_users", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Num Users", HFILL}},
	  { &hf_srvsvc_con_type,
	    { "Connection Type", "srvsvc.con_type", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Connection Type", HFILL}},
	  { &hf_srvsvc_con_time,
	    { "Connection Time", "srvsvc.con_time", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Connection Time", HFILL}},
	  { &hf_srvsvc_num_entries,
	    { "Number of entries", "srvsvc.share.num_entries", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of Entries", HFILL}},
	  { &hf_srvsvc_num_pointers,
	    { "Pointer entries", "srvsvc.share.pointer_entries", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Pointer Entries", HFILL}},
	  { &hf_srvsvc_preferred_len,
	    { "Preferred length", "srvsvc.preferred_len", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Preferred Length", HFILL}},
	  { &hf_srvsvc_parm_error,
	    { "Parameter Error", "srvsvc.parm_error", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Parameter Error", HFILL}},
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
		&ett_srvsvc_share_info_1,
		&ett_srvsvc_share_info_2,
		&ett_srvsvc_share_info_502
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
