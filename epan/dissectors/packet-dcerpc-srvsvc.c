/* packet-dcerpc-srvsvc.c
 * Routines for SMB \PIPE\srvsvc packet disassembly
 * Copyright 2001-2003, Tim Potter <tpot@samba.org>
 * Copyright 2002, Richard Sharpe <rsharpe@ns.aus.com>
 *   decode srvsvc calls where Samba knows them ...
 * Copyright 2002, Ronnie Sahlberg
 *   rewrote entire dissector
 *
 * 2002, some share information levels implemented based on samba
 * sources.
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

/* The IDL file for this interface can be extracted by grepping for IDL */


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
#include "packet-smb-browse.h"
#include "packet-windows-common.h"	/* for "DOS_errors[]" */

static int proto_dcerpc_srvsvc = -1;
static int hf_srvsvc_opnum = -1;
static int hf_srvsvc_reserved = -1;
static int hf_srvsvc_server = -1;
static int hf_srvsvc_emulated_server = -1;
static int hf_srvsvc_alerts = -1;
static int hf_srvsvc_guest = -1;
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
static int hf_srvsvc_share_alternate_name = -1;
static int hf_srvsvc_file_id = -1;
static int hf_srvsvc_perm = -1;
static int hf_srvsvc_policy = -1;
static int hf_srvsvc_file_num_locks = -1;
static int hf_srvsvc_con_id = -1;
static int hf_srvsvc_max_uses = -1;
static int hf_srvsvc_cur_uses = -1;
static int hf_srvsvc_con_time = -1;
static int hf_srvsvc_con_type = -1;
static int hf_srvsvc_con_num_opens = -1;
static int hf_srvsvc_chrqpri = -1;
static int hf_srvsvc_chrqnumusers = -1;
static int hf_srvsvc_chrqnumahead = -1;
static int hf_srvsvc_chrdev = -1;
static int hf_srvsvc_chrdevq = -1;
static int hf_srvsvc_chrdev_time = -1;
static int hf_srvsvc_chrdev_status = -1;
static int hf_srvsvc_chrdev_opcode = -1;
static int hf_srvsvc_info_level = -1;
static int hf_srvsvc_rc = -1;
static int hf_srvsvc_platform_id = -1;
static int hf_srvsvc_ver_major = -1;
static int hf_srvsvc_ver_minor = -1;
static int hf_srvsvc_client_type = -1;
static int hf_srvsvc_comment = -1;
static int hf_srvsvc_users = -1;
static int hf_srvsvc_disc = -1;
static int hf_srvsvc_hidden = -1;
static int hf_srvsvc_announce = -1;
static int hf_srvsvc_anndelta = -1;
static int hf_srvsvc_licences = -1;
static int hf_srvsvc_user_path = -1;
static int hf_srvsvc_share = -1;
static int hf_srvsvc_share_type = -1;
static int hf_srvsvc_num_entries = -1;
static int hf_srvsvc_total_entries = -1;
static int hf_srvsvc_preferred_len = -1;
static int hf_srvsvc_parm_error = -1;
static int hf_srvsvc_enum_handle = -1;
static int hf_srvsvc_ulist_mtime = -1;
static int hf_srvsvc_glist_mtime = -1;
static int hf_srvsvc_alist_mtime = -1;
static int hf_srvsvc_security = -1;
static int hf_srvsvc_dfs_root_flags = -1;
static int hf_srvsvc_numadmin = -1;
static int hf_srvsvc_lanmask = -1;
static int hf_srvsvc_chdevs = -1;
static int hf_srvsvc_chdevqs = -1;
static int hf_srvsvc_chdevjobs = -1;
static int hf_srvsvc_connections = -1;
static int hf_srvsvc_shares = -1;
static int hf_srvsvc_openfiles = -1;
static int hf_srvsvc_sessopens = -1;
static int hf_srvsvc_sessvcs = -1;
static int hf_srvsvc_sessreqs = -1;
static int hf_srvsvc_opensearch = -1;
static int hf_srvsvc_activelocks = -1;
static int hf_srvsvc_sizreqbufs = -1;
static int hf_srvsvc_numbigbufs = -1;
static int hf_srvsvc_numfiletasks = -1;
static int hf_srvsvc_alertsched = -1;
static int hf_srvsvc_erroralert = -1;
static int hf_srvsvc_logonalert = -1;
static int hf_srvsvc_accessalert = -1;
static int hf_srvsvc_diskalert = -1;
static int hf_srvsvc_netioalert = -1;
static int hf_srvsvc_maxauditsz = -1;
static int hf_srvsvc_srvheuristics = -1;
static int hf_srvsvc_auditedevents = -1;
static int hf_srvsvc_auditprofile = -1;
static int hf_srvsvc_autopath = -1;
static int hf_srvsvc_initworkitems = -1;
static int hf_srvsvc_maxworkitems = -1;
static int hf_srvsvc_rawworkitems = -1;
static int hf_srvsvc_irpstacksize = -1;
static int hf_srvsvc_maxrawbuflen = -1;
static int hf_srvsvc_maxpagedmemoryusage = -1;
static int hf_srvsvc_maxnonpagedmemoryusage = -1;
static int hf_srvsvc_enablesoftcompat = -1;
static int hf_srvsvc_enableforcedlogoff = -1;
static int hf_srvsvc_timesource = -1;
static int hf_srvsvc_acceptdownlevelapis = -1;
static int hf_srvsvc_lmannounce = -1;
static int hf_srvsvc_domain = -1;
static int hf_srvsvc_maxcopyreadlen = -1;
static int hf_srvsvc_maxcopywritelen = -1;
static int hf_srvsvc_minkeepsearch = -1;
static int hf_srvsvc_maxkeepsearch = -1;
static int hf_srvsvc_minkeepcomplsearch = -1;
static int hf_srvsvc_maxkeepcomplsearch = -1;
static int hf_srvsvc_threadcountadd = -1;
static int hf_srvsvc_numblockthreads = -1;
static int hf_srvsvc_scavtimeout = -1;
static int hf_srvsvc_minrcvqueue = -1;
static int hf_srvsvc_minfreeworkitems = -1;
static int hf_srvsvc_xactmemsize = -1;
static int hf_srvsvc_threadpriority = -1;
static int hf_srvsvc_maxmpxct = -1;
static int hf_srvsvc_oplockbreakwait = -1;
static int hf_srvsvc_oplockbreakresponsewait = -1;
static int hf_srvsvc_enableoplocks = -1;
static int hf_srvsvc_enableoplockforceclose = -1;
static int hf_srvsvc_enablefcbopens = -1;
static int hf_srvsvc_enableraw = -1;
static int hf_srvsvc_enablesharednetdrives = -1;
static int hf_srvsvc_minfreeconnections = -1;
static int hf_srvsvc_maxfreeconnections = -1;
static int hf_srvsvc_initsesstable = -1;
static int hf_srvsvc_initconntable = -1;
static int hf_srvsvc_initfiletable = -1;
static int hf_srvsvc_initsearchtable = -1;
static int hf_srvsvc_errortreshold = -1;
static int hf_srvsvc_networkerrortreshold = -1;
static int hf_srvsvc_diskspacetreshold = -1;
static int hf_srvsvc_maxlinkdelay = -1;
static int hf_srvsvc_minlinkthroughput = -1;
static int hf_srvsvc_linkinfovalidtime = -1;
static int hf_srvsvc_scavqosinfoupdatetime = -1;
static int hf_srvsvc_maxworkitemidletime = -1;
static int hf_srvsvc_disk_name = -1;
static int hf_srvsvc_disk_name_len = -1;
static int hf_srvsvc_disk_inf0_unknown = -1;
static int hf_srvsvc_service = -1;
static int hf_srvsvc_service_options = -1;
static int hf_srvsvc_transport_numberofvcs = -1;
static int hf_srvsvc_transport_name = -1;
static int hf_srvsvc_transport_address = -1;
static int hf_srvsvc_transport_address_len = -1;
static int hf_srvsvc_transport_networkaddress = -1;
static int hf_srvsvc_service_bits = -1;
static int hf_srvsvc_service_bits_of_interest = -1;
static int hf_srvsvc_update_immediately = -1;
static int hf_srvsvc_path_flags = -1;
static int hf_srvsvc_share_flags = -1;
static int hf_srvsvc_path_type = -1;
static int hf_srvsvc_outbuflen = -1;
static int hf_srvsvc_prefix = -1;
static int hf_srvsvc_hnd = -1;
static int hf_srvsvc_server_stat_start = -1;
static int hf_srvsvc_server_stat_fopens = -1;
static int hf_srvsvc_server_stat_devopens = -1;
static int hf_srvsvc_server_stat_jobsqueued = -1;
static int hf_srvsvc_server_stat_sopens = -1;
static int hf_srvsvc_server_stat_stimeouts = -1;
static int hf_srvsvc_server_stat_serrorout = -1;
static int hf_srvsvc_server_stat_pwerrors = -1;
static int hf_srvsvc_server_stat_permerrors = -1;
static int hf_srvsvc_server_stat_syserrors = -1;
static int hf_srvsvc_server_stat_bytessent = -1;
static int hf_srvsvc_server_stat_bytesrcvd = -1;
static int hf_srvsvc_server_stat_avresponse = -1;
static int hf_srvsvc_server_stat_reqbufneed = -1;
static int hf_srvsvc_server_stat_bigbufneed = -1;
static int hf_srvsvc_tod_elapsed = -1;
static int hf_srvsvc_tod_msecs = -1;
static int hf_srvsvc_tod_hours = -1;
static int hf_srvsvc_tod_mins = -1;
static int hf_srvsvc_tod_secs = -1;
static int hf_srvsvc_tod_hunds = -1;
static int hf_srvsvc_tod_timezone = -1;
static int hf_srvsvc_tod_tinterval = -1;
static int hf_srvsvc_tod_day = -1;
static int hf_srvsvc_tod_month = -1;
static int hf_srvsvc_tod_year = -1;
static int hf_srvsvc_tod_weekday = -1;
static int hf_srvsvc_path_len = -1;

static gint ett_dcerpc_srvsvc = -1;
static gint ett_srvsvc_share_info_1 = -1;
static gint ett_srvsvc_share_info_2 = -1;
static gint ett_srvsvc_share_info_501 = -1;
static gint ett_srvsvc_share_info_502 = -1;



/*
 IDL [ uuid(4b324fc8-1670-01d3-1278-5a47bf6ee188),
 IDL   version(3.0),
 IDL   implicit_handle(handle_t rpc_binding)
 IDL ] interface srvsvc
 IDL {
*/
static e_uuid_t uuid_dcerpc_srvsvc = {
        0x4b324fc8, 0x1670, 0x01d3,
        { 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88 }
};

static guint16 ver_dcerpc_srvsvc = 3;

static int
srvsvc_dissect_pointer_long(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
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
			   guint8 *drep)
{

  offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			      hf_srvsvc_enum_handle, 0);
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
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Char Device", 
			hf_srvsvc_chrdev, 0);

	return offset;
}

static int
srvsvc_dissect_CHARDEV_INFO_0_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_CHARDEV_INFO_0_array, NDR_POINTER_UNIQUE,
		"CHARDEV_INFO_0 array:", -1);

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
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Char Device", 
			hf_srvsvc_chrdev, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_chrdev_status, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "User", hf_srvsvc_user, 0);

	/* XXX dont know how to decode this time field */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_chrdev_time, 0);

	return offset;
}
static int
srvsvc_dissect_CHARDEV_INFO_1_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_CHARDEV_INFO_1_array, NDR_POINTER_UNIQUE,
		"CHARDEV_INFO_1 array:", -1);

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
				     guint8 *drep)
{
	guint32 level;
	dcerpc_info *di;

	di = pinfo->private_data;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEV_INFO_0_CONTAINER,
			NDR_POINTER_UNIQUE, "CHARDEV_INFO_0_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", CHARDEV_INFO_0 level");
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEV_INFO_1_CONTAINER,
			NDR_POINTER_UNIQUE, "CHARDEV_INFO_1_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", CHARDEV_INFO_1 level");
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = srvsvc_dissect_CHARDEV_ENUM_UNION(tvb, offset, pinfo, tree, drep);

	return offset;
}

/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(0)] [unique] CHARDEV_INFO_0 *dev0;
 * IDL   [case(1)] [unique] CHARDEV_INFO_1 *dev1;
 * IDL } CHARDEV_INFO_UNION;
 */
static int
srvsvc_dissect_CHARDEV_INFO_UNION(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	guint32 level;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEV_INFO_0,
			NDR_POINTER_UNIQUE, "CHARDEV_INFO_0:", -1);
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEV_INFO_1,
			NDR_POINTER_UNIQUE, "CHARDEV_INFO_1:", -1);
		break;
	}

	return offset;
}

/*
 * IDL long NetrCharDevEnum(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [out] [ref] CHARDEV_ENUM_STRUCT *devs,
 * IDL      [in] long PreferredMaximumLength,
 * IDL      [out] long num_entries,
 * IDL      [in] [out] [unique] long *ResumeHandle
 * IDL );
*/
static int
srvsvc_dissect_netrchardevenum_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_CHARDEV_ENUM_STRUCT,
		NDR_POINTER_REF, "CHARDEV_ENUM_STRUCT", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_preferred_len, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_ENUM_HANDLE,
		NDR_POINTER_UNIQUE, "Enum Handle", -1);

	return offset;
}
static int
srvsvc_dissect_netrchardevenum_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEV_ENUM_STRUCT,
			NDR_POINTER_REF, "CHARDEV_ENUM_STRUCT", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_ENUM_HANDLE,
			NDR_POINTER_UNIQUE, "Enum Handle", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}


/*
 * IDL long NetrCharDevGetInfo(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *DevName,
 * IDL      [in] long Level ,
 * IDL      [out] [ref] CHARDEV_INFO_STRUCT *dev
 * IDL );
*/
static int
srvsvc_dissect_netrchardevgetinfo_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Char Device", hf_srvsvc_chrdev, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	return offset;
}
static int
srvsvc_dissect_netrchardevgetinfo_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEV_INFO_UNION,
			NDR_POINTER_REF, "CHARDEV_INFO_UNION", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrCharDevControl(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *DevName,
 * IDL      [in] long Opcode
 * IDL );
*/
static int
srvsvc_dissect_netrchardevcontrol_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Char Device", hf_srvsvc_chrdev, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_chrdev_opcode, 0);

	return offset;
}
static int
srvsvc_dissect_netrchardevcontrol_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

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
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Char QDevice", hf_srvsvc_chrdev, 0);

	return offset;
}

static int
srvsvc_dissect_CHARDEVQ_INFO_0_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_CHARDEVQ_INFO_0_array, NDR_POINTER_UNIQUE,
		"CHARDEVQ_INFO_0 array:", -1);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   [string] [unique] wchar_t *dev;
 * IDL   long priority;
 * IDL   [string] [unique] wchar_t *devs;
 * IDL   long users;
 * IDL   long num_ahead;
 * IDL } CHARDEVQ_INFO_1;
 */
static int
srvsvc_dissect_CHARDEVQ_INFO_1(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Char Device", hf_srvsvc_chrdev, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_chrqpri, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Char Devices", hf_srvsvc_chrdevq, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_chrqnumusers, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_chrqnumahead, 0);

	return offset;
}
static int
srvsvc_dissect_CHARDEVQ_INFO_1_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_CHARDEVQ_INFO_1_array, NDR_POINTER_UNIQUE,
		"CHARDEVQ_INFO_1 array:", -1);

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
				     guint8 *drep)
{
	guint32 level;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEVQ_INFO_0_CONTAINER,
			NDR_POINTER_UNIQUE, "CHARDEVQ_INFO_0_CONTAINER:", -1);
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEVQ_INFO_1_CONTAINER,
			NDR_POINTER_UNIQUE, "CHARDEVQ_INFO_1_CONTAINER:", -1);
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
				     guint8 *drep)
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
				     guint8 *drep)
{
	guint32 level;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEVQ_INFO_0,
			NDR_POINTER_UNIQUE, "CHARDEVQ_INFO_0:", -1);
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEVQ_INFO_1,
			NDR_POINTER_UNIQUE, "CHARDEVQ_INFO_1:", -1);
		break;
	}

	return offset;
}


/*
 * IDL long NetrCharDevQEnum(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [unique] wchar_t *UserName,
 * IDL      [in] [out] [ref] CHARDEVQ_ENUM_STRUCT *devs,
 * IDL      [in] long PreferredMaximumLength,
 * IDL      [out] long num_entries,
 * IDL      [in] [out] [unique] long *ResumeHandle
 * IDL );
*/
static int
srvsvc_dissect_netrchardevqenum_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "User", hf_srvsvc_user, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_CHARDEVQ_ENUM_STRUCT,
		NDR_POINTER_REF, "CHARDEVQ_ENUM_STRUCT", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_preferred_len, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_ENUM_HANDLE,
		NDR_POINTER_UNIQUE, "Enum Handle", -1);

	return offset;
}
static int
srvsvc_dissect_netrchardevqenum_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEVQ_ENUM_STRUCT,
			NDR_POINTER_REF, "CHARDEVQ_ENUM_STRUCT", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_ENUM_HANDLE,
			NDR_POINTER_UNIQUE, "Enum Handle", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrCharDevQGetInfo(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *QueueName,
 * IDL      [in] [string] [ref] wchar_t *UserName,
 * IDL      [in] long Level,
 * IDL      [out] [ref] CHARDEVQ_INFO *devq
 * IDL );
*/
static int
srvsvc_dissect_netrchardevqgetinfo_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Device Queue", hf_srvsvc_chrdevq, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "User", hf_srvsvc_user, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_info_level, NULL);

	return offset;
}
static int
srvsvc_dissect_netrchardevqgetinfo_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CHARDEVQ_INFO,
			NDR_POINTER_REF, "CHARDEVQ_INFO:", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrCharDevQSetInfo(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *QueueName,
 * IDL      [in] long Level,
 * IDL      [in] [ref] CHARDEVQ_INFO *dev,
 * IDL      [in] [out] [unique] long *ParmError
 * IDL );
*/
static int
srvsvc_dissect_netrchardevqsetinfo_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Device Queue", hf_srvsvc_chrdevq, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_info_level, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_CHARDEVQ_INFO,
		NDR_POINTER_REF, "CHARDEVQ_INFO", -1);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_pointer_long, NDR_POINTER_UNIQUE,
			"Parameter Error:", hf_srvsvc_parm_error);

	return offset;
}
static int
srvsvc_dissect_netrchardevqsetinfo_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_pointer_long, NDR_POINTER_UNIQUE,
			"Parameter Error:", hf_srvsvc_parm_error);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrCharDevQPurge(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *QueueName
 * IDL );
*/
static int
srvsvc_dissect_netrchardevqpurge_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Device Queue", hf_srvsvc_chrdevq, 0);

	return offset;
}
static int
srvsvc_dissect_netrchardevqpurge_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrCharDevQPurge(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *QueueName
 * IDL      [in] [string] [ref] wchar_t *ComputerName
 * IDL );
*/
static int
srvsvc_dissect_netrchardevqpurgeself_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Device Queue", hf_srvsvc_chrdevq, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Computer", hf_srvsvc_computer, 0);

	return offset;
}
static int
srvsvc_dissect_netrchardevqpurgeself_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

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
				     guint8 *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_con_id, NULL);

	return offset;
}
static int
srvsvc_dissect_CONNECT_INFO_0_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_CONNECT_INFO_0_array, NDR_POINTER_UNIQUE,
		"CONNECT_INFO_0 array:", -1);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   long conid;
 * IDL   long type;
 * IDL   long num_opens;
 * IDL   long users;
 * IDL   long time;
 * IDL   [string] [unique] wchar_t *username;
 * IDL   [string] [unique] wchar_t *share;
 * IDL } CONNECT_INFO_1;
 */
static int
srvsvc_dissect_CONNECT_INFO_1(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_con_id, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_con_type, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_con_num_opens, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_users, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_con_time, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "User", hf_srvsvc_user, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Share", hf_srvsvc_share, 0);

	return offset;
}
static int
srvsvc_dissect_CONNECT_INFO_1_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_CONNECT_INFO_1_array, NDR_POINTER_UNIQUE,
		"CONNECT_INFO_1 array:", -1);

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
				     guint8 *drep)
{
	guint32 level;
	dcerpc_info *di;

	di = pinfo->private_data;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CONNECT_INFO_0_CONTAINER,
			NDR_POINTER_UNIQUE, "CONNECT_INFO_0_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", CONNECT_INFO_0 level");
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CONNECT_INFO_1_CONTAINER,
			NDR_POINTER_UNIQUE, "CONNECT_INFO_1_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", CONNECT_INFO_1 level");
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = srvsvc_dissect_CONNECT_ENUM_UNION(tvb, offset, pinfo, tree, drep);

	return offset;
}


/*
 * IDL long NetrConnectionEnum(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [unique] wchar_t *Qualifier,
 * IDL      [in] [out] [ref] CONNECT_ENUM_STRUCT *con,
 * IDL      [in] long MaxLen,
 * IDL      [in] long num_connections,
 * IDL      [in] [out] [unique] long *ResumeHandle
 * IDL );
*/
static int
srvsvc_dissect_netrconnectionenum_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Qualifier", hf_srvsvc_qualifier, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_CONNECT_ENUM_STRUCT,
		NDR_POINTER_REF, "CONNECT_ENUM_STRUCT:", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_preferred_len, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_ENUM_HANDLE,
		NDR_POINTER_UNIQUE, "Enum Handle", -1);

	return offset;
}
static int
srvsvc_dissect_netrconnectionenum_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_CONNECT_ENUM_STRUCT,
			NDR_POINTER_REF, "CONNECT_ENUM_STRUCT:", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_ENUM_HANDLE,
			NDR_POINTER_UNIQUE, "Enum Handle", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

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
				     guint8 *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_file_id, NULL);

	return offset;
}
static int
srvsvc_dissect_FILE_INFO_2_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_FILE_INFO_2_array, NDR_POINTER_UNIQUE,
		"FILE_INFO_2 array:", -1);

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
				     guint8 *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_file_id, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_perm, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_file_num_locks, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Path", hf_srvsvc_path, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "User", hf_srvsvc_user, 0);

	return offset;
}
static int
srvsvc_dissect_FILE_INFO_3_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_FILE_INFO_3_array, NDR_POINTER_UNIQUE,
		"CHARDEV_INFO_3 array:", -1);

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
				     guint8 *drep)
{
	guint32 level;
	dcerpc_info *di;

	di = pinfo->private_data;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_FILE_INFO_2_CONTAINER,
			NDR_POINTER_UNIQUE, "FILE_INFO_2_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", FILE_INFO_2 level");
		break;
	case 3:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_FILE_INFO_3_CONTAINER,
			NDR_POINTER_UNIQUE, "FILE_INFO_3_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", FILE_INFO_3 level");
		break;
	}

	return offset;
}

/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(2)] [unique] FILE_INFO_2 *file0;
 * IDL   [case(3)] [unique] FILE_INFO_3 *file1;
 * IDL } FILE_INFO_UNION;
 */
static int
srvsvc_dissect_FILE_INFO_UNION(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	guint32 level;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_FILE_INFO_2,
			NDR_POINTER_UNIQUE, "FILE_INFO_2:", -1);
		break;
	case 3:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_FILE_INFO_3,
			NDR_POINTER_UNIQUE, "FILE_INFO_3:", -1);
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = srvsvc_dissect_FILE_ENUM_UNION(tvb, offset, pinfo, tree, drep);

	return offset;
}


/*
 * IDL long NetrFileEnum(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [unique] wchar_t *Path,
 * IDL      [in] [string] [unique] wchar_t *UserName,
 * IDL      [in] [out] [ref] FILE_ENUM_STRUCT *file,
 * IDL      [in] long MaxLen,
 * IDL      [out] long num_entries,
 * IDL      [in] [out] [unique] long *ResumeHandle
 * IDL );
*/
static int
srvsvc_dissect_netrfileenum_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Path", hf_srvsvc_path, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "User", hf_srvsvc_user, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_FILE_ENUM_STRUCT,
		NDR_POINTER_REF, "FILE_ENUM_STRUCT:", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_preferred_len, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_ENUM_HANDLE,
		NDR_POINTER_UNIQUE, "Enum Handle", -1);

	return offset;
}
static int
srvsvc_dissect_netrfileenum_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_FILE_ENUM_STRUCT,
			NDR_POINTER_REF, "FILE_ENUM_STRUCT:", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_ENUM_HANDLE,
			NDR_POINTER_UNIQUE, "Enum Handle", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}


/*
 * IDL long NetrFileGetInfo(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long fileid,
 * IDL      [in] long level,
 * IDL      [out] [ref] FILE_INFO_UNION *file
 * IDL );
*/
static int
srvsvc_dissect_netrfilegetinfo_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_file_id, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	return offset;
}
static int
srvsvc_dissect_netrfilegetinfo_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_FILE_INFO_UNION,
			NDR_POINTER_REF, "FILE_INFO_UNION:", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}


/*
 * IDL long NetrFileClose(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long fileid,
 * IDL );
*/
static int
srvsvc_dissect_netrfileclose_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_file_id, NULL);

	return offset;
}
static int
srvsvc_dissect_netrfileclose_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

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
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Session", hf_srvsvc_session, 0);

	return offset;
}
static int
srvsvc_dissect_SESSION_INFO_0_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SESSION_INFO_0_array, NDR_POINTER_UNIQUE,
		"SESSION_INFO_0 array:", -1);

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
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Session", hf_srvsvc_session, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "User", hf_srvsvc_user, 0);

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
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SESSION_INFO_1_array, NDR_POINTER_UNIQUE,
		"SESSION_INFO_1 array:", -1);

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
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Session", hf_srvsvc_session, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "User", hf_srvsvc_user, 0);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_num_opens, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_time, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_idle_time, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_user_flags, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Client Type", 
			hf_srvsvc_client_type, 0);

	return offset;
}
static int
srvsvc_dissect_SESSION_INFO_2_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SESSION_INFO_2_array, NDR_POINTER_UNIQUE,
		"SESSION_INFO_2 array:", -1);

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
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Session", hf_srvsvc_session, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "User", hf_srvsvc_user, 0);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_time, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_idle_time, NULL);

	return offset;
}
static int
srvsvc_dissect_SESSION_INFO_10_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SESSION_INFO_10_array, NDR_POINTER_UNIQUE,
		"SESSION_INFO_10 array:", -1);

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
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Session", hf_srvsvc_session, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "User", hf_srvsvc_user, 0);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_num_opens, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_time, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_idle_time, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_session_user_flags, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Client Type", 
			hf_srvsvc_client_type, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Transport", hf_srvsvc_transport, 0);

	return offset;
}
static int
srvsvc_dissect_SESSION_INFO_502_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SESSION_INFO_502_array, NDR_POINTER_UNIQUE,
		"SESSION_INFO_502 array:", -1);

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
				     guint8 *drep)
{
	guint32 level;
	dcerpc_info *di;

	di = pinfo->private_data;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SESSION_INFO_0_CONTAINER,
			NDR_POINTER_UNIQUE, "SESSION_INFO_0_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", SESSION_INFO_0 level");
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SESSION_INFO_1_CONTAINER,
			NDR_POINTER_UNIQUE, "SESSION_INFO_1_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", SESSION_INFO_1 level");
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SESSION_INFO_2_CONTAINER,
			NDR_POINTER_UNIQUE, "SESSION_INFO_2_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", SESSION_INFO_2 level");
		break;
	case 10:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SESSION_INFO_10_CONTAINER,
			NDR_POINTER_UNIQUE, "SESSION_INFO_10_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", SESSION_INFO_10 level");
		break;
	case 502:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SESSION_INFO_502_CONTAINER,
			NDR_POINTER_UNIQUE, "SESSION_INFO_502_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, 
					", SESSION_INFO_502 level");
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = srvsvc_dissect_SESSION_ENUM_UNION(tvb, offset, pinfo, tree, drep);

	return offset;
}


/*
 * IDL long NetrSessionEnum(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [unique] wchar_t *ClientName,
 * IDL      [in] [string] [unique] wchar_t *UserName,
 * IDL      [in] [out] [ref] SESSION_ENUM_STRUCT *ses,
 * IDL      [in] long maxlen,
 * IDL      [out] long num_sessions,
 * IDL      [in] [out] [unique] long *resumehandle,
 * IDL );
*/
static int
srvsvc_dissect_netrsessionenum_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Computer", hf_srvsvc_computer, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "User", hf_srvsvc_user, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SESSION_ENUM_STRUCT,
		NDR_POINTER_REF, "SESSION_ENUM_STRUCT", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_preferred_len, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_ENUM_HANDLE,
		NDR_POINTER_UNIQUE, "Enum Handle", -1);

	return offset;
}
static int
srvsvc_dissect_netrsessionenum_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SESSION_ENUM_STRUCT,
		NDR_POINTER_REF, "SESSION_ENUM_STRUCT", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_ENUM_HANDLE,
			NDR_POINTER_UNIQUE, "Enum Handle", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}


/*
 * IDL long NetrSessionDel(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *ClientName,
 * IDL      [in] [string] [ref] wchar_t *UserName,
 * IDL );
*/
static int
srvsvc_dissect_netrsessiondel_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Computer", hf_srvsvc_computer, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "User", hf_srvsvc_user, 0);

	return offset;
}
static int
srvsvc_dissect_netrsessiondel_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

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
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Share", hf_srvsvc_share, 0);

	return offset;
}
static int
srvsvc_dissect_SHARE_INFO_0_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SHARE_INFO_0_array, NDR_POINTER_UNIQUE,
		"SHARE_INFO_0 array:", -1);

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
srvsvc_dissect_SHARE_INFO_1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	dcerpc_info *di;

	di=pinfo->private_data;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "Share");
		tree = proto_item_add_subtree(item, ett_srvsvc_share_info_1);
	}

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Share", hf_srvsvc_share, 3);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_share_type, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Comment", hf_srvsvc_comment, 0);

	return offset;
}
static int
srvsvc_dissect_SHARE_INFO_1_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SHARE_INFO_1_array, NDR_POINTER_UNIQUE,
		"SHARE_INFO_1 array:", -1);

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
srvsvc_dissect_SHARE_INFO_2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	dcerpc_info *di;

	di=pinfo->private_data;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "Share");
		tree = proto_item_add_subtree(item, ett_srvsvc_share_info_2);
	}

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Share", hf_srvsvc_share, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_share_type, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Comment", hf_srvsvc_comment, 0);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_perm, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_max_uses, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_cur_uses, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Path", hf_srvsvc_path, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Password", 
			hf_srvsvc_share_passwd, 0);

	return offset;
}
static int
srvsvc_dissect_SHARE_INFO_2_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SHARE_INFO_2_array, NDR_POINTER_UNIQUE,
		"SHARE_INFO_2 array:", -1);

	return offset;
}

/*
  IDL typedef struct {
  IDL    [unique] [string] wchar_t *share;
  IDL    long type;
  IDL    [unique] [string] wchar_t *comment;
  IDL    long policy;
  IDL } SHARE_INFO_501;
*/
static int
srvsvc_dissect_SHARE_INFO_501(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	dcerpc_info *di;

	di=pinfo->private_data;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "Share");
		tree = proto_item_add_subtree(item, ett_srvsvc_share_info_501);
	}

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Share", hf_srvsvc_share, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_share_type, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Comment", hf_srvsvc_comment, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_policy, NULL);

	return offset;
}
static int
srvsvc_dissect_SHARE_INFO_501_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_501);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] SHARE_INFO_501 *shares;
 * IDL } SHARE_INFO_501_CONTAINER;
 */
static int
srvsvc_dissect_SHARE_INFO_501_CONTAINER(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SHARE_INFO_501_array, NDR_POINTER_UNIQUE,
		"SHARE_INFO_501 array:", -1);

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
srvsvc_dissect_SHARE_INFO_502(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, guint8 *drep)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	dcerpc_info *di;

	di=pinfo->private_data;
	if (parent_tree) {
		item = proto_tree_add_text(parent_tree, tvb, offset, -1, "Share");
		tree = proto_item_add_subtree(item, ett_srvsvc_share_info_502);
	}

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Share", hf_srvsvc_share, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_share_type, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Comment", hf_srvsvc_comment, 0);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_perm, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_max_uses, NULL);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_cur_uses, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Path", hf_srvsvc_path, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Password", 
			hf_srvsvc_share_passwd, 0);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_reserved, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			lsa_dissect_sec_desc_buf_data, NDR_POINTER_UNIQUE,
			"LSA SECURITY DESCRIPTOR data:", -1);

	return offset;
}
static int
srvsvc_dissect_SHARE_INFO_502_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SHARE_INFO_502_array, NDR_POINTER_UNIQUE,
		"SHARE_INFO_502 array:", -1);

	return offset;
}

#if 0
/*
  IDL typedef struct {
  IDL    [unique] [string] wchar_t *comment;
  IDL } SHARE_INFO_1004;
*/
static int
srvsvc_dissect_SHARE_INFO_1004(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Comment", hf_srvsvc_comment, 0);

	return offset;
}

static int
srvsvc_dissect_SHARE_INFO_1004_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	guint32 count;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, &count);

	if (count) {
	   offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		  srvsvc_dissect_SHARE_INFO_1004_array, NDR_POINTER_UNIQUE,
		  "SHARE_INFO_1004 array:", -1);
	}

	return offset;
}

/*
  IDL typedef struct {
  IDL    long dfs_root_flags;
  IDL } SHARE_INFO_1005;
*/
static int
srvsvc_dissect_SHARE_INFO_1005(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_dfs_root_flags, NULL);

	return offset;
}
static int
srvsvc_dissect_SHARE_INFO_1005_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1005);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] SHARE_INFO_1005 *shares;
 * IDL } SHARE_INFO_1005_CONTAINER;
 */
static int
srvsvc_dissect_SHARE_INFO_1005_CONTAINER(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SHARE_INFO_1005_array, NDR_POINTER_UNIQUE,
		"SHARE_INFO_1005 array:", -1);

	return offset;
}


/*
  IDL typedef struct {
  IDL    long max_uses;
  IDL } SHARE_INFO_1006;
*/
static int
srvsvc_dissect_SHARE_INFO_1006(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_max_uses, NULL);

	return offset;
}
static int
srvsvc_dissect_SHARE_INFO_1006_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
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
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SHARE_INFO_1006_array, NDR_POINTER_UNIQUE,
		"SHARE_INFO_1006 array:", -1);

	return offset;
}


/*
  IDL typedef struct {
  IDL    long flags;
  IDL    [unique] [string] wchar_t *alternate_directory_name;
  IDL } SHARE_INFO_1007;
*/
static int
srvsvc_dissect_SHARE_INFO_1007(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_share_flags, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Alternate Name", 
			hf_srvsvc_share_alternate_name, 0);

	return offset;
}
static int
srvsvc_dissect_SHARE_INFO_1007_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1007);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] SHARE_INFO_1007 *shares;
 * IDL } SHARE_INFO_1007_CONTAINER;
 */
static int
srvsvc_dissect_SHARE_INFO_1007_CONTAINER(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SHARE_INFO_1007_array, NDR_POINTER_UNIQUE,
		"SHARE_INFO_1007 array:", -1);

	return offset;
}

/*
  IDL typedef struct {
  IDL    SECDESC [unique] *securitysecriptor; 4byte-len followed by bytestring
  IDL } SHARE_INFO_1501;
*/
static int
srvsvc_dissect_SHARE_INFO_1501(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			lsa_dissect_sec_desc_buf_data, NDR_POINTER_UNIQUE,
			"LSA SECURITY DESCRIPTOR data:", -1);

	return offset;
}
static int
srvsvc_dissect_SHARE_INFO_1501_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1501);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] SHARE_INFO_1501 *shares;
 * IDL } SHARE_INFO_1501_CONTAINER;
 */
static int
srvsvc_dissect_SHARE_INFO_1501_CONTAINER(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SHARE_INFO_1501_array, NDR_POINTER_UNIQUE,
		"SHARE_INFO_1501 array:", -1);

	return offset;
}
#endif

/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(0)] [unique] SHARE_INFO_0 *share0;
 * IDL   [case(1)] [unique] SHARE_INFO_1 *share1;
 * IDL   [case(2)] [unique] SHARE_INFO_2 *share2;
 * IDL   [case(501)] [unique] SHARE_INFO_501 *share501;
 * IDL   [case(502)] [unique] SHARE_INFO_502 *share502;
 * IDL   [case(1004)] [unique] SHARE_INFO_1004 *share1004;
 * IDL   [case(1005)] [unique] SHARE_INFO_1005 *share1005;
 * IDL   [case(1006)] [unique] SHARE_INFO_1006 *share1006;
 * IDL   [case(1007)] [unique] SHARE_INFO_1007 *share1007;
 * IDL   [case(1501)] [unique] SHARE_INFO_1501 *share1501;
 * IDL } SHARE_INFO_UNION;
 */
static int
srvsvc_dissect_SHARE_INFO_UNION(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	guint32 level;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_0,
			NDR_POINTER_UNIQUE, "SHARE_INFO_0:", -1);
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1:", -1);
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_2,
			NDR_POINTER_UNIQUE, "SHARE_INFO_2:", -1);
		break;
	case 501:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_501,
			NDR_POINTER_UNIQUE, "SHARE_INFO_501:", -1);
		break;
	case 502:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_502,
			NDR_POINTER_UNIQUE, "SHARE_INFO_502:", -1);
		break;
	/*
	 * These next lot do not seem to be understood by Windows of any
	 * flavor
	 */
#if 0
	case 1004:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1004,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1004:", -1);
		break;
	case 1005:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1005,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1005:", -1);
		break;
	case 1006:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1006,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1006:", -1);
		break;
	case 1007:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1007,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1007:", -1);
		break;
	case 1501:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1501,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1501:", -1);
		break;
#endif
	}

	return offset;
}


/*
 * IDL long NetrShareAdd(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long Level,
 * IDL      [in] [ref] SHARE_INFO_UNION *share,
 * IDL      [in] [out] [unique] long *ParmError
 * IDL );
*/
static int
srvsvc_dissect_netrshareadd_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_SHARE_INFO_UNION,
		NDR_POINTER_REF, "SHARE_INFO_UNION:", -1);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_pointer_long, NDR_POINTER_UNIQUE,
			"Parameter Error:", hf_srvsvc_parm_error);

	return offset;
}
static int
srvsvc_dissect_netrshareadd_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_pointer_long, NDR_POINTER_UNIQUE,
			"Parameter Error:", hf_srvsvc_parm_error);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}


/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(0)] [unique] SHARE_INFO_0_CONTAINER *share0;
 * IDL   [case(1)] [unique] SHARE_INFO_1_CONTAINER *share1;
 * IDL   [case(2)] [unique] SHARE_INFO_2_CONTAINER *share2;
 * IDL   [case(501)] [unique] SHARE_INFO_501_CONTAINER *share501;
 * IDL   [case(502)] [unique] SHARE_INFO_502_CONTAINER *share502;
 * IDL   [case(1004)] [unique] SHARE_INFO_1004_CONTAINER *share1004;
 * IDL   [case(1005)] [unique] SHARE_INFO_1005_CONTAINER *share1005;
 * IDL   [case(1006)] [unique] SHARE_INFO_1006_CONTAINER *share1006;
 * IDL   [case(1007)] [unique] SHARE_INFO_1007_CONTAINER *share1007;
 * IDL   [case(1501)] [unique] SHARE_INFO_1501_CONTAINER *share1501;
 * IDL } SHARE_ENUM_UNION;
 */
static int
srvsvc_dissect_SHARE_ENUM_UNION(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	guint32 level;
	dcerpc_info *di;

	di = pinfo->private_data;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_0_CONTAINER,
			NDR_POINTER_UNIQUE, "SHARE_INFO_0_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", SHARE_INFO_0 level");
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1_CONTAINER,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", SHARE_INFO_1 level");
		break;
	case 2:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_2_CONTAINER,
			NDR_POINTER_UNIQUE, "SHARE_INFO_2_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", SHARE_INFO_2 level");
		break;
	case 501:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_501_CONTAINER,
			NDR_POINTER_UNIQUE, "SHARE_INFO_501_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", SHARE_INFO_501 level");
		break;
	case 502:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_502_CONTAINER,
			NDR_POINTER_UNIQUE, "SHARE_INFO_502_CONTAINER:", -1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", SHARE_INFO_502 level");
		break;
#if 0
	case 1004:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1004_CONTAINER,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1004_CONTAINER:", -1);
		break;
	case 1005:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1005_CONTAINER,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1005_CONTAINER:", -1);
		break;
	case 1006:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1006_CONTAINER,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1006_CONTAINER:", -1);
		break;
	case 1007:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1007_CONTAINER,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1007_CONTAINER:", -1);
		break;
	case 1501:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_1501_CONTAINER,
			NDR_POINTER_UNIQUE, "SHARE_INFO_1501_CONTAINER:", -1);
		break;
#endif
	}

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   SHARE_ENUM_UNION shares;
 * IDL } SHARE_ENUM_STRUCT;
 */
static int
srvsvc_dissect_SHARE_ENUM_STRUCT(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = srvsvc_dissect_SHARE_ENUM_UNION(tvb, offset, pinfo, tree, drep);

	return offset;
}

/*
 * IDL long NetrShareEnum(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL	    [in] [out] level
 * IDL      [in] [out] [ref] SHARE_ENUM_STRUCT *share,
 * IDL      [in] long MaxLen,
 * IDL      [out] long Entries,
 * IDL      [in] [out] [unique] *ResumeHandle
 * IDL );
 */
static int
srvsvc_dissect_netrshareenum_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_ENUM_UNION,
			NDR_POINTER_REF, "Shares", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_preferred_len, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_ENUM_HANDLE,
			NDR_POINTER_UNIQUE, "Enum Handle", -1);

	return offset;
}

static int
srvsvc_dissect_netrshareenum_reply(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_ENUM_UNION,
			NDR_POINTER_REF, "Shares", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_total_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_ENUM_HANDLE,
			NDR_POINTER_UNIQUE, "Enum Handle", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
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
				     guint8 *drep)
{
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
		"Server", hf_srvsvc_server, cb_wstr_postprocess,
		GINT_TO_POINTER(CB_STR_COL_INFO | 1));

	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_REF,
		"Share", hf_srvsvc_share, cb_wstr_postprocess,
		GINT_TO_POINTER(CB_STR_COL_INFO | 1));

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	return offset;
}

static int
srvsvc_dissect_netrsharegetinfo_reply(tvbuff_t *tvb, int offset,
				      packet_info *pinfo, proto_tree *tree,
				      guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_UNION,
			NDR_POINTER_REF, "Share:", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrShareSetInfo(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *ShareName,
 * IDL      [in] long Level,
 * IDL      [in] [ref] SHARE_INFO_UNION *share
 * IDL      [in] [out] [unique] long *ParmError,
 * IDL );
 */
static int
srvsvc_dissect_netrsharesetinfo_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Share", hf_srvsvc_share, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_INFO_UNION,
			NDR_POINTER_REF, "Share:", -1);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_pointer_long, NDR_POINTER_UNIQUE,
			"Parameter Error:", hf_srvsvc_parm_error);

	return offset;
}
static int
srvsvc_dissect_netrsharesetinfo_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_pointer_long, NDR_POINTER_UNIQUE,
			"Parameter Error:", hf_srvsvc_parm_error);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrShareDel(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *ShareName,
 * IDL      [in] long Reserved,
 * IDL );
 */
static int
srvsvc_dissect_netrsharedel_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Share", hf_srvsvc_share, 0);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_reserved, NULL);

	return offset;
}
static int
srvsvc_dissect_netrsharedel_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrShareDelSticky(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *ShareName,
 * IDL      [in] long Reserved,
 * IDL );
 */
static int
srvsvc_dissect_netrsharedelsticky_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Share", hf_srvsvc_share, 0);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_reserved, NULL);

	return offset;
}
static int
srvsvc_dissect_netrsharedelsticky_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrShareCheck(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *DeviceName,
 * IDL      [out] long type
 * IDL );
 */
static int
srvsvc_dissect_netrsharecheck_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Char Device", hf_srvsvc_chrdev, 0);

	return offset;
}
static int
srvsvc_dissect_netrsharecheck_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_share_type, NULL);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long platform_id;
 * IDL   [string] [unique] wchar_t *server;
 * IDL } SERVER_INFO_100;
 */
static int
srvsvc_dissect_SERVER_INFO_100(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_platform_id, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long platform_id;
 * IDL   [string] [unique] wchar_t *server;
 * IDL   long ver_major;
 * IDL   long ver_minor;
 * IDL   long type;
 * IDL   [string] [unique] wchar_t *comment;
 * IDL } SERVER_INFO_101;
 */
static int
srvsvc_dissect_SERVER_INFO_101(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_platform_id, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_ver_major, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_ver_minor, NULL);

	offset = dissect_smb_server_type_flags(
		tvb, offset, pinfo, tree, drep, TRUE);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Comment", hf_srvsvc_comment, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long platform_id;
 * IDL   [string] [unique] wchar_t *server;
 * IDL   long ver_major;
 * IDL   long ver_minor;
 * IDL   long type;
 * IDL   [string] [unique] wchar_t *comment;
 * IDL   long users;
 * IDL   long disc;
 * IDL   long hidden;
 * IDL   long announce;
 * IDL   long anndelta;
 * IDL   long licences;
 * IDL   [string] [unique] wchar_t *userpath;
 * IDL } SERVER_INFO_102;
 */
static int
srvsvc_dissect_SERVER_INFO_102(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_platform_id, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_ver_major, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_ver_minor, NULL);

	offset = dissect_smb_server_type_flags(
		tvb, offset, pinfo, tree, drep, TRUE);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Comment", hf_srvsvc_comment, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_users, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_disc, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_hidden, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_announce, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_anndelta, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_licences, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "User Path", hf_srvsvc_user_path, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long ulist_mtime;
 * IDL   long glist_mtime;
 * IDL   long alist_mtime;
 * IDL   [string] [unique] wchar_t *alerts;
 * IDL   long security;
 * IDL   long numadmin;
 * IDL   long lanmask;
 * IDL   [string] [unique] wchar_t *guestaccount;
 * IDL   long chdevs;
 * IDL   long chdevqs;
 * IDL   long chdevjobs;
 * IDL   long connections;
 * IDL   long shares;
 * IDL   long openfiles;
 * IDL   long sessopens;
 * IDL   long sessvcs;
 * IDL   long sessreqs;
 * IDL   long opensearch;
 * IDL   long activelocks;
 * IDL   long sizreqbufs
 * IDL   long numbigbufs
 * IDL   long numfiletasks;
 * IDL   long alertsched;
 * IDL   long erroralert;
 * IDL   long logonalert;
 * IDL   long accessalert;
 * IDL   long diskalert;
 * IDL   long netioalert;
 * IDL   long maxauditsz;
 * IDL   [string] [unique] wchar_t *srvheuristics;
 * IDL } SERVER_INFO_402;
 */
static int
srvsvc_dissect_SERVER_INFO_402(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_ulist_mtime, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_glist_mtime, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_alist_mtime, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Alerts", hf_srvsvc_alerts, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_security, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_numadmin, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_lanmask, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Guest", hf_srvsvc_guest, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_chdevs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_chdevqs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_chdevjobs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_connections, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_shares, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_openfiles, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sessopens, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sessvcs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sessreqs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_opensearch, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_activelocks, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sizreqbufs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_numbigbufs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_numfiletasks, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_alertsched, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_erroralert, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_logonalert, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_accessalert, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_diskalert, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_netioalert, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxauditsz, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server Heuristics", 
			hf_srvsvc_srvheuristics, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long ulist_mtime;
 * IDL   long glist_mtime;
 * IDL   long alist_mtime;
 * IDL   [string] [unique] wchar_t *alerts;
 * IDL   long security;
 * IDL   long numadmin;
 * IDL   long lanmask;
 * IDL   [string] [unique] wchar_t *guestaccount;
 * IDL   long chdevs;
 * IDL   long chdevqs;
 * IDL   long chdevjobs;
 * IDL   long connections;
 * IDL   long shares;
 * IDL   long openfiles;
 * IDL   long sessopens;
 * IDL   long sessvcs;
 * IDL   long sessreqs;
 * IDL   long opensearch;
 * IDL   long activelocks;
 * IDL   long sizreqbufs
 * IDL   long numbigbufs
 * IDL   long numfiletasks;
 * IDL   long alertsched;
 * IDL   long erroralert;
 * IDL   long logonalert;
 * IDL   long accessalert;
 * IDL   long diskalert;
 * IDL   long netioalert;
 * IDL   long maxauditsz;
 * IDL   [string] [unique] wchar_t *srvheuristics;
 * IDL   long auditedevents;
 * IDL   long auditprofile;
 * IDL   [string] [unique] wchar_t *autopath;
 * IDL } SERVER_INFO_403;
 */
static int
srvsvc_dissect_SERVER_INFO_403(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_ulist_mtime, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_glist_mtime, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_alist_mtime, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Alerts", hf_srvsvc_alerts, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_security, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_numadmin, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_lanmask, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Guest", hf_srvsvc_guest, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_chdevs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_chdevqs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_chdevjobs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_connections, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_shares, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_openfiles, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sessopens, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sessvcs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sessreqs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_opensearch, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_activelocks, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sizreqbufs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_numbigbufs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_numfiletasks, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_alertsched, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_erroralert, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_logonalert, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_accessalert, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_diskalert, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_netioalert, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxauditsz, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server Heuristics", 
			hf_srvsvc_srvheuristics, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_auditedevents, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_auditprofile, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Autopath", hf_srvsvc_autopath, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long sessopens;
 * IDL   long sessvcs;
 * IDL   long opensearch;
 * IDL   long sizreqbufs
 * IDL   long initworkitems;
 * IDL   long maxworkitems;
 * IDL   long rawworkitems;
 * IDL   long irpstacksize;
 * IDL   long maxrawbuflen;
 * IDL   long sessusers;
 * IDL   long sessconns;
 * IDL   long maxpagedmemoryusage;
 * IDL   long maxnonpagedmemoryusage;
 * IDL   long enablesoftcompat;
 * IDL   long enableforcedlogoff;
 * IDL   long timesource
 * IDL   long acceptdownlevelapis;
 * IDL   long lmannounce;
 * IDL } SERVER_INFO_502;
 */
static int
srvsvc_dissect_SERVER_INFO_502(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sessopens, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sessvcs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_opensearch, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sizreqbufs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_initworkitems, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxworkitems, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rawworkitems, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_irpstacksize, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxrawbuflen, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_srvsvc_users, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_connections, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxpagedmemoryusage, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxnonpagedmemoryusage, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enablesoftcompat, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enableforcedlogoff, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_timesource, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_acceptdownlevelapis, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_lmannounce, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long sessopens;
 * IDL   long sessvcs;
 * IDL   long opensearch;
 * IDL   long sizreqbufs
 * IDL   long initworkitems;
 * IDL   long maxworkitems;
 * IDL   long rawworkitems;
 * IDL   long irpstacksize;
 * IDL   long maxrawbuflen;
 * IDL   long sessusers;
 * IDL   long sessconns;
 * IDL   long maxpagedmemoryusage;
 * IDL   long maxnonpagedmemoryusage;
 * IDL   long enablesoftcompat;
 * IDL   long enableforcedlogoff;
 * IDL   long timesource
 * IDL   long acceptdownlevelapis;
 * IDL   long lmannounce;
 * IDL   [string] [unique] wchar_t *domain;
 * IDL   long maxcopyreadlen;
 * IDL   long maxcopywritelen;
 * IDL   long minkeepsearch;
 * IDL   long mankeepsearch;
 * IDL   long minkeepcomplsearch;
 * IDL   long mankeepcomplsearch;
 * IDL   long threadcountadd;
 * IDL   long numblockthreads;
 * IDL   long scavtimeout;
 * IDL   long minrcvqueue;
 * IDL   long minfreeworkitems;
 * IDL   long xactmemsize;
 * IDL   long threadpriority;
 * IDL   long maxmpxct;
 * IDL   long oplockbreakwait;
 * IDL   long oplockbreakresponsewait;
 * IDL   long enableoplocks;
 * IDL   long enableoplockforceclose
 * IDL   long enablefcbopens;
 * IDL   long enableraw;
 * IDL   long enablesharednetdrives;
 * IDL   long minfreeconnections;
 * IDL   long maxfreeconnections;
 * IDL } SERVER_INFO_503;
 */
static int
srvsvc_dissect_SERVER_INFO_503(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sessopens, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sessvcs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_opensearch, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sizreqbufs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_initworkitems, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxworkitems, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rawworkitems, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_irpstacksize, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxrawbuflen, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_srvsvc_users, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_connections, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxpagedmemoryusage, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxnonpagedmemoryusage, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enablesoftcompat, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enableforcedlogoff, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_timesource, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_acceptdownlevelapis, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_lmannounce, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Domain", hf_srvsvc_domain, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxcopyreadlen, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxcopywritelen, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minkeepsearch, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxkeepsearch, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minkeepcomplsearch, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxkeepcomplsearch, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_threadcountadd, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_numblockthreads, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_scavtimeout, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minrcvqueue, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minfreeworkitems, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_xactmemsize, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_threadpriority, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxmpxct, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_oplockbreakwait, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_oplockbreakresponsewait, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enableoplocks, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enableoplockforceclose, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enablefcbopens, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enableraw, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enablesharednetdrives, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minfreeconnections, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxfreeconnections, NULL);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   long sessopens;
 * IDL   long sessvcs;
 * IDL   long opensearch;
 * IDL   long sizreqbufs
 * IDL   long initworkitems;
 * IDL   long maxworkitems;
 * IDL   long rawworkitems;
 * IDL   long irpstacksize;
 * IDL   long maxrawbuflen;
 * IDL   long sessusers;
 * IDL   long sessconns;
 * IDL   long maxpagedmemoryusage;
 * IDL   long maxnonpagedmemoryusage;
 * IDL   long enablesoftcompat;
 * IDL   long enableforcedlogoff;
 * IDL   long timesource
 * IDL   long acceptdownlevelapis;
 * IDL   long lmannounce;
 * IDL   [string] [unique] wchar_t *domain;
 * IDL   long maxcopyreadlen;
 * IDL   long maxcopywritelen;
 * IDL   long minkeepsearch;
 * IDL   long mankeepsearch;
 * IDL   long minkeepcomplsearch;
 * IDL   long mankeepcomplsearch;
 * IDL   long threadcountadd;
 * IDL   long numblockthreads;
 * IDL   long scavtimeout;
 * IDL   long minrcvqueue;
 * IDL   long minfreeworkitems;
 * IDL   long xactmemsize;
 * IDL   long threadpriority;
 * IDL   long maxmpxct;
 * IDL   long oplockbreakwait;
 * IDL   long oplockbreakresponsewait;
 * IDL   long enableoplocks;
 * IDL   long enableoplockforceclose
 * IDL   long enablefcbopens;
 * IDL   long enableraw;
 * IDL   long enablesharednetdrives;
 * IDL   long minfreeconnections;
 * IDL   long maxfreeconnections;
 * IDL   long initsesstable;
 * IDL   long initconntable;
 * IDL   long initfiletable;
 * IDL   long initsearchtable;
 * IDL   long alertsched;
 * IDL   long errortreshold;
 * IDL   long networkerrortreshold;
 * IDL   long diskspacetreshold;
 * IDL   long reserved;
 * IDL   long maxlinkdelay;
 * IDL   long minlinkthroughput;
 * IDL   long linkinfovalidtime;
 * IDL   long scavqosinfoupdatetime;
 * IDL   long maxworkitemidletime;
 * IDL } SERVER_INFO_599;
 */
static int
srvsvc_dissect_SERVER_INFO_599(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sessopens, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sessvcs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_opensearch, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sizreqbufs, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_initworkitems, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxworkitems, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rawworkitems, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_irpstacksize, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxrawbuflen, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_srvsvc_users, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_connections, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxpagedmemoryusage, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxnonpagedmemoryusage, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enablesoftcompat, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enableforcedlogoff, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_timesource, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_acceptdownlevelapis, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_lmannounce, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Domain", hf_srvsvc_domain, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxcopyreadlen, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxcopywritelen, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minkeepsearch, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxkeepsearch, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minkeepcomplsearch, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxkeepcomplsearch, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_threadcountadd, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_numblockthreads, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_scavtimeout, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minrcvqueue, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minfreeworkitems, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_xactmemsize, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_threadpriority, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxmpxct, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_oplockbreakwait, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_oplockbreakresponsewait, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enableoplocks, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enableoplockforceclose, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enablefcbopens, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enableraw, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enablesharednetdrives, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minfreeconnections, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxfreeconnections, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_initsesstable, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_initconntable, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_initfiletable, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_initsearchtable, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_alertsched, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_errortreshold, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_networkerrortreshold, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_diskspacetreshold, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_srvsvc_reserved, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_srvsvc_reserved, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxlinkdelay, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minlinkthroughput, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_srvsvc_linkinfovalidtime, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_srvsvc_scavqosinfoupdatetime, NULL);

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxworkitemidletime, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   [string] [unique] wchar_t *comment;
 * IDL } SERVER_INFO_1005;
 */
static int
srvsvc_dissect_SERVER_INFO_1005(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Comment", hf_srvsvc_comment, 0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long disc;
 * IDL } SERVER_INFO_1010;
 */
static int
srvsvc_dissect_SERVER_INFO_1010(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_disc, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long hidden;
 * IDL } SERVER_INFO_1016;
 */
static int
srvsvc_dissect_SERVER_INFO_1016(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_hidden, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long announce;
 * IDL } SERVER_INFO_1017;
 */
static int
srvsvc_dissect_SERVER_INFO_1017(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_announce, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long anndelta;
 * IDL } SERVER_INFO_1018;
 */
static int
srvsvc_dissect_SERVER_INFO_1018(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_anndelta, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long users;
 * IDL } SERVER_INFO_1107;
 */
static int
srvsvc_dissect_SERVER_INFO_1107(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_users, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long sessopens;
 * IDL } SERVER_INFO_1501;
 */
static int
srvsvc_dissect_SERVER_INFO_1501(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sessopens, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long sessvcs;
 * IDL } SERVER_INFO_1502;
 */
static int
srvsvc_dissect_SERVER_INFO_1502(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_sessvcs, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long opensearch;
 * IDL } SERVER_INFO_1503;
 */
static int
srvsvc_dissect_SERVER_INFO_1503(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_opensearch, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long maxworkitems;
 * IDL } SERVER_INFO_1506;
 */
static int
srvsvc_dissect_SERVER_INFO_1506(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxworkitems, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long maxrawbuflen;
 * IDL } SERVER_INFO_1509;
 */
static int
srvsvc_dissect_SERVER_INFO_1509(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxrawbuflen, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long sessusers;
 * IDL } SERVER_INFO_1510;
 */
static int
srvsvc_dissect_SERVER_INFO_1510(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_srvsvc_users, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long sessconns;
 * IDL } SERVER_INFO_1511;
 */
static int
srvsvc_dissect_SERVER_INFO_1511(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_connections, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long maxnonpagedmemoryusage;
 * IDL } SERVER_INFO_1512;
 */
static int
srvsvc_dissect_SERVER_INFO_1512(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxnonpagedmemoryusage, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long maxpagedmemoryusage;
 * IDL } SERVER_INFO_1513;
 */
static int
srvsvc_dissect_SERVER_INFO_1513(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxpagedmemoryusage, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long enablesoftcompat;
 * IDL } SERVER_INFO_1514;
 */
static int
srvsvc_dissect_SERVER_INFO_1514(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enablesoftcompat, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long enableforcedlogoff;
 * IDL } SERVER_INFO_1515;
 */
static int
srvsvc_dissect_SERVER_INFO_1515(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enableforcedlogoff, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long timesource;
 * IDL } SERVER_INFO_1516;
 */
static int
srvsvc_dissect_SERVER_INFO_1516(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_timesource, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long lmannounce;
 * IDL } SERVER_INFO_1518;
 */
static int
srvsvc_dissect_SERVER_INFO_1518(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_lmannounce, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long maxcopyreadlen;
 * IDL } SERVER_INFO_1520;
 */
static int
srvsvc_dissect_SERVER_INFO_1520(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxcopyreadlen, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long maxcopywritelen;
 * IDL } SERVER_INFO_1521;
 */
static int
srvsvc_dissect_SERVER_INFO_1521(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxcopywritelen, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long minkeepsearch;
 * IDL } SERVER_INFO_1522;
 */
static int
srvsvc_dissect_SERVER_INFO_1522(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minkeepsearch, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long maxkeepsearch;
 * IDL } SERVER_INFO_1523;
 */
static int
srvsvc_dissect_SERVER_INFO_1523(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxkeepsearch, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long minkeepcomplsearch;
 * IDL } SERVER_INFO_1524;
 */
static int
srvsvc_dissect_SERVER_INFO_1524(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minkeepcomplsearch, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long maxkeepcomplsearch;
 * IDL } SERVER_INFO_1525;
 */
static int
srvsvc_dissect_SERVER_INFO_1525(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxkeepcomplsearch, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long scavtimeout;
 * IDL } SERVER_INFO_1528;
 */
static int
srvsvc_dissect_SERVER_INFO_1528(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_scavtimeout, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long minrcvqueue;
 * IDL } SERVER_INFO_1529;
 */
static int
srvsvc_dissect_SERVER_INFO_1529(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minrcvqueue, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long minfreeworkitems;
 * IDL } SERVER_INFO_1530;
 */
static int
srvsvc_dissect_SERVER_INFO_1530(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minfreeworkitems, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long maxmpxct;
 * IDL } SERVER_INFO_1533;
 */
static int
srvsvc_dissect_SERVER_INFO_1533(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxmpxct, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long oplockbreakwait;
 * IDL } SERVER_INFO_1534;
 */
static int
srvsvc_dissect_SERVER_INFO_1534(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_oplockbreakwait, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long oplockbreakresponsewait;
 * IDL } SERVER_INFO_1535;
 */
static int
srvsvc_dissect_SERVER_INFO_1535(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_oplockbreakresponsewait, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long enableoplocks;
 * IDL } SERVER_INFO_1536;
 */
static int
srvsvc_dissect_SERVER_INFO_1536(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enableoplocks, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long enableoplockforceclose;
 * IDL } SERVER_INFO_1537;
 */
static int
srvsvc_dissect_SERVER_INFO_1537(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enableoplockforceclose, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long enablefcbopens;
 * IDL } SERVER_INFO_1538;
 */
static int
srvsvc_dissect_SERVER_INFO_1538(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enablefcbopens, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long enableraw;
 * IDL } SERVER_INFO_1539;
 */
static int
srvsvc_dissect_SERVER_INFO_1539(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enableraw, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long enablesharednetdrives;
 * IDL } SERVER_INFO_1540;
 */
static int
srvsvc_dissect_SERVER_INFO_1540(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_enablesharednetdrives, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long minfreeconnections;
 * IDL } SERVER_INFO_1541;
 */
static int
srvsvc_dissect_SERVER_INFO_1541(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minfreeconnections, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long maxfreeconnections;
 * IDL } SERVER_INFO_1542;
 */
static int
srvsvc_dissect_SERVER_INFO_1542(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxfreeconnections, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long initsesstable;
 * IDL } SERVER_INFO_1543;
 */
static int
srvsvc_dissect_SERVER_INFO_1543(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_initsesstable, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long initconntable;
 * IDL } SERVER_INFO_1544;
 */
static int
srvsvc_dissect_SERVER_INFO_1544(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_initconntable, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long initfiletable;
 * IDL } SERVER_INFO_1545;
 */
static int
srvsvc_dissect_SERVER_INFO_1545(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_initfiletable, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long initsearchtable;
 * IDL } SERVER_INFO_1546;
 */
static int
srvsvc_dissect_SERVER_INFO_1546(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_initsearchtable, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long alertsched;
 * IDL } SERVER_INFO_1547;
 */
static int
srvsvc_dissect_SERVER_INFO_1547(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_alertsched, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long errortreshold;
 * IDL } SERVER_INFO_1548;
 */
static int
srvsvc_dissect_SERVER_INFO_1548(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_errortreshold, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long networkerrortreshold;
 * IDL } SERVER_INFO_1549;
 */
static int
srvsvc_dissect_SERVER_INFO_1549(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_networkerrortreshold, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long diskspacetreshold;
 * IDL } SERVER_INFO_1550;
 */
static int
srvsvc_dissect_SERVER_INFO_1550(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_diskspacetreshold, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long maxlinkdelay;
 * IDL } SERVER_INFO_1552;
 */
static int
srvsvc_dissect_SERVER_INFO_1552(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxlinkdelay, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long minlinkthroughput;
 * IDL } SERVER_INFO_1553;
 */
static int
srvsvc_dissect_SERVER_INFO_1553(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_minlinkthroughput, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long linkinfovalidtime;
 * IDL } SERVER_INFO_1554;
 */
static int
srvsvc_dissect_SERVER_INFO_1554(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_linkinfovalidtime, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long scavqosinfoupdatetime;
 * IDL } SERVER_INFO_1555;
 */
static int
srvsvc_dissect_SERVER_INFO_1555(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_scavqosinfoupdatetime, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long maxworkitemidletime;
 * IDL } SERVER_INFO_1556;
 */
static int
srvsvc_dissect_SERVER_INFO_1556(tvbuff_t *tvb, int offset,
				   packet_info *pinfo, proto_tree *tree,
				   guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_maxworkitemidletime, NULL);

	return offset;
}

/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(100)] [unique] SERVER_INFO_100 *srv100;
 * IDL   [case(101)] [unique] SERVER_INFO_101 *srv101;
 * IDL   [case(102)] [unique] SERVER_INFO_102 *srv102;
 * IDL   [case(402)] [unique] SERVER_INFO_402 *srv402;
 * IDL   [case(403)] [unique] SERVER_INFO_403 *srv403;
 * IDL   [case(502)] [unique] SERVER_INFO_502 *srv502;
 * IDL   [case(503)] [unique] SERVER_INFO_503 *srv503;
 * IDL   [case(599)] [unique] SERVER_INFO_599 *srv599;
 * IDL   [case(1005)] [unique] SERVER_INFO_1005 *srv1005;
 * IDL   [case(1010)] [unique] SERVER_INFO_1010 *srv1010;
 * IDL   [case(1016)] [unique] SERVER_INFO_1016 *srv1016;
 * IDL   [case(1017)] [unique] SERVER_INFO_1017 *srv1017;
 * IDL   [case(1018)] [unique] SERVER_INFO_1018 *srv1018;
 * IDL   [case(1107)] [unique] SERVER_INFO_1107 *srv1107;
 * IDL   [case(1501)] [unique] SERVER_INFO_1501 *srv1501;
 * IDL   [case(1502)] [unique] SERVER_INFO_1502 *srv1502;
 * IDL   [case(1503)] [unique] SERVER_INFO_1503 *srv1503;
 * IDL   [case(1506)] [unique] SERVER_INFO_1506 *srv1506;
 * IDL   [case(1509)] [unique] SERVER_INFO_1509 *srv1509;
 * IDL   [case(1510)] [unique] SERVER_INFO_1510 *srv1510;
 * IDL   [case(1511)] [unique] SERVER_INFO_1511 *srv1511;
 * IDL   [case(1512)] [unique] SERVER_INFO_1512 *srv1512;
 * IDL   [case(1513)] [unique] SERVER_INFO_1513 *srv1513;
 * IDL   [case(1514)] [unique] SERVER_INFO_1514 *srv1514;
 * IDL   [case(1515)] [unique] SERVER_INFO_1515 *srv1515;
 * IDL   [case(1516)] [unique] SERVER_INFO_1516 *srv1516;
 * IDL   [case(1518)] [unique] SERVER_INFO_1518 *srv1518;
 * IDL   [case(1520)] [unique] SERVER_INFO_1520 *srv1520;
 * IDL   [case(1521)] [unique] SERVER_INFO_1521 *srv1521;
 * IDL   [case(1522)] [unique] SERVER_INFO_1522 *srv1522;
 * IDL   [case(1523)] [unique] SERVER_INFO_1523 *srv1523;
 * IDL   [case(1524)] [unique] SERVER_INFO_1524 *srv1524;
 * IDL   [case(1525)] [unique] SERVER_INFO_1525 *srv1525;
 * IDL   [case(1528)] [unique] SERVER_INFO_1528 *srv1528;
 * IDL   [case(1529)] [unique] SERVER_INFO_1529 *srv1529;
 * IDL   [case(1530)] [unique] SERVER_INFO_1530 *srv1530;
 * IDL   [case(1533)] [unique] SERVER_INFO_1533 *srv1533;
 * IDL   [case(1534)] [unique] SERVER_INFO_1534 *srv1534;
 * IDL   [case(1535)] [unique] SERVER_INFO_1535 *srv1535;
 * IDL   [case(1536)] [unique] SERVER_INFO_1536 *srv1536;
 * IDL   [case(1537)] [unique] SERVER_INFO_1537 *srv1537;
 * IDL   [case(1538)] [unique] SERVER_INFO_1538 *srv1538;
 * IDL   [case(1539)] [unique] SERVER_INFO_1539 *srv1539;
 * IDL   [case(1540)] [unique] SERVER_INFO_1540 *srv1540;
 * IDL   [case(1541)] [unique] SERVER_INFO_1541 *srv1541;
 * IDL   [case(1542)] [unique] SERVER_INFO_1542 *srv1542;
 * IDL   [case(1543)] [unique] SERVER_INFO_1543 *srv1543;
 * IDL   [case(1544)] [unique] SERVER_INFO_1544 *srv1544;
 * IDL   [case(1545)] [unique] SERVER_INFO_1545 *srv1545;
 * IDL   [case(1546)] [unique] SERVER_INFO_1546 *srv1546;
 * IDL   [case(1547)] [unique] SERVER_INFO_1547 *srv1547;
 * IDL   [case(1548)] [unique] SERVER_INFO_1548 *srv1548;
 * IDL   [case(1549)] [unique] SERVER_INFO_1549 *srv1549;
 * IDL   [case(1550)] [unique] SERVER_INFO_1550 *srv1550;
 * IDL   [case(1552)] [unique] SERVER_INFO_1552 *srv1552;
 * IDL   [case(1553)] [unique] SERVER_INFO_1553 *srv1553;
 * IDL   [case(1554)] [unique] SERVER_INFO_1554 *srv1554;
 * IDL   [case(1555)] [unique] SERVER_INFO_1555 *srv1555;
 * IDL   [case(1556)] [unique] SERVER_INFO_1556 *srv1556;
 * IDL } SERVER_INFO_UNION;
 */
static int
srvsvc_dissect_SERVER_INFO_UNION(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	guint32 level;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 100:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_100,
			NDR_POINTER_UNIQUE, "SERVER_INFO_100:", -1);
		break;

	case 101:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_101,
			NDR_POINTER_UNIQUE, "SERVER_INFO_101:", -1);
		break;

	case 102:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_102,
			NDR_POINTER_UNIQUE, "SERVER_INFO_102:", -1);
		break;

	case 402:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_402,
			NDR_POINTER_UNIQUE, "SERVER_INFO_402:", -1);
		break;

	case 403:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_403,
			NDR_POINTER_UNIQUE, "SERVER_INFO_403:", -1);
		break;

	case 502:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_502,
			NDR_POINTER_UNIQUE, "SERVER_INFO_502:", -1);
		break;

	case 503:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_503,
			NDR_POINTER_UNIQUE, "SERVER_INFO_503:", -1);
		break;

	case 599:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_599,
			NDR_POINTER_UNIQUE, "SERVER_INFO_599:", -1);
		break;

	case 1005:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1005,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1005:", -1);
		break;

	case 1010:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1010,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1010:", -1);
		break;

	case 1016:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1016,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1016:", -1);
		break;

	case 1017:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1017,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1017:", -1);
		break;

	case 1018:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1018,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1018:", -1);
		break;

	case 1107:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1107,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1107:", -1);
		break;

	case 1501:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1501,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1501:", -1);
		break;

	case 1502:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1502,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1502:", -1);
		break;

	case 1503:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1503,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1503:", -1);
		break;

	case 1506:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1506,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1506:", -1);
		break;

	case 1509:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1509,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1509:", -1);
		break;

	case 1510:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1510,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1510:", -1);
		break;

	case 1511:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1511,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1511:", -1);
		break;

	case 1512:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1512,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1512:", -1);
		break;

	case 1513:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1513,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1513:", -1);
		break;

	case 1514:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1514,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1514:", -1);
		break;

	case 1515:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1515,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1515:", -1);
		break;

	case 1516:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1516,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1516:", -1);
		break;

	case 1518:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1518,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1518:", -1);
		break;

	case 1520:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1520,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1520:", -1);
		break;

	case 1521:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1521,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1521:", -1);
		break;

	case 1522:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1522,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1522:", -1);
		break;

	case 1523:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1523,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1523:", -1);
		break;

	case 1524:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1524,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1524:", -1);
		break;

	case 1525:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1525,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1525:", -1);
		break;

	case 1528:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1528,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1528:", -1);
		break;

	case 1529:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1529,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1529:", -1);
		break;

	case 1530:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1530,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1530:", -1);
		break;

	case 1533:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1533,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1533:", -1);
		break;

	case 1534:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1534,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1534:", -1);
		break;

	case 1535:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1535,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1535:", -1);
		break;

	case 1536:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1536,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1536:", -1);
		break;

	case 1537:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1537,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1537:", -1);
		break;

	case 1538:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1538,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1538:", -1);
		break;

	case 1539:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1539,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1539:", -1);
		break;

	case 1540:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1540,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1540:", -1);
		break;

	case 1541:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1541,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1541:", -1);
		break;

	case 1542:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1542,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1542:", -1);
		break;

	case 1543:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1543,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1543:", -1);
		break;

	case 1544:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1544,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1544:", -1);
		break;

	case 1545:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1545,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1545:", -1);
		break;

	case 1546:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1546,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1546:", -1);
		break;

	case 1547:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1547,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1547:", -1);
		break;

	case 1548:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1548,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1548:", -1);
		break;

	case 1549:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1549,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1549:", -1);
		break;

	case 1550:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1550,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1550:", -1);
		break;

	case 1552:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1552,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1552:", -1);
		break;

	case 1553:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1553,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1553:", -1);
		break;

	case 1554:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1554,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1554:", -1);
		break;

	case 1555:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1555,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1555:", -1);
		break;

	case 1556:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_1556,
			NDR_POINTER_UNIQUE, "SERVER_INFO_1556:", -1);
		break;

	}

	return offset;
}

/*
 * IDL long NetrServerGetInfo(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long Level,
 * IDL      [out] [ref] SERVER_INFO_UNION *srv;
 * IDL );
 */
static int
srvsvc_dissect_netrservergetinfo_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
		"Server", hf_srvsvc_server, cb_wstr_postprocess,
		GINT_TO_POINTER(CB_STR_COL_INFO | 1));

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	return offset;
}
static int
srvsvc_dissect_netrservergetinfo_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_UNION,
			NDR_POINTER_REF, "Server Info", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrServerSetInfo(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long Level,
 * IDL      [in] [ref] SERVER_INFO_UNION *srv;
 * IDL      [in] [out] [unique] long *ParamError;
 * IDL );
 */
static int
srvsvc_dissect_netrserversetinfo_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_INFO_UNION,
			NDR_POINTER_REF, "Server Info", -1);

        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_pointer_long, NDR_POINTER_UNIQUE,
			"Parameter Error:", hf_srvsvc_parm_error);

	return offset;
}
static int
srvsvc_dissect_netrserversetinfo_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_pointer_long, NDR_POINTER_UNIQUE,
			"Parameter Error:", hf_srvsvc_parm_error);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}


/*
 * IDL typedef struct {
 * IDL   [size_is()] [unique] wchar_t *disk;
 * IDL } DISK_INFO_0;
 */
static int
srvsvc_dissect_DISK_INFO_0(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	guint32 len;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* this call is to make wireshark eat the array header for the conformant run */
		offset =dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, NULL);

		return offset;
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_disk_inf0_unknown, &len);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_disk_name_len, &len);

	offset = dissect_ndr_uint16s(
		tvb, offset, pinfo, tree, drep, hf_srvsvc_disk_name, len);

  	return offset;
}
static int
srvsvc_dissect_DISK_INFO_0_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_DISK_INFO_0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [length_is(EntriesRead)] [size_is(EntriesRead)] [unique] DISK_INFO_0 *disk;
 * IDL } DISK_ENUM_CONTAINER;
 */
static int
srvsvc_dissect_DISK_ENUM_CONTAINER(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_DISK_INFO_0_array, NDR_POINTER_UNIQUE,
		"DISK_INFO_0 array:", -1);

	return offset;
}


/*
 * IDL long NetrServerDiskEnum(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long Level,
 * IDL      [in] [out] [ref] DISK_ENUM_CONTAINER *disk;
 * IDL      [in] long maxlen,
 * IDL      [out] long entries,
 * IDL      [in] [out] [unique] long *resumehandle,
 * IDL );
 */
static int
srvsvc_dissect_netrserverdiskenum_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_DISK_ENUM_CONTAINER,
			NDR_POINTER_REF, "Disks", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_preferred_len, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_ENUM_HANDLE,
		NDR_POINTER_UNIQUE, "Enum Handle", -1);

	return offset;
}
static int
srvsvc_dissect_netrserverdiskenum_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_DISK_ENUM_CONTAINER,
			NDR_POINTER_REF, "Disks", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_ENUM_HANDLE,
		NDR_POINTER_UNIQUE, "Enum Handle", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long start;
 * IDL   long fopens;
 * IDL   long devopens;
 * IDL   long jobsqueued;
 * IDL   long sopens;
 * IDL   long stimeouts;
 * IDL   long serrorout;
 * IDL   long pwerrors;
 * IDL   long permerrors;
 * IDL   long syserrors;
 * IDL   long bytessent_low;
 * IDL   long bytessent_high;
 * IDL   long bytesrcvd_low;
 * IDL   long bytesrcvd_high;
 * IDL   long avresponse;
 * IDL   long reqbufneed;
 * IDL   long bigbufneed;
 * IDL } SERVER_STAT;
 */

static int
srvsvc_dissect_SERVER_STAT(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_server_stat_start, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_server_stat_fopens, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_server_stat_devopens, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_server_stat_jobsqueued, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_server_stat_sopens, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_server_stat_stimeouts, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_server_stat_serrorout, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_server_stat_pwerrors, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_server_stat_permerrors, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_server_stat_syserrors, NULL);

	offset = dissect_ndr_duint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_server_stat_bytessent, NULL);

	offset = dissect_ndr_duint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_server_stat_bytesrcvd, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_server_stat_avresponse, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_server_stat_reqbufneed, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_server_stat_bigbufneed, NULL);

	return offset;
}

/*
 * IDL long NetrServerStatisticsGet(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [unique] wchar_t *Service,
 * IDL      [in] long Level,
 * IDL      [in] long Options,
 * IDL      [out] [ref] SERVER_STAT *stat
 * IDL );
 */
static int
srvsvc_dissect_netrserverstatisticsget_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Service", hf_srvsvc_service, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_info_level, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_service_options, 0);

	return offset;
}
static int
srvsvc_dissect_netrserverstatisticsget_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_STAT,
			NDR_POINTER_REF, "Stat", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   [size_is(transportaddresslen)] char transportaddress;
 * IDL } TRANSPORT_ADDRESS;
 */
static int
srvsvc_dissect_TRANSPORT_ADDRESS(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	dcerpc_info *di;
	guint32 len;

	di=pinfo->private_data;
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_transport_address_len, &len);

	proto_tree_add_item(tree, hf_srvsvc_transport_address, tvb, offset,
		len, FALSE);
	offset += len;

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long numberofvcs;
 * IDL   [string] [unique] transportname;
 * IDL   [unique] TRANSPORT_ADDRESS *transportaddress;
 * IDL   long transportaddresslen;
 * IDL   [string] [unique] wchar_t *networkaddress;
 * IDL } TRANSPORT_INFO_0;
 */
static int
srvsvc_dissect_TRANSPORT_INFO_0(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_transport_numberofvcs, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Name", 
			hf_srvsvc_transport_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_TRANSPORT_ADDRESS,
			NDR_POINTER_UNIQUE, "Transport Address", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_transport_address_len, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Network Address", 
			hf_srvsvc_transport_networkaddress, 0);

	return offset;
}
static int
srvsvc_dissect_TRANSPORT_INFO_0_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_TRANSPORT_INFO_0);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] TRANSPORT_INFO_0 *trans;
 * IDL } SERVER_XPORT_INFO_0_CONTAINER;
 */
static int
srvsvc_dissect_SERVER_XPORT_INFO_0_CONTAINER(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_TRANSPORT_INFO_0_array, NDR_POINTER_UNIQUE,
		"TRANSPORT_INFO_0 array:", -1);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long numberofvcs;
 * IDL   [string] [unique] transportname;
 * IDL   [unique] TRANSPORT_ADDRESS *transportaddress;
 * IDL   long transportaddresslen;
 * IDL   [string] [unique] wchar_t *networkaddress;
 * IDL } TRANSPORT_INFO_1;
 */
static int
srvsvc_dissect_TRANSPORT_INFO_1(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_transport_numberofvcs, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Name", 
			hf_srvsvc_transport_name, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_TRANSPORT_ADDRESS,
			NDR_POINTER_UNIQUE, "Transport Address", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_transport_address_len, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Network Address", 
			hf_srvsvc_transport_networkaddress, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Domain", hf_srvsvc_domain, 0);

	return offset;
}
static int
srvsvc_dissect_TRANSPORT_INFO_1_array(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_TRANSPORT_INFO_1);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long EntriesRead;
 * IDL   [size_is(EntriesRead)] [unique] TRANSPORT_INFO_1 *trans;
 * IDL } SERVER_XPORT_INFO_1_CONTAINER;
 */
static int
srvsvc_dissect_SERVER_XPORT_INFO_1_CONTAINER(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_TRANSPORT_INFO_1_array, NDR_POINTER_UNIQUE,
		"TRANSPORT_INFO_1 array:", -1);

	return offset;
}


/*
 * IDL typedef [switch_type(long)] union {
 * IDL   [case(0)] [unique] SERVER_XPORT_INFO_0_CONTAINER *xp0;
 * IDL   [case(1)] [unique] SERVER_XPORT_INFO_1_CONTAINER *xp1;
 * IDL } SERVER_XPORT_ENUM_UNION;
 */
static int
srvsvc_dissect_SERVER_XPORT_ENUM_UNION(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	guint32 level;
	dcerpc_info *di;

	di = pinfo->private_data;

	ALIGN_TO_4_BYTES;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep, hf_srvsvc_info_level, &level);

	switch(level){
	case 0:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_XPORT_INFO_0_CONTAINER,
			NDR_POINTER_UNIQUE, "SERVER_XPORT_INFO_0_CONTAINER:",
			-1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", TRANSPORT_INFO_0 level");
		break;
	case 1:
		offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_XPORT_INFO_1_CONTAINER,
			NDR_POINTER_UNIQUE, "SERVER_XPORT_INFO_1_CONTAINER:",
			-1);
		if (check_col(pinfo->cinfo, COL_INFO) && di->ptype == PDU_REQ)
			col_append_str(pinfo->cinfo, COL_INFO, ", TRANSPORT_INFO_1 level");
		break;
	}

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long Level;
 * IDL   SERVER_XPORT_ENUM_UNION xport;
 * IDL } SERVER_XPORT_ENUM_STRUCT;
 */
static int
srvsvc_dissect_SERVER_XPORT_ENUM_STRUCT(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = srvsvc_dissect_SERVER_XPORT_ENUM_UNION(tvb, offset,
			pinfo, tree, drep);

	return offset;
}


/*
 * IDL long NetrServerTransportAdd(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long Level,
 * IDL      [in] [ref] TRANSPORT_INFO_0 *trans;
 * IDL );
 */
static int
srvsvc_dissect_netrservertransportadd_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_info_level, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_TRANSPORT_INFO_0,
			NDR_POINTER_REF, "Transports", -1);

	return offset;
}
static int
srvsvc_dissect_netrservertransportadd_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrServerTransportEnum(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [out] [ref] SERVER_XPORT_ENUM_STRUCT *xport;
 * IDL      [in] long MaxLen,
 * IDL      [out] long entries,
 * IDL      [in] [out] [unique] long *resumehandle;
 * IDL );
 */
static int
srvsvc_dissect_netrservertransportenum_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_XPORT_ENUM_STRUCT,
			NDR_POINTER_REF, "Transports", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_preferred_len, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		srvsvc_dissect_ENUM_HANDLE,
		NDR_POINTER_UNIQUE, "Enum Handle", -1);

	return offset;
}
static int
srvsvc_dissect_netrservertransportenum_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_XPORT_ENUM_STRUCT,
			NDR_POINTER_REF, "Transports", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_ENUM_HANDLE,
			NDR_POINTER_UNIQUE, "Enum Handle", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}


/*
 * IDL long NetrServerTransportDel(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long Level,
 * IDL      [in] [ref] TRANSPORT_INFO_0 *trans;
 * IDL );
 */
static int
srvsvc_dissect_netrservertransportdel_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_info_level, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_TRANSPORT_INFO_0,
			NDR_POINTER_REF, "Transports", -1);

	return offset;
}
static int
srvsvc_dissect_netrservertransportdel_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL typedef struct {
 * IDL   long elapsed;
 * IDL   long msecs;
 * IDL   long hours;
 * IDL   long mins;
 * IDL   long secs;
 * IDL   long hunds;
 * IDL   long timezone;
 * IDL   long tinterval;
 * IDL   long day;
 * IDL   long month;
 * IDL   long year;
 * IDL   long weekday;
 * IDL } TIMEOFDAY;
 */
static int
srvsvc_dissect_TIMEOFDAY(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	/*
	 * XXX - is "hf_srvsvc_tod_elapsed" something that should be
	 * processed by "add_abstime_absent_unknown()" from
	 * "packet-smb-pipe.c"?  This structure looks similar
	 * to the result of a NetRemoteTOD RAP call, and that has
	 * a "current time" field that's processed by
	 * "add_abstime_absent_unknown()".
	 *
	 * Should other fields, such as the time zone offset and
	 * the time interval, be processed as they are for
	 * "lm_data_resp_netremotetod_nolevel" as well?
	 */
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_tod_elapsed, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_tod_msecs, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_tod_hours, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_tod_mins, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_tod_secs, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_tod_hunds, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_tod_timezone, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_tod_tinterval, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_tod_day, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_tod_month, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_tod_year, NULL);
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_tod_weekday, NULL);

	return offset;
}

/*
 * IDL long NetrRemoteTOD(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [out] [unique] TIMEOFDAY *t
 * IDL );
 */
static int
srvsvc_dissect_netrremotetod_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

	return offset;
}
static int
srvsvc_dissect_netrremotetod_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_TIMEOFDAY,
			NDR_POINTER_UNIQUE, "Time of day", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrSetServerServiceBits(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [unique] wchar_t *Transport,
 * IDL      [in] long ServiceBits;
 * IDL      [in] long UpdateImmediately;
 * IDL );
 */
static int
srvsvc_dissect_netrsetserverservicebits_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Transport", hf_srvsvc_transport, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_service_bits, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_update_immediately, NULL);

	return offset;
}
static int
srvsvc_dissect_netrsetserverservicebits_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrPathType(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *PathName,
 * IDL      [in] long PathFlags;
 * IDL      [out] long PathType;
 * IDL );
 */
static int
srvsvc_dissect_netrpathtype_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Path", hf_srvsvc_path, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_path_flags, NULL);

	return offset;
}
static int
srvsvc_dissect_netrpathtype_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_path_type, NULL);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrPathCanonicalize(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *PathName,
 * IDL      [in] long OutBufLen;
 * IDL      [in] [string] [ref] wchar_t *Prefix,
 * IDL      [in] [out] [ref] long *PathType;
 * IDL      [in] long PathFlags;
 * IDL );
 */
static int
srvsvc_dissect_netrpathcanonicalize_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Path", hf_srvsvc_path, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_outbuflen, NULL);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Prefix", hf_srvsvc_prefix, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_path_type, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_path_flags, NULL);

	return offset;
}
static int
srvsvc_dissect_netrpathcanonicalize_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	guint32 len;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* this call is to make wireshark eat the array header for the conformant run */
		offset =dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, NULL);

		return offset;
	}
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_path_len, &len);

	offset = dissect_ndr_uint16s(
		tvb, offset, pinfo, tree, drep, hf_srvsvc_path, len);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_path_type, NULL);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}


/*
 * IDL long NetrPathCompare(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *PathName1,
 * IDL      [in] [string] [ref] wchar_t *PathName2,
 * IDL      [in] long PathType;
 * IDL      [in] long PathFlags;
 * IDL );
 */
static int
srvsvc_dissect_netrpathcompare_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Path 1", hf_srvsvc_path, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Path 2", hf_srvsvc_path, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_path_type, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_path_flags, NULL);

	return offset;
}
static int
srvsvc_dissect_netrpathcompare_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}


/*
 * IDL long NetrNameValidate(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *PathName,
 * IDL      [in] long PathType;
 * IDL      [in] long PathFlags;
 * IDL );
 */
static int
srvsvc_dissect_netrnamevalidate_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Path", hf_srvsvc_path, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_path_type, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_path_flags, NULL);

	return offset;
}
static int
srvsvc_dissect_netrnamevalidate_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrNameCanonicalize(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *PathName,
 * IDL      [in] long OutBufLen,
 * IDL      [in] long PathType,
 * IDL      [in] long PathFlags,
 * IDL      [out] [ref] *PathName
 * IDL );
 */
static int
srvsvc_dissect_netrnamecanonicalize_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Path", hf_srvsvc_path, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_outbuflen, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_path_type, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_path_flags, NULL);

	return offset;
}
static int
srvsvc_dissect_netrnamecanonicalize_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	guint32 len;
	dcerpc_info *di;

	di=pinfo->private_data;
	if(di->conformant_run){
		/* this call is to make wireshark eat the array header for the conformant run */
		offset =dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep, NULL);

		return offset;
	}
	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_path_len, &len);

	offset = dissect_ndr_uint16s(
		tvb, offset, pinfo, tree, drep, hf_srvsvc_path, len);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}


/*
 * IDL long NetrNameCompare(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *PathName1,
 * IDL      [in] [string] [ref] wchar_t *PathName2,
 * IDL      [in] long PathType;
 * IDL      [in] long PathFlags;
 * IDL );
 */
static int
srvsvc_dissect_netrnamecompare_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Path 1", hf_srvsvc_path, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Path 2", hf_srvsvc_path, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_path_type, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_path_flags, NULL);

	return offset;
}
static int
srvsvc_dissect_netrnamecompare_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}


/*
 * IDL long NetrShareEnumSticky(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL	    [in] [out] level
 * IDL      [in] [out] [ref] SHARE_ENUM_STRUCT *share,
 * IDL      [in] long MaxLen,
 * IDL      [out] long Entries,
 * IDL      [in] [out] [unique] *ResumeHandle
 * IDL );
 */
static int
srvsvc_dissect_netrshareenumsticky_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_ENUM_STRUCT,
			NDR_POINTER_REF, "Shares", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_preferred_len, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_ENUM_HANDLE,
			NDR_POINTER_UNIQUE, "Enum Handle", -1);

	return offset;
}
static int
srvsvc_dissect_netrshareenumsticky_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SHARE_ENUM_STRUCT,
			NDR_POINTER_REF, "Shares", -1);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
		hf_srvsvc_num_entries, NULL);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_ENUM_HANDLE,
			NDR_POINTER_UNIQUE, "Enum Handle", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}


/*
 * IDL long NetrShareDelStart(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [ref] wchar_t *Share,
 * IDL      [in] long reserved,
 * IDL      [out] [context_handle] hnd
 * IDL );
 */
static int
srvsvc_dissect_netrsharedelstart_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Share", hf_srvsvc_share, 0);

        offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                     hf_srvsvc_reserved, NULL);

	return offset;
}
static int
srvsvc_dissect_netrsharedelstart_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_srvsvc_hnd, NULL, NULL, TRUE, FALSE);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}

/*
 * IDL long NetrShareDelCommit(
 * IDL     [in] [out] [contect_handle] h
 * IDL );
 */
static int
srvsvc_dissect_netrsharedelcommit_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_srvsvc_hnd, NULL, NULL, TRUE, FALSE);

	return offset;
}
static int
srvsvc_dissect_netrsharedelcommit_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_nt_policy_hnd(tvb, offset, pinfo, tree, drep,
				       hf_srvsvc_hnd, NULL, NULL, TRUE, FALSE);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}


/* XXX dont know the out parameters. only the in parameters.
 *
 * IDL long NetrGetFileSecurity(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [unique] wchar_t *Share,
 * IDL      [in] [string] [ref] wchar_t *File,
 * IDL      [in] long requetedinformation
 * IDL      [out] [ref] SECDESC *securitysecriptor; 4byte-len followed by bytestring
 * IDL );
 */
static int
srvsvc_dissect_netrgetfilesecurity_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Share", hf_srvsvc_share, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Path", hf_srvsvc_path, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	return offset;
}
static int
srvsvc_dissect_netrgetfilesecurity_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			lsa_dissect_sec_desc_buf_data, NDR_POINTER_REF,
			"LSA SECURITY DESCRIPTOR data:", -1);

	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}


/*
 * IDL long NetrSetFileSecurity(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [unique] wchar_t *Share,
 * IDL      [in] [string] [ref] wchar_t *File,
 * IDL      [in] long sequrityinformation
 * IDL      SECDESC [ref] *securitysecriptor; 4byte-len followed by bytestring
 * IDL );
 */
static int
srvsvc_dissect_netrsetfilesecurity_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Share", hf_srvsvc_share, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_REF, "Path", hf_srvsvc_path, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			lsa_dissect_sec_desc_buf_data, NDR_POINTER_REF,
			"LSA SECURITY DESCRIPTOR data:", -1);

	return offset;
}
static int
srvsvc_dissect_netrsetfilesecurity_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}


/*
 * IDL long NetrServerTransportAddEx(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] long Level
 * IDL      [in] [ref] SERVER_XPORT_ENUM_STRUCT *sxes;
 * IDL );
 */
static int
srvsvc_dissect_netrservertransportaddex_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_info_level, 0);

	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
			srvsvc_dissect_SERVER_XPORT_ENUM_STRUCT,
			NDR_POINTER_REF, "Transports", -1);

	return offset;
}
static int
srvsvc_dissect_netrservertransportaddex_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}


/*
 * IDL long NetrServerSetServiceBitsEx(
 * IDL      [in] [string] [unique] wchar_t *ServerName,
 * IDL      [in] [string] [unique] wchar_t *EmulatedServerName,
 * IDL      [in] [string] [unique] wchar_t *Transport,
 * IDL      [in] long servicebitsofinterest
 * IDL      [in] long servicebits
 * IDL      [in] long updateimmediately
 * IDL );
 */
static int
srvsvc_dissect_netrserversetservicebitsex_rqst(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Server", hf_srvsvc_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Emulated Server", 
			hf_srvsvc_emulated_server, 0);

        offset = dissect_ndr_str_pointer_item(tvb, offset, pinfo, tree, drep,
			NDR_POINTER_UNIQUE, "Transport", hf_srvsvc_transport, 0);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_service_bits_of_interest, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_service_bits, NULL);

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_update_immediately, NULL);

	return offset;
}
static int
srvsvc_dissect_netrserversetservicebitsex_reply(tvbuff_t *tvb, int offset,
				     packet_info *pinfo, proto_tree *tree,
				     guint8 *drep)
{
	offset = dissect_doserror(tvb, offset, pinfo, tree, drep,
			hf_srvsvc_rc, NULL);

	return offset;
}




/*
  IDL }
*/
static dcerpc_sub_dissector dcerpc_srvsvc_dissectors[] = {
	{SRV_NETRCHARDEVENUM,		"NetrCharDevEnum",
		srvsvc_dissect_netrchardevenum_rqst,
		srvsvc_dissect_netrchardevenum_reply},
	{SRV_NETRCHARDEVGETINFO,	"NetrCharDevGetInfo",
		srvsvc_dissect_netrchardevgetinfo_rqst,
		srvsvc_dissect_netrchardevgetinfo_reply},
	{SRV_NETRCHARDEVCONTROL,	"NetrCharDevControl",
		srvsvc_dissect_netrchardevcontrol_rqst,
		srvsvc_dissect_netrchardevcontrol_reply},
	{SRV_NETRCHARDEVQENUM,		"NetrCharDevQEnum",
		srvsvc_dissect_netrchardevqenum_rqst,
		srvsvc_dissect_netrchardevqenum_reply},
	{SRV_NETRCHARDEVQGETINFO,	"NetrCharDevQGetInfo",
		srvsvc_dissect_netrchardevqgetinfo_rqst,
		srvsvc_dissect_netrchardevqgetinfo_reply},
	{SRV_NETRCHARDEVQSETINFO,	"NetrCharDevQSetInfo",
		srvsvc_dissect_netrchardevqsetinfo_rqst,
		srvsvc_dissect_netrchardevqsetinfo_reply},
	{SRV_NETRCHARDEVQPURGE,		"NetrCharDevQPurge",
		srvsvc_dissect_netrchardevqpurge_rqst,
		srvsvc_dissect_netrchardevqpurge_reply},
	{SRV_NETRCHARDEVQPURGESELF,	"NetrCharDevQPurgeSelf",
		srvsvc_dissect_netrchardevqpurgeself_rqst,
		srvsvc_dissect_netrchardevqpurgeself_reply},
	{SRV_NETRCONNECTIONENUM,	"NetrConnectionEnum",
		srvsvc_dissect_netrconnectionenum_rqst,
		srvsvc_dissect_netrconnectionenum_reply},
	{SRV_NETRFILEENUM,		"NetrFileEnum",
		srvsvc_dissect_netrfileenum_rqst,
		srvsvc_dissect_netrfileenum_reply},
	{SRV_NETRFILEGETINFO,		"NetrFileGetInfo",
		srvsvc_dissect_netrfilegetinfo_rqst,
		srvsvc_dissect_netrfilegetinfo_reply},
	{SRV_NETRFILECLOSE,		"NetrFileClose",
		srvsvc_dissect_netrfileclose_rqst,
		srvsvc_dissect_netrfileclose_reply},
	{SRV_NETRSESSIONENUM,		"NetrSessionEnum",
		srvsvc_dissect_netrsessionenum_rqst,
		srvsvc_dissect_netrsessionenum_reply},
	{SRV_NETRSESSIONDEL,		"NetrSessionDel",
		srvsvc_dissect_netrsessiondel_rqst,
		srvsvc_dissect_netrsessiondel_reply},
	{SRV_NETRSHAREADD,		"NetrShareAdd",
		srvsvc_dissect_netrshareadd_rqst,
		srvsvc_dissect_netrshareadd_reply},
	{SRV_NETRSHAREENUM,		"NetrShareEnum",
		srvsvc_dissect_netrshareenum_rqst,
		srvsvc_dissect_netrshareenum_reply},
	{SRV_NETRSHAREGETINFO,		"NetrShareGetInfo",
		srvsvc_dissect_netrsharegetinfo_rqst,
		srvsvc_dissect_netrsharegetinfo_reply},
	{SRV_NETRSHARESETINFO,		"NetrShareSetInfo",
		srvsvc_dissect_netrsharesetinfo_rqst,
		srvsvc_dissect_netrsharesetinfo_reply},
	{SRV_NETRSHAREDEL,		"NetrShareDel",
		srvsvc_dissect_netrsharedel_rqst,
		srvsvc_dissect_netrsharedel_reply},
	{SRV_NETRSHAREDELSTICKY,	"NetrShareDelSticky",
		srvsvc_dissect_netrsharedelsticky_rqst,
		srvsvc_dissect_netrsharedelsticky_reply},
	{SRV_NETRSHARECHECK,		"NetrShareCheck",
		srvsvc_dissect_netrsharecheck_rqst,
		srvsvc_dissect_netrsharecheck_reply},
	{SRV_NETRSERVERGETINFO,		"NetrServerGetInfo",
		srvsvc_dissect_netrservergetinfo_rqst,
		srvsvc_dissect_netrservergetinfo_reply},
	{SRV_NETRSERVERSETINFO,		"NetrServerSetInfo",
		srvsvc_dissect_netrserversetinfo_rqst,
		srvsvc_dissect_netrserversetinfo_reply},
	{SRV_NETRSERVERDISKENUM,	"NetrServerDiskEnum",
		srvsvc_dissect_netrserverdiskenum_rqst,
		srvsvc_dissect_netrserverdiskenum_reply},
	{SRV_NETRSERVERSTATISTICSGET,	"NetrServerStatisticsGet",
		srvsvc_dissect_netrserverstatisticsget_rqst,
		srvsvc_dissect_netrserverstatisticsget_reply},
	{SRV_NETRSERVERTRANSPORTADD,	"NetrServerTransportAdd",
		srvsvc_dissect_netrservertransportadd_rqst,
		srvsvc_dissect_netrservertransportadd_reply},
	{SRV_NETRSERVERTRANSPORTENUM,	"NetrServerTransportEnum",
		srvsvc_dissect_netrservertransportenum_rqst,
		srvsvc_dissect_netrservertransportenum_reply},
	{SRV_NETRSERVERTRANSPORTDEL,	"NetrServerTransportDel",
		srvsvc_dissect_netrservertransportdel_rqst,
		srvsvc_dissect_netrservertransportdel_reply},
	{SRV_NETRREMOTETOD,		"NetrRemoteTOD",
		srvsvc_dissect_netrremotetod_rqst,
		srvsvc_dissect_netrremotetod_reply},
	{SRV_NETRSERVERSETSERVICEBITS,	"NetrServerSetServiceBits",
		srvsvc_dissect_netrsetserverservicebits_rqst,
		srvsvc_dissect_netrsetserverservicebits_reply},
	{SRV_NETRPRPATHTYPE,		"NetrpPathType",
		srvsvc_dissect_netrpathtype_rqst,
		srvsvc_dissect_netrpathtype_reply},
	{SRV_NETRPRPATHCANONICALIZE,	"NetrpPathCanonicalize",
		srvsvc_dissect_netrpathcanonicalize_rqst,
		srvsvc_dissect_netrpathcanonicalize_reply},
	{SRV_NETRPRPATHCOMPARE,		"NetrpPathCompare",
		srvsvc_dissect_netrpathcompare_rqst,
		srvsvc_dissect_netrpathcompare_reply},
	{SRV_NETRPRNAMEVALIDATE,	"NetrpNameValidate",
		srvsvc_dissect_netrnamevalidate_rqst,
		srvsvc_dissect_netrnamevalidate_reply},
	{SRV_NETRPRNAMECANONICALIZE,	"NetrpNameCanonicalize",
		srvsvc_dissect_netrnamecanonicalize_rqst,
		srvsvc_dissect_netrnamecanonicalize_reply},
	{SRV_NETRPRNAMECOMPARE,		"NetrpNameCompare",
		srvsvc_dissect_netrnamecompare_rqst,
		srvsvc_dissect_netrnamecompare_reply},
	{SRV_NETRSHAREENUMSTICKY,	"NetrShareEnumSticky",
		srvsvc_dissect_netrshareenumsticky_rqst,
		srvsvc_dissect_netrshareenumsticky_reply},
	{SRV_NETRSHAREDELSTART,		"NetrShareDelStart",
		srvsvc_dissect_netrsharedelstart_rqst,
		srvsvc_dissect_netrsharedelstart_reply},
	{SRV_NETRSHAREDELCOMMIT,	"NetrShareDelCommit",
		srvsvc_dissect_netrsharedelcommit_rqst,
		srvsvc_dissect_netrsharedelcommit_reply},
	{SRV_NETRPGETFILESECURITY,	"NetrpGetFileSecurity",
		srvsvc_dissect_netrgetfilesecurity_rqst,
		srvsvc_dissect_netrgetfilesecurity_reply},
	{SRV_NETRPSETFILESECURITY,	"NetrpSetFileSecurity",
		srvsvc_dissect_netrsetfilesecurity_rqst,
		srvsvc_dissect_netrsetfilesecurity_reply},
	{SRV_NETRSERVERTRANSPORTADDEX,	"NetrServerTransportAddEx",
		srvsvc_dissect_netrservertransportaddex_rqst,
		srvsvc_dissect_netrservertransportaddex_reply},
	{SRV_NETRSERVERSETSERVICEBITSEX,"NetrServerSetServiceBitsEx",
		srvsvc_dissect_netrserversetservicebitsex_rqst,
		srvsvc_dissect_netrserversetservicebitsex_reply},
	{ SRV_NETRDFSGETVERSION, "NetrDfsGetVersion", 
		NULL, NULL },
	{ SRV_NETRDFSCREATELOCALPARTITION, "NetrDfsCreateLocalPartition", 
		NULL, NULL },
	{ SRV_NETRDFSDELETELOCALPARTITION, "NetrDfsDeleteLocalPartition", 
		NULL, NULL },
	{ SRV_NETRDFSSETLOCALVOLUMESTATE, "NetrDfsSetLocalVolumeState", 
		NULL, NULL },
	{ SRV_NETRDFSSETSERVERINFO, "NetrDfsSetServerInfo", 
		NULL, NULL },
	{ SRV_NETRDFSCREATEEXITPOINT, "NetrDfsCreateExitPoint", 
		NULL, NULL },
	{ SRV_NETRDFSDELETEEXITPOINT, "NetrDfsDeleteExitPoint", 
		NULL, NULL },
	{ SRV_NETRDFSMODIFYPREFIX, "NetrDfsModifyPrefix", 
		NULL, NULL },
	{ SRV_NETRDFSFIXLOCALVOLUME, "NetrDfsFixLocalVolume", 
		NULL, NULL },
	{ SRV_NETRDFSMANAGERREPORTSITEINFO, "NetrDfsManagerReportSiteInfo", 
		NULL, NULL },
	{ SRV_NETRSERVERTRANSPORTDELEX, "NetrServerTransportDelEx",
		NULL, NULL },
	{0, NULL, NULL, NULL}
};

void
proto_register_dcerpc_srvsvc(void)
{
        static hf_register_info hf[] = {
	  { &hf_srvsvc_opnum,
	    { "Operation", "srvsvc.opnum", FT_UINT16, BASE_DEC,
	      NULL, 0x0, "Operation", HFILL }},
	  { &hf_srvsvc_server,
	    { "Server", "srvsvc.server", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Server Name", HFILL}},
	  { &hf_srvsvc_emulated_server,
	    { "Emulated Server", "srvsvc.emulated_server", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Emulated Server Name", HFILL}},
	  { &hf_srvsvc_alerts,
	    { "Alerts", "srvsvc.alerts", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Alerts", HFILL}},
	  { &hf_srvsvc_guest,
	    { "Guest Account", "srvsvc.guest", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Guest Account", HFILL}},
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
	  { &hf_srvsvc_share_alternate_name,
	    { "Alternate Name", "srvsvc.share_alternate_name", FT_STRING, BASE_NONE,
	    NULL, 0x0, "Alternate name for this share", HFILL}},
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
	  { &hf_srvsvc_rc,
	    { "Return code", "srvsvc.rc", FT_UINT32,
	      BASE_HEX, VALS(DOS_errors), 0x0, "Return Code", HFILL}},

	  { &hf_srvsvc_platform_id,
	    { "Platform ID", "srvsvc.info.platform_id", FT_UINT32,
	      BASE_DEC, VALS(platform_id_vals), 0x0, "Platform ID", HFILL}},
	  { &hf_srvsvc_ver_major,
	    { "Major Version", "srvsvc.version.major", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Major Version", HFILL}},
	  { &hf_srvsvc_ver_minor,
	    { "Minor Version", "srvsvc.version.minor", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Minor Version", HFILL}},
	  { &hf_srvsvc_client_type,
	    { "Client Type", "srvsvc.client.type", FT_STRING,
	      BASE_NONE, NULL, 0x0, "Client Type", HFILL}},
	  { &hf_srvsvc_comment,
	    { "Comment", "srvsvc.comment", FT_STRING,
	      BASE_NONE, NULL, 0x0, "Comment", HFILL}},
	  { &hf_srvsvc_users,
	    { "Users", "srvsvc.users", FT_UINT32,
	      BASE_DEC, NULL, 0x0 , "User Count", HFILL}},
	  { &hf_srvsvc_disc,
	    { "Disc", "srvsvc.disc", FT_UINT32,
	      BASE_DEC, NULL, 0x0 , "", HFILL}},
	  { &hf_srvsvc_hidden,
	    { "Hidden", "srvsvc.hidden", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Hidden", HFILL}},
	  { &hf_srvsvc_reserved,
	    { "Reserved", "srvsvc.reserved", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Announce", HFILL }},
	  { &hf_srvsvc_announce,
	    { "Announce", "srvsvc.announce", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Announce", HFILL }},
	  { &hf_srvsvc_anndelta,
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
	  { &hf_srvsvc_share_type,
	    { "Share Type", "srvsvc.share_type", FT_UINT32,
	      BASE_HEX, VALS(share_type_vals), 0x0, "Share Type", HFILL}},
	  { &hf_srvsvc_file_id,
	    { "File ID", "srvsvc.file_id", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "File ID", HFILL}},
	  { &hf_srvsvc_perm,
	    { "Permissions", "srvsvc.perm", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Permissions", HFILL}},
	  { &hf_srvsvc_dfs_root_flags,
	    { "DFS Root Flags", "srvsvc.dfs_root_flags", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "DFS Root Flags. Contact wireshark developers if you know what the bits are", HFILL}},
	  { &hf_srvsvc_policy,
	    { "Policy", "srvsvc.policy", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Policy", HFILL}},
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
	  { &hf_srvsvc_con_type,
	    { "Connection Type", "srvsvc.con_type", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Connection Type", HFILL}},
	  { &hf_srvsvc_con_time,
	    { "Connection Time", "srvsvc.con_time", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Connection Time", HFILL}},
	  { &hf_srvsvc_ulist_mtime,
	    { "Ulist mtime", "srvsvc.ulist_mtime", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Ulist mtime", HFILL}},
	  { &hf_srvsvc_glist_mtime,
	    { "Glist mtime", "srvsvc.glist_mtime", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Glist mtime", HFILL}},
	  { &hf_srvsvc_alist_mtime,
	    { "Alist mtime", "srvsvc.alist_mtime", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Alist mtime", HFILL}},
	  { &hf_srvsvc_connections,
	    { "Connections", "srvsvc.connections", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of Connections", HFILL}},
	  { &hf_srvsvc_shares,
	    { "Shares", "srvsvc.shares", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of Shares", HFILL}},
	  { &hf_srvsvc_diskalert,
	    { "Disk Alerts", "srvsvc.diskalert", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of disk alerts", HFILL}},
	  { &hf_srvsvc_netioalert,
	    { "Net I/O Alerts", "srvsvc.netioalert", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of Net I/O Alerts", HFILL}},
	  { &hf_srvsvc_maxauditsz,
	    { "Max Audits", "srvsvc.maxaudits", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Maximum number of audits", HFILL}},
	  { &hf_srvsvc_srvheuristics,
	    { "Server Heuristics", "srvsvc.srvheuristics", FT_STRING,
	      BASE_DEC, NULL, 0x0, "Server Heuristics", HFILL}},
	  { &hf_srvsvc_openfiles,
	    { "Open Files", "srvsvc.openfiles", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Open Files", HFILL}},
	  { &hf_srvsvc_opensearch,
	    { "Open Search", "srvsvc.opensearch", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Open Search", HFILL}},
	  { &hf_srvsvc_activelocks,
	    { "Active Locks", "srvsvc.activelocks", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Active Locks", HFILL}},
	  { &hf_srvsvc_numfiletasks,
	    { "Num Filetasks", "srvsvc.numfiletasks", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of filetasks", HFILL}},
	  { &hf_srvsvc_alertsched,
	    { "Alert Sched", "srvsvc.alertsched", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Alert Schedule", HFILL}},
	  { &hf_srvsvc_erroralert,
	    { "Error Alerts", "srvsvc.erroralert", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of error alerts", HFILL}},
	  { &hf_srvsvc_logonalert,
	    { "Logon Alerts", "srvsvc.logonalert", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of logon alerts", HFILL}},
	  { &hf_srvsvc_accessalert,
	    { "Access Alerts", "srvsvc.accessalert", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of access alerts", HFILL}},
	  { &hf_srvsvc_sizreqbufs,
	    { "Siz Req Bufs", "srvsvc.sizreqbufs", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "", HFILL}},
	  { &hf_srvsvc_numbigbufs,
	    { "Num Big Bufs", "srvsvc.numbigbufs", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of big buffers", HFILL}},
	  { &hf_srvsvc_sessopens,
	    { "Sessions Open", "srvsvc.sessopens", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Sessions Open", HFILL}},
	  { &hf_srvsvc_sessvcs,
	    { "Sessions VCs", "srvsvc.sessvcs", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Sessions VCs", HFILL}},
	  { &hf_srvsvc_sessreqs,
	    { "Sessions Reqs", "srvsvc.sessreqs", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Sessions Requests", HFILL}},
	  { &hf_srvsvc_auditedevents,
	    { "Audited Events", "srvsvc.auditedevents", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of audited events", HFILL}},
	  { &hf_srvsvc_auditprofile,
	    { "Audit Profile", "srvsvc.auditprofile", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Audit Profile", HFILL}},
	  { &hf_srvsvc_autopath,
	    { "Autopath", "srvsvc.autopath", FT_STRING,
	      BASE_DEC, NULL, 0x0, "Autopath", HFILL}},
	  { &hf_srvsvc_security,
	    { "Security", "srvsvc.security", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Security", HFILL}},
	  { &hf_srvsvc_numadmin,
	    { "Num Admins", "srvsvc.num_admins", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of Administrators", HFILL}},
	  { &hf_srvsvc_lanmask,
	    { "LANMask", "srvsvc.lanmask", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "LANMask", HFILL}},
	  { &hf_srvsvc_chdevs,
	    { "Char Devs", "srvsvc.chdevs", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of Char Devices", HFILL}},
	  { &hf_srvsvc_chdevqs,
	    { "Char Devqs", "srvsvc.chdevqs", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of Char Device Queues", HFILL}},
	  { &hf_srvsvc_chdevjobs,
	    { "Char Dev Jobs", "srvsvc.chdevjobs", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of Char Device Jobs", HFILL}},
	  { &hf_srvsvc_num_entries,
	    { "Number of entries", "srvsvc.share.num_entries", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of Entries", HFILL}},
	  { &hf_srvsvc_total_entries,
	    { "Total entries", "srvsvc.share.tot_entries", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Total Entries", HFILL}},
	  { &hf_srvsvc_initworkitems,
	    { "Init Workitems", "srvsvc.initworkitems", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Workitems", HFILL}},
	  { &hf_srvsvc_maxworkitems,
	    { "Max Workitems", "srvsvc.maxworkitems", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Workitems", HFILL}},
	  { &hf_srvsvc_rawworkitems,
	    { "Raw Workitems", "srvsvc.rawworkitems", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Workitems", HFILL}},
	  { &hf_srvsvc_preferred_len,
	    { "Preferred length", "srvsvc.preferred_len", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Preferred Length", HFILL}},
	  { &hf_srvsvc_parm_error,
	    { "Parameter Error", "srvsvc.parm_error", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Parameter Error", HFILL}},
	  { &hf_srvsvc_enum_handle,
	    { "Enumeration handle", "srvsvc.enum_hnd", FT_BYTES,
	      BASE_HEX, NULL, 0x0, "Enumeration Handle", HFILL}},
	  { &hf_srvsvc_irpstacksize,
	    { "Irp Stack Size", "srvsvc.irpstacksize", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Irp Stack Size", HFILL}},
	  { &hf_srvsvc_maxrawbuflen,
	    { "Max Raw Buf Len", "srvsvc.", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Max Raw Buf Len", HFILL}},
	  { &hf_srvsvc_maxpagedmemoryusage,
	    { "Max Paged Memory Usage", "srvsvc.maxpagedmemoryusage", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Max Paged Memory Usage", HFILL}},
	  { &hf_srvsvc_maxnonpagedmemoryusage,
	    { "Max Non-Paged Memory Usage", "srvsvc.maxnonpagedmemoryusage", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Max Non-Paged Memory Usage", HFILL}},
	  { &hf_srvsvc_enablesoftcompat,
	    { "Enable Soft Compat", "srvsvc.enablesoftcompat", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Enable Soft Compat", HFILL}},
	  { &hf_srvsvc_enableforcedlogoff,
	    { "Enable Forced Logoff", "srvsvc.enableforcedlogoff", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Enable Forced Logoff", HFILL}},
	  { &hf_srvsvc_timesource,
	    { "Timesource", "srvsvc.timesource", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Timesource", HFILL}},
	  { &hf_srvsvc_acceptdownlevelapis,
	    { "Accept Downlevel APIs", "srvsvc.acceptdownlevelapis", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Accept Downlevel APIs", HFILL}},
	  { &hf_srvsvc_lmannounce,
	    { "LM Announce", "srvsvc.lmannounce", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "LM Announce", HFILL}},
	  { &hf_srvsvc_domain,
	    { "Domain", "srvsvc.domain", FT_STRING,
	      BASE_HEX, NULL, 0x0, "Domain", HFILL}},
	  { &hf_srvsvc_maxcopyreadlen,
	    { "Max Copy Read Len", "srvsvc.maxcopyreadlen", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Max Copy Read Len", HFILL}},
	  { &hf_srvsvc_maxcopywritelen,
	    { "Max Copy Write Len", "srvsvc.maxcopywritelen", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Max Copy Write Len", HFILL}},
	  { &hf_srvsvc_minkeepsearch,
	    { "Min Keep Search", "srvsvc.minkeepsearch", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Min Keep Search", HFILL}},
	  { &hf_srvsvc_maxkeepsearch,
	    { "Max Keep Search", "srvsvc.maxkeepsearch", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Max Keep Search", HFILL}},
	  { &hf_srvsvc_minkeepcomplsearch,
	    { "Min Keep Compl Search", "srvsvc.minkeepcomplsearch", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Min Keep Compl Search", HFILL}},
	  { &hf_srvsvc_maxkeepcomplsearch,
	    { "Max Keep Compl Search", "srvsvc.maxkeepcomplsearch", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Max Keep Compl Search", HFILL}},
	  { &hf_srvsvc_threadcountadd,
	    { "Thread Count Add", "srvsvc.threadcountadd", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Thread Count Add", HFILL}},
	  { &hf_srvsvc_numblockthreads,
	    { "Num Block Threads", "srvsvc.numblockthreads", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Num Block Threads", HFILL}},
	  { &hf_srvsvc_scavtimeout,
	    { "Scav Timeout", "srvsvc.scavtimeout", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Scav Timeout", HFILL}},
	  { &hf_srvsvc_minrcvqueue,
	    { "Min Rcv Queue", "srvsvc.minrcvqueue", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Min Rcv Queue", HFILL}},
	  { &hf_srvsvc_minfreeworkitems,
	    { "Min Free Workitems", "srvsvc.minfreeworkitems", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Min Free Workitems", HFILL}},
	  { &hf_srvsvc_xactmemsize,
	    { "Xact Mem Size", "srvsvc.xactmemsize", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Xact Mem Size", HFILL}},
	  { &hf_srvsvc_threadpriority,
	    { "Thread Priority", "srvsvc.threadpriority", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Thread Priority", HFILL}},
	  { &hf_srvsvc_maxmpxct,
	    { "MaxMpxCt", "srvsvc.maxmpxct", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "MaxMpxCt", HFILL}},
	  { &hf_srvsvc_oplockbreakwait,
	    { "Oplock Break Wait", "srvsvc.oplockbreakwait", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Oplock Break Wait", HFILL}},
	  { &hf_srvsvc_oplockbreakresponsewait,
	    { "Oplock Break Response wait", "srvsvc.oplockbreakresponsewait", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Oplock Break response Wait", HFILL}},
	  { &hf_srvsvc_enableoplocks,
	    { "Enable Oplocks", "srvsvc.enableoplocks", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Enable Oplocks", HFILL}},
	  { &hf_srvsvc_enableoplockforceclose,
	    { "Enable Oplock Force Close", "srvsvc.enableoplockforceclose", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Enable Oplock Force Close", HFILL}},
	  { &hf_srvsvc_enablefcbopens,
	    { "Enable FCB Opens", "srvsvc.enablefcbopens", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Enable FCB Opens", HFILL}},
	  { &hf_srvsvc_enableraw,
	    { "Enable RAW", "srvsvc.enableraw", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Enable RAW", HFILL}},
	  { &hf_srvsvc_enablesharednetdrives,
	    { "Enable Shared Net Drives", "srvsvc.enablesharednetdrives", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Enable Shared Net Drives", HFILL}},
	  { &hf_srvsvc_minfreeconnections,
	    { "Min Free Conenctions", "srvsvc.minfreeconnections", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Min Free Connections", HFILL}},
	  { &hf_srvsvc_maxfreeconnections,
	    { "Max Free Conenctions", "srvsvc.maxfreeconnections", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Max Free Connections", HFILL}},
	  { &hf_srvsvc_initsesstable,
	    { "Init Session Table", "srvsvc.initsesstable", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Init Session Table", HFILL}},
	  { &hf_srvsvc_initconntable,
	    { "Init Connection Table", "srvsvc.initconntable", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Init Connection Table", HFILL}},
	  { &hf_srvsvc_initfiletable,
	    { "Init File Table", "srvsvc.initfiletable", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Init File Table", HFILL}},
	  { &hf_srvsvc_initsearchtable,
	    { "Init Search Table", "srvsvc.initsearchtable", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Init Search Table", HFILL}},
	  { &hf_srvsvc_errortreshold,
	    { "Error Treshold", "srvsvc.errortreshold", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Error Treshold", HFILL}},
	  { &hf_srvsvc_networkerrortreshold,
	    { "Network Error Treshold", "srvsvc.networkerrortreshold", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Network Error Treshold", HFILL}},
	  { &hf_srvsvc_diskspacetreshold,
	    { "Diskspace Treshold", "srvsvc.diskspacetreshold", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Diskspace Treshold", HFILL}},
	  { &hf_srvsvc_maxlinkdelay,
	    { "Max Link Delay", "srvsvc.maxlinkdelay", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Max Link Delay", HFILL}},
	  { &hf_srvsvc_minlinkthroughput,
	    { "Min Link Throughput", "srvsvc.minlinkthroughput", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Min Link Throughput", HFILL}},
	  { &hf_srvsvc_linkinfovalidtime,
	    { "Link Info Valid Time", "srvsvc.linkinfovalidtime", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Link Info Valid Time", HFILL}},
	  { &hf_srvsvc_scavqosinfoupdatetime,
	    { "Scav QoS Info Update Time", "srvsvc.scavqosinfoupdatetime", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Scav QoS Info Update Time", HFILL}},
	  { &hf_srvsvc_maxworkitemidletime,
	    { "Max Workitem Idle Time", "srvsvc.maxworkitemidletime", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Max Workitem Idle Time", HFILL}},
	  { &hf_srvsvc_disk_name,
	    { "Disk Name", "srvsvc.disk_name", FT_STRING,
	      BASE_DEC, NULL, 0x0, "Disk Name", HFILL}},
	  { &hf_srvsvc_disk_name_len,
	    { "Disk Name Length", "srvsvc.disk_name_len", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Length of Disk Name", HFILL}},
	  { &hf_srvsvc_disk_inf0_unknown,
	    { "Disk_Info0 unknown", "srvsvc.disk_info0_unknown1", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Disk Info 0 unknown uint32", HFILL}},
	  { &hf_srvsvc_service,
	    { "Service", "srvsvc.service", FT_STRING,
	      BASE_DEC, NULL, 0x0, "Service", HFILL}},
	  { &hf_srvsvc_service_options,
	    { "Options", "srvsvc.service_options", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Service Options", HFILL}},
	  { &hf_srvsvc_transport_numberofvcs,
	    { "VCs", "srvsvc.transport.num_vcs", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of VCs for this transport", HFILL}},
	  { &hf_srvsvc_transport_name,
	    { "Name", "srvsvc.transport.name", FT_STRING,
	      BASE_HEX, NULL, 0x0, "Name of transport", HFILL}},
	  { &hf_srvsvc_transport_address,
	    { "Address", "srvsvc.transport.address", FT_BYTES,
	      BASE_HEX, NULL, 0x0, "Address of transport", HFILL}},
	  { &hf_srvsvc_transport_address_len,
	    { "Address Len", "srvsvc.transport.addresslen", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Length of transport address", HFILL}},
	  { &hf_srvsvc_transport_networkaddress,
	    { "Network Address", "srvsvc.transport.networkaddress", FT_STRING,
	      BASE_HEX, NULL, 0x0, "Network address for transport", HFILL}},
	  { &hf_srvsvc_service_bits,
	    { "Service Bits", "srvsvc.service_bits", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Service Bits", HFILL}},
	  { &hf_srvsvc_service_bits_of_interest,
	    { "Service Bits Of Interest", "srvsvc.service_bits_of_interest", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Service Bits Of Interest", HFILL}},
	  { &hf_srvsvc_update_immediately,
	    { "Update Immediately", "srvsvc.update_immediately", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Update Immediately", HFILL}},
	  { &hf_srvsvc_path_flags,
	    { "Flags", "srvsvc.path_flags", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Path flags", HFILL}},
	  { &hf_srvsvc_share_flags,
	    { "Flags", "srvsvc.share_flags", FT_UINT32,
	      BASE_HEX, NULL, 0x0, "Share flags", HFILL}},
	  { &hf_srvsvc_path_type,
	    { "Type", "srvsvc.path_type", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Path type", HFILL}},
	  { &hf_srvsvc_path_len,
	    { "Len", "srvsvc.path_len", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Path len", HFILL}},
	  { &hf_srvsvc_outbuflen,
	    { "OutBufLen", "srvsvc.outbuflen", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Output Buffer Length", HFILL}},
	  { &hf_srvsvc_prefix,
	    { "Prefix", "srvsvc.prefix", FT_STRING,
	      BASE_HEX, NULL, 0x0, "Path Prefix", HFILL}},
	  { &hf_srvsvc_hnd,
	    { "Context Handle", "srvsvc.hnd", FT_BYTES,
	      BASE_NONE, NULL, 0x0, "Context Handle", HFILL}},
	  { &hf_srvsvc_server_stat_start,
	    { "Start", "srvsvc.server_stat.start", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "", HFILL}},
	  { &hf_srvsvc_server_stat_fopens,
	    { "Fopens", "srvsvc.server_stat.fopens", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of fopens", HFILL}},
	  { &hf_srvsvc_server_stat_devopens,
	    { "Devopens", "srvsvc.server_stat.devopens", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of devopens", HFILL}},
	  { &hf_srvsvc_server_stat_jobsqueued,
	    { "Jobs Queued", "srvsvc.server_stat.jobsqueued", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of jobs queued", HFILL}},
	  { &hf_srvsvc_server_stat_sopens,
	    { "Sopens", "srvsvc.server_stat.sopens", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of sopens", HFILL}},
	  { &hf_srvsvc_server_stat_stimeouts,
	    { "stimeouts", "srvsvc.server_stat.stimeouts", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of stimeouts", HFILL}},
	  { &hf_srvsvc_server_stat_serrorout,
	    { "Serrorout", "srvsvc.server_stat.serrorout", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of serrorout", HFILL}},
	  { &hf_srvsvc_server_stat_pwerrors,
	    { "Pwerrors", "srvsvc.server_stat.pwerrors", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of password errors", HFILL}},
	  { &hf_srvsvc_server_stat_permerrors,
	    { "Permerrors", "srvsvc.server_stat.permerrors", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of permission errors", HFILL}},
	  { &hf_srvsvc_server_stat_syserrors,
	    { "Syserrors", "srvsvc.server_stat.syserrors", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of system errors", HFILL}},
	  { &hf_srvsvc_server_stat_bytessent,
	    { "Bytes Sent", "srvsvc.server_stat.bytessent", FT_UINT64,
	      BASE_DEC, NULL, 0x0, "Number of bytes sent", HFILL}},
	  { &hf_srvsvc_server_stat_bytesrcvd,
	    { "Bytes Rcvd", "srvsvc.server_stat.bytesrcvd", FT_UINT64,
	      BASE_DEC, NULL, 0x0, "Number of bytes received", HFILL}},
	  { &hf_srvsvc_server_stat_avresponse,
	    { "Avresponse", "srvsvc.server_stat.avresponse", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "", HFILL}},
	  { &hf_srvsvc_server_stat_reqbufneed,
	    { "Req Buf Need", "srvsvc.server_stat.reqbufneed", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of request buffers needed?", HFILL}},
	  { &hf_srvsvc_server_stat_bigbufneed,
	    { "Big Buf Need", "srvsvc.server_stat.bigbufneed", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "Number of big buffers needed?", HFILL}},
	  { &hf_srvsvc_tod_elapsed,
	    { "Elapsed", "srvsvc.tod.elapsed", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "", HFILL}},
	  { &hf_srvsvc_tod_msecs,
	    { "msecs", "srvsvc.tod.msecs", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "", HFILL}},
	  { &hf_srvsvc_tod_hours,
	    { "Hours", "srvsvc.tod.hours", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "", HFILL}},
	  { &hf_srvsvc_tod_mins,
	    { "Mins", "srvsvc.tod.mins", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "", HFILL}},
	  { &hf_srvsvc_tod_secs,
	    { "Secs", "srvsvc.tod.secs", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "", HFILL}},
	  { &hf_srvsvc_tod_hunds,
	    { "Hunds", "srvsvc.tod.hunds", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "", HFILL}},
	  { &hf_srvsvc_tod_timezone,
	    { "Timezone", "srvsvc.tod.timezone", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "", HFILL}},
	  { &hf_srvsvc_tod_tinterval,
	    { "Tinterval", "srvsvc.tod.tinterval", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "", HFILL}},
	  { &hf_srvsvc_tod_day,
	    { "Day", "srvsvc.tod.day", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "", HFILL}},
	  { &hf_srvsvc_tod_month,
	    { "Month", "srvsvc.tod.month", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "", HFILL}},
	  { &hf_srvsvc_tod_year,
	    { "Year", "srvsvc.tod.year", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "", HFILL}},
	  { &hf_srvsvc_tod_weekday,
	    { "Weekday", "srvsvc.tod.weekday", FT_UINT32,
	      BASE_DEC, NULL, 0x0, "", HFILL}},
	};

        static gint *ett[] = {
                &ett_dcerpc_srvsvc,
		&ett_srvsvc_share_info_1,
		&ett_srvsvc_share_info_2,
		&ett_srvsvc_share_info_501,
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
                         dcerpc_srvsvc_dissectors, hf_srvsvc_opnum);
}
