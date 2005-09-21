/* packet-afs.c
 * Routines for AFS packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 * Based on routines from tcpdump patches by
 *   Ken Hornstein <kenh@cmf.nrl.navy.mil>
 * Portions based on information retrieved from the RX definitions
 *   in Arla, the free AFS client at http://www.stacken.kth.se/project/arla/
 * Portions based on information/specs retrieved from the OpenAFS sources at
 *   www.openafs.org, Copyright IBM.
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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
# include "config.h"
#endif

#include <stdio.h>

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/addr_resolv.h>
#include <epan/emem.h>

#include "packet-rx.h"
#include "packet-afs.h"

static int proto_afs = -1;
static int hf_afs_fs = -1;
static int hf_afs_cb = -1;
static int hf_afs_prot = -1;
static int hf_afs_vldb = -1;
static int hf_afs_kauth = -1;
static int hf_afs_vol = -1;
static int hf_afs_error = -1;
static int hf_afs_bos = -1;
static int hf_afs_update = -1;
static int hf_afs_rmtsys = -1;
static int hf_afs_ubik = -1;
static int hf_afs_backup = -1;

static int hf_afs_fs_opcode = -1;
static int hf_afs_cb_opcode = -1;
static int hf_afs_prot_opcode = -1;
static int hf_afs_vldb_opcode = -1;
static int hf_afs_kauth_opcode = -1;
static int hf_afs_vol_opcode = -1;
static int hf_afs_error_opcode = -1;
static int hf_afs_bos_opcode = -1;
static int hf_afs_update_opcode = -1;
static int hf_afs_rmtsys_opcode = -1;
static int hf_afs_ubik_opcode = -1;
static int hf_afs_backup_opcode = -1;

static int hf_afs_fs_fid_volume = -1;
static int hf_afs_fs_fid_vnode = -1;
static int hf_afs_fs_fid_uniqifier = -1;
static int hf_afs_fs_offset = -1;
static int hf_afs_fs_length = -1;
static int hf_afs_fs_flength = -1;
static int hf_afs_fs_offset64 = -1;
static int hf_afs_fs_length64 = -1;
static int hf_afs_fs_flength64 = -1;
static int hf_afs_fs_errcode = -1;
static int hf_afs_fs_data = -1;
static int hf_afs_fs_name = -1;
static int hf_afs_fs_oldname = -1;
static int hf_afs_fs_newname = -1;
static int hf_afs_fs_symlink_name = -1;
static int hf_afs_fs_symlink_content = -1;
static int hf_afs_fs_volid = -1;
static int hf_afs_fs_volname = -1;
static int hf_afs_fs_timestamp = -1;
static int hf_afs_fs_offlinemsg = -1;
static int hf_afs_fs_motd = -1;
static int hf_afs_fs_xstats_version = -1;
static int hf_afs_fs_xstats_timestamp = -1;
static int hf_afs_fs_xstats_clientversion = -1;
static int hf_afs_fs_xstats_collnumber = -1;
static int hf_afs_fs_cps_spare1 = -1;
static int hf_afs_fs_cps_spare2 = -1;
static int hf_afs_fs_cps_spare3 = -1;
static int hf_afs_fs_vicelocktype = -1;
static int hf_afs_fs_viceid = -1;
static int hf_afs_fs_ipaddr = -1;
static int hf_afs_fs_token = -1;

static int hf_afs_fs_status_anonymousaccess = -1;
static int hf_afs_fs_status_author = -1;
static int hf_afs_fs_status_calleraccess = -1;
static int hf_afs_fs_status_clientmodtime = -1;
static int hf_afs_fs_status_dataversion = -1;
static int hf_afs_fs_status_dataversionhigh = -1;
static int hf_afs_fs_status_filetype = -1;
static int hf_afs_fs_status_group = -1;
static int hf_afs_fs_status_interfaceversion = -1;
static int hf_afs_fs_status_length = -1;
static int hf_afs_fs_status_linkcount = -1;
static int hf_afs_fs_status_mask = -1;
static int hf_afs_fs_status_mask_fsync = -1;
static int hf_afs_fs_status_mask_setgroup = -1;
static int hf_afs_fs_status_mask_setmode = -1;
static int hf_afs_fs_status_mask_setmodtime = -1;
static int hf_afs_fs_status_mask_setowner = -1;
static int hf_afs_fs_status_mask_setsegsize = -1;
static int hf_afs_fs_status_mode = -1;
static int hf_afs_fs_status_owner = -1;
static int hf_afs_fs_status_parentunique = -1;
static int hf_afs_fs_status_parentvnode = -1;
static int hf_afs_fs_status_segsize = -1;
static int hf_afs_fs_status_servermodtime = -1;
static int hf_afs_fs_status_spare2 = -1;
static int hf_afs_fs_status_spare3 = -1;
static int hf_afs_fs_status_spare4 = -1;
static int hf_afs_fs_status_synccounter = -1;

static int hf_afs_fs_volsync_spare1 = -1;
static int hf_afs_fs_volsync_spare2 = -1;
static int hf_afs_fs_volsync_spare3 = -1;
static int hf_afs_fs_volsync_spare4 = -1;
static int hf_afs_fs_volsync_spare5 = -1;
static int hf_afs_fs_volsync_spare6 = -1;

static int hf_afs_fs_acl_datasize = -1;
static int hf_afs_fs_acl_count_negative = -1;
static int hf_afs_fs_acl_count_positive = -1;
static int hf_afs_fs_acl_entity = -1;
static int hf_afs_fs_acl_r = -1;
static int hf_afs_fs_acl_l = -1;
static int hf_afs_fs_acl_i = -1;
static int hf_afs_fs_acl_d = -1;
static int hf_afs_fs_acl_w = -1;
static int hf_afs_fs_acl_k = -1;
static int hf_afs_fs_acl_a = -1;

static int hf_afs_fs_callback_version = -1;
static int hf_afs_fs_callback_expires = -1;
static int hf_afs_fs_callback_type = -1;

static int hf_afs_bos_errcode = -1;
static int hf_afs_bos_type = -1;
static int hf_afs_bos_instance = -1;
static int hf_afs_bos_status = -1;
static int hf_afs_bos_statusdesc = -1;
static int hf_afs_bos_num = -1;
static int hf_afs_bos_size = -1;
static int hf_afs_bos_flags = -1;
static int hf_afs_bos_date = -1;
static int hf_afs_bos_content = -1;
static int hf_afs_bos_user = -1;
static int hf_afs_bos_key = -1;
static int hf_afs_bos_path = -1;
static int hf_afs_bos_file = -1;
static int hf_afs_bos_cmd = -1;
static int hf_afs_bos_error = -1;
static int hf_afs_bos_spare1 = -1;
static int hf_afs_bos_spare2 = -1;
static int hf_afs_bos_spare3 = -1;
static int hf_afs_bos_parm = -1;
static int hf_afs_bos_kvno = -1;
static int hf_afs_bos_cell = -1;
static int hf_afs_bos_host = -1;
static int hf_afs_bos_newtime = -1;
static int hf_afs_bos_baktime = -1;
static int hf_afs_bos_oldtime = -1;
static int hf_afs_bos_data = -1;
static int hf_afs_bos_keymodtime = -1;
static int hf_afs_bos_keychecksum = -1;
static int hf_afs_bos_keyspare2 = -1;

static int hf_afs_vldb_errcode = -1;
static int hf_afs_vldb_name = -1;
static int hf_afs_vldb_id = -1;
static int hf_afs_vldb_type = -1;
static int hf_afs_vldb_bump = -1;
static int hf_afs_vldb_index = -1;
static int hf_afs_vldb_nextindex = -1;
static int hf_afs_vldb_count = -1;
static int hf_afs_vldb_numservers = -1;
static int hf_afs_vldb_server = -1;
static int hf_afs_vldb_serveruuid = -1;
static int hf_afs_vldb_serveruniq = -1;
static int hf_afs_vldb_serverflags = -1;
static int hf_afs_vldb_serverip = -1;
static int hf_afs_vldb_partition = -1;
static int hf_afs_vldb_rovol = -1;
static int hf_afs_vldb_rwvol = -1;
static int hf_afs_vldb_bkvol = -1;
static int hf_afs_vldb_clonevol = -1;
static int hf_afs_vldb_flags = -1;
static int hf_afs_vldb_flags_rwexists = -1;
static int hf_afs_vldb_flags_roexists = -1;
static int hf_afs_vldb_flags_bkexists = -1;
static int hf_afs_vldb_flags_dfsfileset = -1;

static int hf_afs_vldb_spare1 = -1;
static int hf_afs_vldb_spare2 = -1;
static int hf_afs_vldb_spare3 = -1;
static int hf_afs_vldb_spare4 = -1;
static int hf_afs_vldb_spare5 = -1;
static int hf_afs_vldb_spare6 = -1;
static int hf_afs_vldb_spare7 = -1;
static int hf_afs_vldb_spare8 = -1;
static int hf_afs_vldb_spare9 = -1;

static int hf_afs_kauth_errcode = -1;
static int hf_afs_kauth_princ = -1;
static int hf_afs_kauth_realm = -1;
static int hf_afs_kauth_domain = -1;
static int hf_afs_kauth_kvno = -1;
static int hf_afs_kauth_name = -1;
static int hf_afs_kauth_data = -1;

static int hf_afs_vol_errcode = -1;
static int hf_afs_vol_count = -1;
static int hf_afs_vol_id = -1;
static int hf_afs_vol_name = -1;

static int hf_afs_cb_errcode = -1;
static int hf_afs_cb_callback_version = -1;
static int hf_afs_cb_callback_type = -1;
static int hf_afs_cb_callback_expires = -1;
static int hf_afs_cb_fid_volume = -1;
static int hf_afs_cb_fid_vnode = -1;
static int hf_afs_cb_fid_uniqifier = -1;

static int hf_afs_prot_errcode = -1;
static int hf_afs_prot_name = -1;
static int hf_afs_prot_id = -1;
static int hf_afs_prot_count = -1;
static int hf_afs_prot_oldid = -1;
static int hf_afs_prot_newid = -1;
static int hf_afs_prot_pos = -1;
static int hf_afs_prot_flag = -1;
static int hf_afs_prot_uid = -1;
static int hf_afs_prot_gid = -1;
static int hf_afs_prot_maxuid = -1;
static int hf_afs_prot_maxgid = -1;

static int hf_afs_backup_errcode = -1;

static int hf_afs_ubik_errcode = -1;
static int hf_afs_ubik_version_epoch = -1;
static int hf_afs_ubik_version_counter = -1;
static int hf_afs_ubik_votestart = -1;
static int hf_afs_ubik_state = -1;
static int hf_afs_ubik_site = -1;
static int hf_afs_ubik_interface = -1;
static int hf_afs_ubik_file = -1;
static int hf_afs_ubik_pos = -1;
static int hf_afs_ubik_length = -1;
static int hf_afs_ubik_locktype = -1;
static int hf_afs_ubik_voteend = -1;
static int hf_afs_ubik_votetype = -1;

static int hf_afs_ubik_now = -1;
static int hf_afs_ubik_lastyestime = -1;
static int hf_afs_ubik_lastyeshost = -1;
static int hf_afs_ubik_lastyesstate = -1;
static int hf_afs_ubik_lastyesclaim = -1;
static int hf_afs_ubik_lowesthost = -1;
static int hf_afs_ubik_lowesttime = -1;
static int hf_afs_ubik_synchost = -1;
static int hf_afs_ubik_synctime = -1;
static int hf_afs_ubik_amsyncsite = -1;
static int hf_afs_ubik_syncsiteuntil = -1;
static int hf_afs_ubik_nservers = -1;
static int hf_afs_ubik_lockedpages = -1;
static int hf_afs_ubik_writelockedpages = -1;
static int hf_afs_ubik_activewrite = -1;
static int hf_afs_ubik_tidcounter = -1;
static int hf_afs_ubik_anyreadlocks = -1;
static int hf_afs_ubik_anywritelocks = -1;
static int hf_afs_ubik_recoverystate = -1;
static int hf_afs_ubik_currenttrans = -1;
static int hf_afs_ubik_writetrans = -1;
static int hf_afs_ubik_epochtime = -1;
static int hf_afs_ubik_isclone = -1;
static int hf_afs_ubik_addr = -1;
static int hf_afs_ubik_lastvotetime = -1;
static int hf_afs_ubik_lastbeaconsent = -1;
static int hf_afs_ubik_lastvote = -1;
static int hf_afs_ubik_currentdb = -1;
static int hf_afs_ubik_beaconsincedown = -1;
static int hf_afs_ubik_up = -1;
static int hf_afs_repframe = -1;
static int hf_afs_reqframe = -1;
static int hf_afs_time = -1;

static gint ett_afs = -1;
static gint ett_afs_op = -1;
static gint ett_afs_acl = -1;
static gint ett_afs_fid = -1;
static gint ett_afs_callback = -1;
static gint ett_afs_ubikver = -1;
static gint ett_afs_status = -1;
static gint ett_afs_status_mask = -1;
static gint ett_afs_volsync = -1;
static gint ett_afs_volumeinfo = -1;
static gint ett_afs_vicestat = -1;
static gint ett_afs_vldb_flags = -1;

/*
 * Macros for helper dissection routines
 *
 * The macros are here to save on coding. They assume that
 * the current offset is in 'offset', and that the offset
 * should be incremented after performing the macro's operation.
 */


/* Output a unsigned integer, stored into field 'field'
   Assumes it is in network byte order, converts to host before using */
#define OUT_UINT(field) \
	proto_tree_add_uint(tree, field, tvb, offset, sizeof(guint32), tvb_get_ntohl(tvb, offset)); \
	offset += 4;

/* Output a unsigned integer, stored into field 'field'
   Assumes it is in network byte order, converts to host before using */
#define OUT_INT(field) \
	proto_tree_add_int(tree, field, tvb, offset, sizeof(gint32), tvb_get_ntohl(tvb, offset)); \
	offset += 4;

/* Output a unsigned integer, stored into field 'field'
   Assumes it is in network byte order, converts to host before using */
#define OUT_UINT64(field) \
	proto_tree_add_item(tree, field, tvb, offset, 8, FALSE); \
	offset += 8;

/* Output a unsigned integer, stored into field 'field'
   Assumes it is in network byte order, converts to host before using */
#define OUT_INT64(field) \
	proto_tree_add_item(tree, field, tvb, offset, 8, FALSE); \
	offset += 8;

/* Output a unsigned integer, stored into field 'field'
   Assumes it is in network byte order, converts to host before using,
   Note - does not increment offset, so can be used repeatedly for bitfields */
#define DISP_UINT(field) \
	proto_tree_add_uint(tree,field,tvb,offset,sizeof(guint32),tvb_get_ntohl(tvb, offset));

/* Output an IPv4 address, stored into field 'field' */
#define OUT_IP(field) \
	proto_tree_add_ipv4(tree,field,tvb,offset,sizeof(gint32),\
		tvb_get_letohl(tvb, offset));\
	offset += 4;

/* Output a simple rx array */
#define OUT_RXArray8(func) \
	{ \
		unsigned int j,i; \
		j = tvb_get_guint8(tvb, offset); \
		offset += 1; \
		for (i=0; i<j; i++) { \
			func; \
		} \
	}

/* Output a simple rx array */
#define OUT_RXArray32(func) \
	{ \
		unsigned int j,i; \
		j = tvb_get_ntohl(tvb, offset); \
		offset += sizeof(guint32); \
		for (i=0; i<j; i++) { \
			func; \
		} \
	}

/* Output a UNIX seconds/microseconds timestamp, after converting to an
   nstime_t */
#define OUT_TIMESTAMP(field) \
	{ nstime_t ts; \
	ts.secs = tvb_get_ntohl(tvb, offset); \
	ts.nsecs = tvb_get_ntohl(tvb, offset)*1000; \
	proto_tree_add_time(tree,field, tvb,offset,2*sizeof(guint32),&ts); \
	offset += 8; \
	}

/* Output a seconds-only time value, after converting to an nstime_t;
   this can be an absolute time as a UNIX time-since-epoch, or a
   relative time in seconds */
#define OUT_TIMESECS(field) \
	{ nstime_t ts; \
	ts.secs = tvb_get_ntohl(tvb, offset); \
	ts.nsecs = 0; \
	proto_tree_add_time(tree,field, tvb,offset,sizeof(guint32),&ts); \
	offset += 4; \
	}

/* Output a rx style string, up to a maximum length first
   4 bytes - length, then char data */
#define OUT_RXString(field) \
	{	guint32 i,len; \
		char *tmp; \
		const guint8 *p; \
		i = tvb_get_ntohl(tvb, offset); \
		offset += 4; \
		p = tvb_get_ptr(tvb,offset,i); \
		len = ((i+4-1)/4)*4; \
		tmp = g_malloc(i+1); \
		memcpy(tmp, p, i); \
		tmp[i] = '\0'; \
		proto_tree_add_string(tree, field, tvb, offset-4, len+4, \
		(void *)tmp); \
		g_free(tmp); \
		offset += len; \
	}

/* Output a fixed length vectorized string (each char is a 32 bit int) */
#define OUT_RXStringV(field, length) \
	{ 	char tmp[length+1]; \
		int i,soff; \
		soff = offset;\
		for (i=0; i<length; i++)\
		{\
			tmp[i] = (char) tvb_get_ntohl(tvb, offset);\
			offset += sizeof(guint32);\
		}\
		tmp[length] = '\0';\
		proto_tree_add_string(tree, field, tvb, soff, length*sizeof(guint32), tmp);\
	}


/* Output a callback */
#define OUT_FS_AFSCallBack() \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, tvb, offset, 3*4, "Callback"); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_callback); \
		OUT_UINT(hf_afs_fs_callback_version); \
		OUT_TIMESECS(hf_afs_fs_callback_expires); \
		OUT_UINT(hf_afs_fs_callback_type); \
		tree = save; \
	}

/* Output a callback */
#define OUT_CB_AFSCallBack() \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, tvb, offset, 3*4, "Callback"); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_callback); \
		OUT_UINT(hf_afs_cb_callback_version); \
		OUT_TIMESECS(hf_afs_cb_callback_expires); \
		OUT_UINT(hf_afs_cb_callback_type); \
		tree = save; \
	}

/* Output a File ID */
#define OUT_FS_AFSFid(label) \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, tvb, offset, 3*4, \
			"FileID (%s)", label); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_fid); \
		OUT_UINT(hf_afs_fs_fid_volume); \
		OUT_UINT(hf_afs_fs_fid_vnode); \
		OUT_UINT(hf_afs_fs_fid_uniqifier); \
		tree = save; \
	}

/* Output a Status mask */
#define OUT_FS_STATUSMASK() \
	{ 	proto_tree *save, *ti; \
		guint32 mask; \
		mask = tvb_get_ntohl(tvb, offset); \
		ti = proto_tree_add_uint(tree, hf_afs_fs_status_mask, tvb, offset, \
			sizeof(guint32), mask); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_status_mask); \
		proto_tree_add_boolean(tree, hf_afs_fs_status_mask_setmodtime, \
			tvb,offset,sizeof(guint32), mask); \
		proto_tree_add_boolean(tree, hf_afs_fs_status_mask_setowner, \
			tvb,offset,sizeof(guint32), mask); \
		proto_tree_add_boolean(tree, hf_afs_fs_status_mask_setgroup, \
			tvb,offset,sizeof(guint32), mask); \
		proto_tree_add_boolean(tree, hf_afs_fs_status_mask_setmode, \
			tvb,offset,sizeof(guint32), mask); \
		proto_tree_add_boolean(tree, hf_afs_fs_status_mask_setsegsize, \
			tvb,offset,sizeof(guint32), mask); \
		proto_tree_add_boolean(tree, hf_afs_fs_status_mask_fsync, \
			tvb,offset,sizeof(guint32), mask); \
		offset += 4; \
		tree = save; \
	}

/* Output vldb flags */
#define OUT_VLDB_Flags() \
	{ 	proto_tree *save, *ti; \
		guint32 flags; \
		flags = tvb_get_ntohl(tvb, offset); \
		ti = proto_tree_add_uint(tree, hf_afs_vldb_flags, tvb, offset, \
			sizeof(guint32), flags); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_vldb_flags); \
		proto_tree_add_boolean(tree, hf_afs_vldb_flags_rwexists, \
			tvb,offset,sizeof(guint32), flags); \
		proto_tree_add_boolean(tree, hf_afs_vldb_flags_roexists, \
			tvb,offset,sizeof(guint32), flags); \
		proto_tree_add_boolean(tree, hf_afs_vldb_flags_bkexists, \
			tvb,offset,sizeof(guint32), flags); \
		proto_tree_add_boolean(tree, hf_afs_vldb_flags_dfsfileset, \
			tvb,offset,sizeof(guint32), flags); \
		offset += 4; \
		tree = save; \
	}



/* Output a File ID */
#define OUT_CB_AFSFid(label) \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, tvb, offset, 3*4, \
			"FileID (%s)", label); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_fid); \
		OUT_UINT(hf_afs_cb_fid_volume); \
		OUT_UINT(hf_afs_cb_fid_vnode); \
		OUT_UINT(hf_afs_cb_fid_uniqifier); \
		tree = save; \
	}

/* Output a StoreStatus */
#define OUT_FS_AFSStoreStatus(label) \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, tvb, offset, 6*4, \
			label); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_status); \
		OUT_FS_STATUSMASK(); \
		OUT_TIMESECS(hf_afs_fs_status_clientmodtime); \
		OUT_UINT(hf_afs_fs_status_owner); \
		OUT_UINT(hf_afs_fs_status_group); \
		OUT_UINT(hf_afs_fs_status_mode); \
		OUT_UINT(hf_afs_fs_status_segsize); \
		tree = save; \
	}

/* Output a FetchStatus */
#define OUT_FS_AFSFetchStatus(label) \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, tvb, offset, 21*4, \
			label); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_status); \
		OUT_UINT(hf_afs_fs_status_interfaceversion); \
		OUT_UINT(hf_afs_fs_status_filetype); \
		OUT_UINT(hf_afs_fs_status_linkcount); \
		OUT_UINT(hf_afs_fs_status_length); \
		OUT_UINT(hf_afs_fs_status_dataversion); \
		OUT_UINT(hf_afs_fs_status_author); \
		OUT_UINT(hf_afs_fs_status_owner); \
		OUT_UINT(hf_afs_fs_status_calleraccess); \
		OUT_UINT(hf_afs_fs_status_anonymousaccess); \
		OUT_UINT(hf_afs_fs_status_mode); \
		OUT_UINT(hf_afs_fs_status_parentvnode); \
		OUT_UINT(hf_afs_fs_status_parentunique); \
		OUT_UINT(hf_afs_fs_status_segsize); \
		OUT_TIMESECS(hf_afs_fs_status_clientmodtime); \
		OUT_TIMESECS(hf_afs_fs_status_servermodtime); \
		OUT_UINT(hf_afs_fs_status_group); \
		OUT_UINT(hf_afs_fs_status_synccounter); \
		OUT_UINT(hf_afs_fs_status_dataversionhigh); \
		OUT_UINT(hf_afs_fs_status_spare2); \
		OUT_UINT(hf_afs_fs_status_spare3); \
		OUT_UINT(hf_afs_fs_status_spare4); \
		tree = save; \
	}

/* Output a VolSync */
#define OUT_FS_AFSVolSync() \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, tvb, offset, 6*4, \
			"VolSync"); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_volsync); \
		OUT_TIMESECS(hf_afs_fs_volsync_spare1); \
		OUT_UINT(hf_afs_fs_volsync_spare2); \
		OUT_UINT(hf_afs_fs_volsync_spare3); \
		OUT_UINT(hf_afs_fs_volsync_spare4); \
		OUT_UINT(hf_afs_fs_volsync_spare5); \
		OUT_UINT(hf_afs_fs_volsync_spare6); \
		tree = save; \
	}

/* Output a AFSCBFids */
#define OUT_FS_AFSCBFids() \
	OUT_RXArray32(OUT_FS_AFSFid("Target"));

/* Output a ViceIds */
#define OUT_FS_ViceIds() \
	OUT_RXArray8(OUT_UINT(hf_afs_fs_viceid));

/* Output a IPAddrs */
#define OUT_FS_IPAddrs() \
	OUT_RXArray8(OUT_IP(hf_afs_fs_ipaddr));

/* Output a AFSCBs */
#define OUT_FS_AFSCBs()	\
	OUT_RXArray32(OUT_FS_AFSCallBack());

/* Output a AFSBulkStats */
#define OUT_FS_AFSBulkStats() \
	OUT_RXArray32(OUT_FS_AFSFetchStatus("Status"));

/* Output a AFSFetchVolumeStatus */
#define OUT_FS_AFSFetchVolumeStatus()

/* Output a AFSStoreVolumeStatus */
#define OUT_FS_AFSStoreVolumeStatus()

/* Output a ViceStatistics structure */
#define OUT_FS_ViceStatistics()

/* Output a AFS_CollData structure */
#define OUT_FS_AFS_CollData()

/* Output a VolumeInfo structure */
#define OUT_FS_VolumeInfo()

/* Output an AFS Token - might just be bytes though */
#define OUT_FS_AFSTOKEN() OUT_RXStringV(hf_afs_fs_token, 1024)

/* Output a AFS acl */
#define ACLOUT(who, positive, acl, bytes) \
	{ 	proto_tree *save, *ti; \
		int tmpoffset; \
		int acllen; \
		char tmp[10]; \
		tmp[0] = 0; \
		if ( acl & PRSFS_READ ) strcat(tmp, "r"); \
		if ( acl & PRSFS_LOOKUP ) strcat(tmp, "l"); \
		if ( acl & PRSFS_INSERT ) strcat(tmp, "i"); \
		if ( acl & PRSFS_DELETE ) strcat(tmp, "d"); \
		if ( acl & PRSFS_WRITE ) strcat(tmp, "w"); \
		if ( acl & PRSFS_LOCK ) strcat(tmp, "k"); \
		if ( acl & PRSFS_ADMINISTER ) strcat(tmp, "a"); \
		ti = proto_tree_add_text(tree, tvb, offset, bytes, \
			"ACL:  %s %s%s", \
			who, tmp, positive ? "" : " (negative)"); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_acl); \
		proto_tree_add_string(tree,hf_afs_fs_acl_entity, tvb,offset,strlen(who), who);\
		tmpoffset = offset + strlen(who) + 1; \
		acllen = bytes - strlen(who) - 1; \
		proto_tree_add_boolean(tree,hf_afs_fs_acl_r, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_boolean(tree,hf_afs_fs_acl_l, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_boolean(tree,hf_afs_fs_acl_i, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_boolean(tree,hf_afs_fs_acl_d, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_boolean(tree,hf_afs_fs_acl_w, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_boolean(tree,hf_afs_fs_acl_k, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_boolean(tree,hf_afs_fs_acl_a, tvb,tmpoffset,acllen,acl);\
		tree = save; \
	}

/* Output a UUID */
#define OUT_UUID(x) \
	OUT_BYTES(x, 11*sizeof(guint32));
#define SKIP_UUID() \
	SKIP(11*sizeof(guint32));


/* Output a bulkaddr */
#define OUT_VLDB_BulkAddr() \
	OUT_RXArray32(OUT_IP(hf_afs_vldb_serverip));

/* output a bozo_key */
#define OUT_BOS_KEY() \
	OUT_BYTES(hf_afs_bos_key, 8);

/* output a bozo_key */
#define OUT_BOS_KEYINFO() \
	OUT_TIMESTAMP(hf_afs_bos_keymodtime); \
	OUT_UINT(hf_afs_bos_keychecksum); \
	OUT_UINT(hf_afs_bos_keyspare2);

/* output a bozo_netKTime */
#define OUT_BOS_TIME() \
	SKIP(4); SKIP(2); SKIP(2); SKIP(2); SKIP(2);

/* output a bozo_status */
#define OUT_BOS_STATUS() \
	SKIP(10 * 4);

/* output a ubik interface addr array */
#define OUT_UBIK_InterfaceAddrs() \
    { \
        unsigned int i,j,seen_null=0; \
        for (i=0; i<255; i++) { \
		j = tvb_get_ntohl(tvb, offset); \
		if ( j != 0 ) { \
			OUT_IP(hf_afs_ubik_interface); \
			seen_null = 0; \
		} else { \
			if ( ! seen_null ) { \
			proto_tree_add_text(tree, tvb, offset, \
				tvb_length_remaining(tvb, offset), \
				"Null Interface Addresses"); \
				seen_null = 1; \
			} \
			offset += 4; \
		}\
        } \
    }

#define OUT_UBIK_DebugOld() \
	{ \
		OUT_TIMESECS(hf_afs_ubik_now); \
		OUT_TIMESECS(hf_afs_ubik_lastyestime); \
		OUT_IP(hf_afs_ubik_lastyeshost); \
		OUT_UINT(hf_afs_ubik_lastyesstate); \
		OUT_TIMESECS(hf_afs_ubik_lastyesclaim); \
		OUT_IP(hf_afs_ubik_lowesthost); \
		OUT_TIMESECS(hf_afs_ubik_lowesttime); \
		OUT_IP(hf_afs_ubik_synchost); \
		OUT_TIMESECS(hf_afs_ubik_synctime); \
		OUT_UBIKVERSION("Sync Version"); \
		OUT_UBIKVERSION("Sync TID"); \
		OUT_UINT(hf_afs_ubik_amsyncsite); \
		OUT_TIMESECS(hf_afs_ubik_syncsiteuntil); \
		OUT_UINT(hf_afs_ubik_nservers); \
		OUT_UINT(hf_afs_ubik_lockedpages); \
		OUT_UINT(hf_afs_ubik_writelockedpages); \
		OUT_UBIKVERSION("Local Version"); \
		OUT_UINT(hf_afs_ubik_activewrite); \
		OUT_UINT(hf_afs_ubik_tidcounter); \
		OUT_UINT(hf_afs_ubik_anyreadlocks); \
		OUT_UINT(hf_afs_ubik_anywritelocks); \
		OUT_UINT(hf_afs_ubik_recoverystate); \
		OUT_UINT(hf_afs_ubik_currenttrans); \
		OUT_UINT(hf_afs_ubik_writetrans); \
		OUT_TIMESECS(hf_afs_ubik_epochtime); \
	}

#define OUT_UBIK_SDebugOld() \
	{ \
		OUT_IP(hf_afs_ubik_addr); \
		OUT_TIMESECS(hf_afs_ubik_lastvotetime); \
		OUT_TIMESECS(hf_afs_ubik_lastbeaconsent); \
		OUT_UINT(hf_afs_ubik_lastvote); \
		OUT_UBIKVERSION("Remote Version"); \
		OUT_UINT(hf_afs_ubik_currentdb); \
		OUT_UINT(hf_afs_ubik_beaconsincedown); \
		OUT_UINT(hf_afs_ubik_up); \
	}

/* Skip a certain number of bytes */
#define SKIP(bytes) \
	offset += bytes;

/* Raw data - to end of frame */
#define OUT_BYTES_ALL(field) OUT_BYTES(field, tvb_length_remaining(tvb,offset))

/* Raw data */
#define OUT_BYTES(field, bytes) \
	proto_tree_add_item(tree, field, tvb, offset, bytes, FALSE);\
	offset += bytes;



/* Skip the opcode */
#define SKIP_OPCODE() \
	{ \
		SKIP(sizeof(guint32)); \
	}

/* Output a UBIK version code */
#define OUT_UBIKVERSION(label) \
	{ 	proto_tree *save, *ti; \
		unsigned int epoch,counter; \
		nstime_t ts; \
		epoch = tvb_get_ntohl(tvb, offset); \
		offset += 4; \
		counter = tvb_get_ntohl(tvb, offset); \
		offset += 4; \
		ts.secs = epoch; \
		ts.nsecs = 0; \
		ti = proto_tree_add_text(tree, tvb, offset-8, 8, \
			"UBIK Version (%s): %u.%u", label, epoch, counter ); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_ubikver); \
		if ( epoch != 0 ) \
		proto_tree_add_time(tree,hf_afs_ubik_version_epoch, tvb,offset-8, \
			sizeof(guint32),&ts); \
		else \
			proto_tree_add_text(tree, tvb, offset-8, \
			sizeof(guint32),"Epoch: 0"); \
		proto_tree_add_uint(tree,hf_afs_ubik_version_counter, tvb,offset-4, \
			sizeof(guint32),counter); \
		tree = save; \
	}

/* Output a kauth getticket request */
#define OUT_KAUTH_GetTicket() \
	{ \
		int len = 0; \
		OUT_UINT(hf_afs_kauth_kvno); \
		OUT_RXString(hf_afs_kauth_domain); \
		len = tvb_get_ntohl(tvb, offset); \
		offset += 4; \
		OUT_BYTES(hf_afs_kauth_data, len); \
		OUT_RXString(hf_afs_kauth_princ); \
		OUT_RXString(hf_afs_kauth_realm); \
	}

#define GETSTR ((const char *)tvb_get_ptr(tvb,offset,tvb_ensure_length_remaining(tvb,offset)))

#define VALID_OPCODE(opcode) ((opcode >= OPCODE_LOW && opcode <= OPCODE_HIGH) || \
		(opcode >= VOTE_LOW && opcode <= VOTE_HIGH) || \
		(opcode >= DISK_LOW && opcode <= DISK_HIGH))

static const value_string fs_req[] = {
	{ 130,		"fetch-data" },
	{ 131,		"fetch-acl" },
	{ 132,		"fetch-status" },
	{ 133,		"store-data" },
	{ 134,		"store-acl" },
	{ 135,		"store-status" },
	{ 136,		"remove-file" },
	{ 137,		"create-file" },
	{ 138,		"rename" },
	{ 139,		"symlink" },
	{ 140,		"link" },
	{ 141,		"makedir" },
	{ 142,		"rmdir" },
	{ 143,		"old-set-lock" },
	{ 144,		"old-extend-lock" },
	{ 145,		"old-release-lock" },
	{ 146,		"get-stats" },
	{ 147,		"give-up-callbacks" },
	{ 148,		"get-volume-info" },
	{ 149,		"get-volume-status" },
	{ 150,		"set-volume-status" },
	{ 151,		"get-root-volume" },
	{ 152,		"check-token" },
	{ 153,		"get-time" },
	{ 154,		"nget-volume-info" },
	{ 155,		"bulk-status" },
	{ 156,		"set-lock" },
	{ 157,		"extend-lock" },
	{ 158,		"release-lock" },
	{ 159,		"xstats-version" },
	{ 160,		"get-xstats" },
	{ 161,		"dfs-lookup" },
	{ 162,		"dfs-flushcps" },
	{ 163,		"dfs-symlink" },
	{ 220,		"residency" },
	{ 65536, 	"inline-bulk-status" },
	{ 65537, 	"fetch-data-64" },
	{ 65538, 	"store-data-64" },
	{ 65539, 	"give-up-all-callbacks" },
	{ 65540, 	"get-capabilities" },
	{ 0,		NULL },
};

static const value_string cb_req[] = {
	{ 204,		"callback" },
	{ 205,		"init-callback-state" },
	{ 206,		"probe" },
	{ 207,		"get-lock" },
	{ 208,		"get-ce" },
	{ 209,		"xstats-version" },
	{ 210,		"get-xstats" },
	{ 211,		"init-callback-state2" },
	{ 212,		"who-are-you" },
	{ 213,		"init-callback-state3" },
	{ 214,		"probeuuid" },
	{ 215,		"get-server-prefs" },
	{ 216,		"get-cellservdb" },
	{ 217,		"get-local-cell" },
	{ 218,		"get-cache-config" },
	{ 65536,	"get-ce-64" },
	{ 65537,	"get-cell-by-num" },
	{ 65538,	"get-capabilities" },
	{ 0,		NULL },
};

static const value_string prot_req[] = {
	{ 500,		"new-user" },
	{ 501,		"where-is-it" },
	{ 502,		"dump-entry" },
	{ 503,		"add-to-group" },
	{ 504,		"name-to-id" },
	{ 505,		"id-to-name" },
	{ 506,		"delete" },
	{ 507,		"remove-from-group" },
	{ 508,		"get-cps" },
	{ 509,		"new-entry" },
	{ 510,		"list-max" },
	{ 511,		"set-max" },
	{ 512,		"list-entry" },
	{ 513,		"change-entry" },
	{ 514,		"list-elements" },
	{ 515,		"is-member-of" },
	{ 516,		"set-fld-sentry" },
	{ 517,		"list-owned" },
	{ 518,		"get-cps2" },
	{ 519,		"get-host-cps" },
	{ 520,		"update-entry" },
	{ 521,		"list-entries" },
	{ 0,		NULL },
};

static const value_string vldb_req[] = {
	{ 501,		"create-entry" },
	{ 502,		"delete-entry" },
	{ 503,		"get-entry-by-id" },
	{ 504,		"get-entry-by-name" },
	{ 505,		"get-new-volume-id" },
	{ 506,		"replace-entry" },
	{ 507,		"update-entry" },
	{ 508,		"set-lock" },
	{ 509,		"release-lock" },
	{ 510,		"list-entry" },
	{ 511,		"list-attributes" },
	{ 512,		"linked-list" },
	{ 513,		"get-stats" },
	{ 514,		"probe" },
	{ 515,		"get-addrs" },
	{ 516,		"change-addr" },
	{ 517,		"create-entry-n" },
	{ 518,		"get-entry-by-id-n" },
	{ 519,		"get-entry-by-name-n" },
	{ 520,		"replace-entry-n" },
	{ 521,		"list-entry-n" },
	{ 522,		"list-attrib-n" },
	{ 523,		"linked-list-n" },
	{ 524,		"update-entry-by-name" },
	{ 525,		"create-entry-u" },
	{ 526,		"get-entry-by-id-u" },
	{ 527,		"get-entry-by-name-u" },
	{ 528,		"replace-entry-u" },
	{ 529,		"list-entry-u" },
	{ 530,		"list-attrib-u" },
	{ 531,		"linked-list-u" },
	{ 532,		"regaddr" },
	{ 533,		"get-addrs-u" },
	{ 534,		"list-attrib-n2" },
	{ 0,		NULL },
};

static const value_string kauth_req[] = {
	{ 1,		"auth-old" },
	{ 21,		"authenticate" },
	{ 22,		"authenticate-v2" },
	{ 2,		"change-pw" },
	{ 3,		"get-ticket-old" },
	{ 23,		"get-ticket" },
	{ 4,		"set-pw" },
	{ 5,		"set-fields" },
	{ 6,		"create-user" },
	{ 7,		"delete-user" },
	{ 8,		"get-entry" },
	{ 9,		"list-entry" },
	{ 10,		"get-stats" },
	{ 11,		"debug" },
	{ 12,		"get-pw" },
	{ 13,		"get-random-key" },
	{ 14,		"unlock" },
	{ 15,		"lock-status" },
	{ 0,		NULL },
};

static const value_string vol_req[] = {
	{ 100,		"create-volume" },
	{ 101,		"delete-volume" },
	{ 102,		"restore" },
	{ 103,		"forward" },
	{ 104,		"end-trans" },
	{ 105,		"clone" },
	{ 106,		"set-flags" },
	{ 107,		"get-flags" },
	{ 108,		"trans-create" },
	{ 109,		"dump" },
	{ 110,		"get-nth-volume" },
	{ 111,		"set-forwarding" },
	{ 112,		"get-name" },
	{ 113,		"get-status" },
	{ 114,		"sig-restore" },
	{ 115,		"list-partitions" },
	{ 116,		"list-volumes" },
	{ 117,		"set-id-types" },
	{ 118,		"monitor" },
	{ 119,		"partition-info" },
	{ 120,		"reclone" },
	{ 121,		"list-one-volume" },
	{ 122,		"nuke" },
	{ 123,		"set-date" },
	{ 124,		"x-list-volumes" },
	{ 125,		"x-list-one-volume" },
	{ 126,		"set-info" },
	{ 127,		"x-list-partitions" },
	{ 128,		"forward-multiple" },
	{ 65536,	"convert-ro" },
	{ 65537,	"getsize" },
	{ 0,		NULL },
};

static const value_string bos_req[] = {
	{ 80,		"create-bnode" },
	{ 81,		"delete-bnode" },
	{ 82,		"set-status" },
	{ 83,		"get-status" },
	{ 84,		"enumerate-instance" },
	{ 85,		"get-instance-info" },
	{ 86,		"get-instance-parm" },
	{ 87,		"add-superuser" },
	{ 88,		"delete-superuser" },
	{ 89,		"list-superusers" },
	{ 90,		"list-keys" },
	{ 91,		"add-key" },
	{ 92,		"delete-key" },
	{ 93,		"set-cell-name" },
	{ 94,		"get-cell-name" },
	{ 95,		"get-cell-host" },
	{ 96,		"add-cell-host" },
	{ 97,		"delete-cell-host" },
	{ 98,		"set-t-status" },
	{ 99,		"shutdown-all" },
	{ 100,		"restart-all" },
	{ 101,		"startup-all" },
	{ 102,		"set-noauth-flag" },
	{ 103,		"re-bozo" },
	{ 104,		"restart" },
	{ 105,		"install" },
	{ 106,		"uninstall" },
	{ 107,		"get-dates" },
	{ 108,		"exec" },
	{ 109,		"prune" },
	{ 110,		"set-restart-time" },
	{ 111,		"get-restart-time" },
	{ 112,		"get-log" },
	{ 113,		"wait-all" },
	{ 114,		"get-instance-strings" },
	{ 115, 		"get-restricted" },
	{ 116, 		"set restricted" },
	{ 0,		NULL },
};

static const value_string update_req[] = {
	{ 1,		"fetch-file" },
	{ 2,		"fetch-info" },
	{ 0,		NULL },
};

static const value_string rmtsys_req[] = {
	{ 1,		"setpag" },
	{ 2,		"pioctl" },
	{ 0,		NULL },
};

static const value_string backup_req[] = {
	{ 100,		"perform-dump" },
	{ 101,		"perform-restore" },
	{ 102,		"check-dump" },
	{ 103,		"abort-dump" },
	{ 104,		"wait-for-dump" },
	{ 105,		"end-dump" },
	{ 106,		"get-tm-info" },
	{ 107,		"label-tape" },
	{ 108,		"scan-nodes" },
	{ 109,		"read-label" },
	{ 110,		"scan-dumps" },
	{ 111,		"get-tc-info" },
	{ 112,		"save-database" },
	{ 113,		"restore-database" },
	{ 114,		"get-status" },
	{ 115,		"request-abort" },
	{ 116,		"end-status" },
	{ 117,		"scan-status" },
	{ 118,		"delete-dump" },
	{ 0,		NULL },
};

static const value_string ubik_req[] = {
	{ 10000,	"vote-beacon" },
	{ 10001,	"vote-debug-old" },
	{ 10002,	"vote-sdebug-old" },
	{ 10003,	"vote-getsyncsite" },
	{ 10004,	"vote-debug" },
	{ 10005,	"vote-sdebug" },
	{ 10006,	"vote-xdebug" },
	{ 10007,	"vote-xsdebug" },
	{ 20000,	"disk-begin" },
	{ 20001,	"disk-commit" },
	{ 20002,	"disk-lock" },
	{ 20003,	"disk-write" },
	{ 20004,	"disk-getversion" },
	{ 20005,	"disk-getfile" },
	{ 20006,	"disk-sendfile" },
	{ 20007,	"disk-abort" },
	{ 20008,	"disk-releaselocks" },
	{ 20009,	"disk-truncate" },
	{ 20010,	"disk-probe" },
	{ 20011,	"disk-writev" },
	{ 20012,	"disk-interfaceaddr" },
	{ 20013,	"disk-setversion" },
	{ 0,		NULL },
};

static const value_string cb_types[] = {
	{ CB_TYPE_EXCLUSIVE, "exclusive" },
	{ CB_TYPE_SHARED, "shared" },
	{ CB_TYPE_DROPPED, "dropped" },
	{ 0, NULL },
};

static const value_string afs_errors[] = {
	/* VOL Errors */
	{ 363520, "ID Exists"},
	{ 363521, "IO Error"},
	{ 363522, "Name Exists"},
	{ 363523, "Create Failed"},
	{ 363524, "Entry Not Found"},
	{ 363525, "Empty"},
	{ 363526, "Entry Deleted"},
	{ 363527, "Bad Name"},
	{ 363528, "Bad Index"},
	{ 363529, "Bad Volume Type"},
	{ 363530, "Bad Partition"},
	{ 363531, "Bad Server"},
	{ 363532, "Bad Replicate Server"},
	{ 363533, "No Replicate Server"},
	{ 363534, "Duplicate Replicate Server"},
	{ 363535, "ReadWrite Volume Not Found"},
	{ 363536, "Bad Reference Count"},
	{ 363537, "Size Exceeded"},
	{ 363538, "Bad Entry"},
	{ 363539, "Bad Volume ID Bump"},
	{ 363540, "Already has edit"},
	{ 363541, "Entry Locked"},
	{ 363542, "Bad Volume Operation"},
	{ 363543, "Bad Rel Lock Type"},
	{ 363544, "Rerelease"},
	{ 363545, "Bad Server"},
	{ 363546, "Permission Denied"},
	{ 363547, "Out of Memory"},

	/* KAUTH Errors */
	{ 180480, "Database Inconsistent"},
	{ 180481, "Exists"},
	{ 180482, "IO"},
	{ 180483, "Create Failed"},
	{ 180484, "noent"},
	{ 180485, "Empty"},
	{ 180486, "Bad Name"},
	{ 180487, "Bad Index"},
	{ 180488, "No auth"},
	{ 180489, "Answer too long"},
	{ 180490, "Bad Request"},
	{ 180491, "Old Interface"},
	{ 180492, "Bad Argument"},
	{ 180493, "Bad Command"},
	{ 180494, "No keys"},
	{ 180495, "Read PW"},
	{ 180496, "Bad key"},
	{ 180497, "Ubik Init"},
	{ 180498, "Ubik Call"},
	{ 180499, "Bad Protocol"},
	{ 180500, "No cells"},
	{ 180501, "No cell"},
	{ 180502, "Too many ubiks"},
	{ 180503, "Too many keys"},
	{ 180504, "Bad ticket"},
	{ 180505, "Unknown Key"},
	{ 180506, "Key Cache Invalid"},
	{ 180507, "Bad Server"},
	{ 180508, "Bad User"},
	{ 180509, "Bad CPW"},
	{ 180510, "Bad Create"},
	{ 180511, "No ticket"},
	{ 180512, "Assoc user"},
	{ 180513, "Not special"},
	{ 180514, "Clock skew too great"},
	{ 180515, "No recursion"},
	{ 180516, "RX failed"},
	{ 180517, "Null password"},
	{ 180518, "Internal error"},
	{ 180519, "Password expired"},
	{ 180520, "Reused"},
	{ 180521, "Too soon"},
	{ 180522, "Locked"},

	/* PT Errors */
	{ 267264, "Exists"},
	{ 267265, "ID Exists"},
	{ 267266, "No IDs"},
	{ 267267, "DB Failed"},
	{ 267268, "No such entry"},
	{ 267269, "Permission denied"},
	{ 267270, "Not group"},
	{ 267271, "Not user"},
	{ 267272, "Bad name"},
	{ 267273, "Bad argument"},
	{ 267274, "No more"},
	{ 267275, "Bad DB"},
	{ 267276, "Group empty"},
	{ 267277, "Inconsistent"},
	{ 267278, "DB Address"},
	{ 267279, "Too many"},
	{ 267280, "No memory"},

	/* Volume server errors */
	{ 1492325120, "Release error"},
	{ 1492325121, "No op"},
	{ 1492325122, "Read dump error"},
	{ 1492325123, "Dump error"},
	{ 1492325124, "Attach error"},
	{ 1492325125, "Illegal partition"},
	{ 1492325126, "Detach error"},
	{ 1492325127, "Bad access"},
	{ 1492325128, "VLDB error"},
	{ 1492325129, "Bad Name"},
	{ 1492325130, "Volume moved"},
	{ 1492325131, "Bad operation"},
	{ 1492325132, "Bad release"},
	{ 1492325133, "Volume busy"},
	{ 1492325134, "No memory"},
	{ 1492325135, "No volume"},
	{ 1492325136, "Multiple RW volumes"},
	{ 1492325137, "Failed operation"},

	/* add more of these errors to decode the errcode responses */
	{ 0, NULL },
};

static const value_string port_types[] = {
	{ AFS_PORT_FS, "File Server" },
	{ AFS_PORT_CB, "Callback Server" },
	{ AFS_PORT_BOS, "BOS Server" },
	{ AFS_PORT_PROT, "Protection Server" },
	{ AFS_PORT_VLDB, "Volume Location Database Server" },
	{ AFS_PORT_KAUTH, "Kerberos Authentication Server" },
	{ AFS_PORT_ERROR, "Error Server" },
	{ AFS_PORT_VOL, "Volume Server" },
	{ AFS_PORT_RMTSYS, "Rmtsys? Server" },
	{ AFS_PORT_UPDATE, "Update? Server" },
	{ AFS_PORT_BACKUP, "Backup Server" },
	{ 0, NULL }
};

static const value_string port_types_short[] = {
	{ AFS_PORT_FS, "FS" },
	{ AFS_PORT_CB, "CB" },
	{ AFS_PORT_BOS, "BOS" },
	{ AFS_PORT_PROT, "PROT" },
	{ AFS_PORT_VLDB, "VLDB" },
	{ AFS_PORT_KAUTH, "KAUTH" },
	{ AFS_PORT_ERROR, "ERR" },
	{ AFS_PORT_VOL, "VOL" },
	{ AFS_PORT_RMTSYS, "RMT" },
	{ AFS_PORT_UPDATE, "UPD" },
	{ AFS_PORT_BACKUP, "BKUP" },
	{ 0, NULL }
};

static const value_string ubik_lock_types[] = {
	{ 1,		"read" },
	{ 2,		"write" },
	{ 3,		"wait" },
	{ 0,		NULL },
};

static const value_string xstat_collections[] = {
	{ 0,		"call counting & info" },
	{ 1,		"performance info" },
	{ 2,		"full performance info" },
	{ 0,		NULL },
};

static const value_string vice_lock_types[] = {
	{ 0,		"read" },
	{ 1,		"write" },
	{ 2,		"extend" },
	{ 3,		"release" },
	{ 0,		NULL },
};

static const value_string volume_types[] = {
	{ 0,		"read-write" },
	{ 1,		"read-only" },
	{ 2,		"backup" },
	{ 0xffffffff, "any" },
	{ 0,		NULL },
};

struct afs_request_key {
  guint32 conversation, callnumber;
  guint16 service;
};

struct afs_request_val {
  guint32 opcode;
  guint req_num;
  guint rep_num;
  nstime_t req_time;
};

static GHashTable *afs_request_hash = NULL;


/*
 * Dissector prototypes
 */
static int dissect_acl(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset);
static void dissect_fs_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_fs_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_bos_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_bos_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_vol_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_vol_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_kauth_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_kauth_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_cb_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_cb_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_prot_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_prot_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_vldb_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_vldb_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_ubik_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_ubik_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_backup_reply(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);
static void dissect_backup_request(tvbuff_t *tvb, struct rxinfo *rxinfo,
	proto_tree *tree, int offset, int opcode);

/*
 * Hash Functions
 */
static gint
afs_equal(gconstpointer v, gconstpointer w)
{
  const struct afs_request_key *v1 = (const struct afs_request_key *)v;
  const struct afs_request_key *v2 = (const struct afs_request_key *)w;

  if (v1 -> conversation == v2 -> conversation &&
      v1 -> service == v2 -> service &&
      v1 -> callnumber == v2 -> callnumber ) {

    return 1;
  }

  return 0;
}

static guint
afs_hash (gconstpointer v)
{
	const struct afs_request_key *key = (const struct afs_request_key *)v;
	guint val;

	val = key -> conversation + key -> service + key -> callnumber;

	return val;
}

/*
 * Protocol initialization
 */
static void
afs_init_protocol(void)
{
	if (afs_request_hash)
		g_hash_table_destroy(afs_request_hash);

	afs_request_hash = g_hash_table_new(afs_hash, afs_equal);
}



/*
 * Dissection routines
 */

static void
dissect_afs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct rxinfo *rxinfo = pinfo->private_data;
	int reply = 0;
	conversation_t *conversation;
	struct afs_request_key request_key, *new_request_key;
	struct afs_request_val *request_val=NULL;
	proto_tree      *afs_tree, *afs_op_tree, *ti;
	int port, node, typenode, opcode;
	value_string const *vals;
	int offset = 0;
	nstime_t delta_ts;

	void (*dissector)(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode);


	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "AFS (RX)");
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
	}

	reply = (rxinfo->flags & RX_CLIENT_INITIATED) == 0;
	port = ((reply == 0) ? pinfo->destport : pinfo->srcport );

	/*
	 * Find out what conversation this packet is part of.
	 * XXX - this should really be done by the transport-layer protocol,
	 * although for connectionless transports, we may not want to do that
	 * unless we know some higher-level protocol will want it - or we
	 * may want to do it, so you can say e.g. "show only the packets in
	 * this UDP 'connection'".
	 *
	 * Note that we don't have to worry about the direction this packet
	 * was going - the conversation code handles that for us, treating
	 * packets from A:X to B:Y as being part of the same conversation as
	 * packets from B:Y to A:X.
	 */
	conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype,
	    pinfo->srcport, pinfo->destport, 0);
	if (conversation == NULL) {
		/* It's not part of any conversation - create a new one. */
		conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
			pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	}

	request_key.conversation = conversation->index;
	request_key.service = rxinfo->serviceid;
	request_key.callnumber = rxinfo->callnumber;

	request_val = (struct afs_request_val *) g_hash_table_lookup(
		afs_request_hash, &request_key);

	/* only allocate a new hash element when it's a request */
	opcode = 0;
	if(!pinfo->fd->flags.visited){
		if ( !request_val && !reply) {
			new_request_key = se_alloc(sizeof(struct afs_request_key));
			*new_request_key = request_key;

			request_val = se_alloc(sizeof(struct afs_request_val));
			request_val -> opcode = tvb_get_ntohl(tvb, offset);
			request_val -> req_num = pinfo->fd->num;
			request_val -> rep_num = 0;
			request_val -> req_time = pinfo->fd->abs_ts;

			g_hash_table_insert(afs_request_hash, new_request_key,
				request_val);
		}
		if( request_val && reply ) {
			request_val -> rep_num = pinfo->fd->num;
		}
	}

	if ( request_val ) {
		opcode = request_val->opcode;
	}


	node = 0;
	typenode = 0;
	vals = NULL;
	dissector = NULL;
	switch (port) {
		case AFS_PORT_FS:
			typenode = hf_afs_fs;
			node = hf_afs_fs_opcode;
			vals = fs_req;
			dissector = reply ? dissect_fs_reply : dissect_fs_request;
			break;
		case AFS_PORT_CB:
			typenode = hf_afs_cb;
			node = hf_afs_cb_opcode;
			vals = cb_req;
			dissector = reply ? dissect_cb_reply : dissect_cb_request;
			break;
		case AFS_PORT_PROT:
			typenode = hf_afs_prot;
			node = hf_afs_prot_opcode;
			vals = prot_req;
			dissector = reply ? dissect_prot_reply : dissect_prot_request;
			break;
		case AFS_PORT_VLDB:
			typenode = hf_afs_vldb;
			node = hf_afs_vldb_opcode;
			vals = vldb_req;
			dissector = reply ? dissect_vldb_reply : dissect_vldb_request;
			break;
		case AFS_PORT_KAUTH:
			typenode = hf_afs_kauth;
			node = hf_afs_kauth_opcode;
			vals = kauth_req;
			dissector = reply ? dissect_kauth_reply : dissect_kauth_request;
			break;
		case AFS_PORT_VOL:
			typenode = hf_afs_vol;
			node = hf_afs_vol_opcode;
			vals = vol_req;
			dissector = reply ? dissect_vol_reply : dissect_vol_request;
			break;
		case AFS_PORT_ERROR:
			typenode = hf_afs_error;
			node = hf_afs_error_opcode;
			/* dissector = reply ? dissect_error_reply : dissect_error_request; */
			break;
		case AFS_PORT_BOS:
			typenode = hf_afs_bos;
			node = hf_afs_bos_opcode;
			vals = bos_req;
			dissector = reply ? dissect_bos_reply : dissect_bos_request;
			break;
		case AFS_PORT_UPDATE:
			typenode = hf_afs_update;
			node = hf_afs_update_opcode;
			vals = update_req;
			/* dissector = reply ? dissect_update_reply : dissect_update_request; */
			break;
		case AFS_PORT_RMTSYS:
			typenode = hf_afs_rmtsys;
			node = hf_afs_rmtsys_opcode;
			vals = rmtsys_req;
			/* dissector = reply ? dissect_rmtsys_reply : dissect_rmtsys_request; */
			break;
		case AFS_PORT_BACKUP:
			typenode = hf_afs_backup;
			node = hf_afs_backup_opcode;
			vals = backup_req;
			dissector = reply ? dissect_backup_reply : dissect_backup_request;
			break;
	}

	if ( (opcode >= VOTE_LOW && opcode <= VOTE_HIGH) ||
		(opcode >= DISK_LOW && opcode <= DISK_HIGH) ) {
		typenode = hf_afs_ubik;
		node = hf_afs_ubik_opcode;
		vals = ubik_req;
		dissector = reply ? dissect_ubik_reply : dissect_ubik_request;
	}


	if ( VALID_OPCODE(opcode) ) {
		if ( vals ) {
			if (check_col(pinfo->cinfo, COL_INFO))
				col_add_fstr(pinfo->cinfo, COL_INFO, "%s%s %s: %s (%d)",
				typenode == hf_afs_ubik ? "UBIK-" : "",
				val_to_str(port, port_types_short, "Unknown(%d)"),
				reply ? "Reply" : "Request",
				val_to_str(opcode, vals, "Unknown(%d)"), opcode);
		} else {
			if (check_col(pinfo->cinfo, COL_INFO))
				col_add_fstr(pinfo->cinfo, COL_INFO, "%s%s %s: Unknown(%d)",
				typenode == hf_afs_ubik ? "UBIK-" : "",
				val_to_str(port, port_types_short, "Unknown(%d)"),
				reply ? "Reply" : "Request",
				opcode);
		}
	} else {
		if (check_col(pinfo->cinfo, COL_INFO))
			col_add_fstr(pinfo->cinfo, COL_INFO, "Encrypted %s %s",
			val_to_str(port, port_types_short, "Unknown(%d)"),
			reply ? "Reply" : "Request"
			);
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_afs, tvb, offset, -1,
				FALSE);
		afs_tree = proto_item_add_subtree(ti, ett_afs);

		proto_tree_add_text(afs_tree, tvb, 0, 0,
			"Service: %s%s%s %s",
			VALID_OPCODE(opcode) ? "" : "Encrypted ",
			typenode == hf_afs_ubik ? "UBIK - " : "",
			val_to_str(port, port_types, "Unknown(%d)"),
			reply ? "Reply" : "Request");

		if( request_val && !reply && request_val->rep_num) {
			proto_tree_add_uint_format(afs_tree, hf_afs_repframe,
			    tvb, 0, 0, request_val->rep_num,
			    "The reply to this request is in frame %u",
			    request_val->rep_num);
		}
		if( request_val && reply && request_val->rep_num) {
			proto_tree_add_uint_format(afs_tree, hf_afs_reqframe,
			    tvb, 0, 0, request_val->req_num,
			    "This is a reply to a request in frame %u",
			    request_val->req_num);
			nstime_delta(&delta_ts, &pinfo->fd->abs_ts, &request_val->req_time);
			proto_tree_add_time(afs_tree, hf_afs_time, tvb, offset, 0,
				&delta_ts);
		}


		if ( VALID_OPCODE(opcode) ) {
			/* until we do cache, can't handle replies */
			ti = NULL;
			if ( !reply && node != 0 ) {
				if ( rxinfo->seq == 1 )
				{
					ti = proto_tree_add_uint(afs_tree,
						node, tvb, offset, 4, opcode);
				} else {
					ti = proto_tree_add_uint(afs_tree,
						node, tvb, 0, 0, opcode);
				}
			} else if ( reply && node != 0 ) {
				/* the opcode isn't in this packet */
				ti = proto_tree_add_uint(afs_tree,
					node, tvb, 0, 0, opcode);
			} else {
				ti = proto_tree_add_text(afs_tree, tvb,
					0, 0, "Operation: Unknown");
			}

			/* Add the subtree for this particular service */
			afs_op_tree = proto_item_add_subtree(ti, ett_afs_op);

			
			if ( typenode != 0 ) {
				/* indicate the type of request */
				proto_tree_add_boolean_hidden(afs_tree, typenode, tvb, offset, 0, 1);
			}

			/* Process the packet according to what service it is */
			if ( dissector ) {
				(*dissector)(tvb, rxinfo, afs_op_tree, offset, opcode);
			}
		}
	}

	/* if it's the last packet, and it's a reply, remove opcode
		from hash */
	/* ignoring for now, I'm not sure how the chunk deallocation works */
	if ( rxinfo->flags & RX_LAST_PACKET && reply ){

	}
}


/*
 * Here is a helper routine for adding an AFS acl to the proto tree
 * This is to be used with FS packets only
 *
 * An AFS ACL is a string that has the following format:
 *
 * <positive> <negative>
 * <uid1> <aclbits1>
 * ....
 *
 * "positive" and "negative" are integers which contain the number of
 * positive and negative ACL's in the string.  The uid/aclbits pair are
 * ASCII strings containing the UID/PTS record and and a ascii number
 * representing a logical OR of all the ACL permission bits
 */
/*
 * XXX - FIXME:
 *
 *	sscanf is probably quite dangerous if we run outside the packet.
 *
 *	"GETSTR" doesn't guarantee that the resulting string is
 *	null-terminated.
 *
 * Should this just scan the string itself, rather than using "sscanf()"?
 */
static int
dissect_acl(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset)
{
	int old_offset;
	gint32 bytes;
	int i, n, pos, neg, acl;
	char user[128]; /* Be sure to adjust sscanf()s below if length is changed... */

	old_offset = offset;
	bytes = tvb_get_ntohl(tvb, offset);
	OUT_UINT(hf_afs_fs_acl_datasize);


	if (sscanf(GETSTR, "%d %n", &pos, &n) != 1) {
		/* does not matter what we return, if this fails,
		 * we cant dissect anything else in the packet either.
		 */
		return offset;
	}
	proto_tree_add_uint(tree, hf_afs_fs_acl_count_positive, tvb,
		offset, n, pos);
	offset += n;


	if (sscanf(GETSTR, "%d %n", &neg, &n) != 1) {
		return offset;
	}
	proto_tree_add_uint(tree, hf_afs_fs_acl_count_negative, tvb,
		offset, n, neg);
	offset += n;

	/*
	 * This wacky order preserves the order used by the "fs" command
	 */
	for (i = 0; i < pos; i++) {
		if (sscanf(GETSTR, "%127s %d %n", user, &acl, &n) != 2) {
			return offset;
		}
		ACLOUT(user,1,acl,n);
		offset += n;
	}
	for (i = 0; i < neg; i++) {
		if (sscanf(GETSTR, "%127s %d %n", user, &acl, &n) != 2) {
			return offset;
		}
		ACLOUT(user,0,acl,n);
		offset += n;
		if (offset >= old_offset+bytes ) {
			return offset;
		}
	}

	return offset;
}

/*
 * Here are the helper dissection routines
 */

static void
dissect_fs_reply(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 130: /* fetch data */
				/* only on first packet */
				if ( rxinfo->seq == 1 )
				{
					OUT_FS_AFSFetchStatus("Status");
					OUT_FS_AFSCallBack();
					OUT_FS_AFSVolSync();
				}
				OUT_BYTES_ALL(hf_afs_fs_data);
				break;
			case 131: /* fetch acl */
				offset = dissect_acl(tvb, rxinfo, tree, offset);
				OUT_FS_AFSFetchStatus("Status");
				OUT_FS_AFSVolSync();
				break;
			case 132: /* Fetch status */
				OUT_FS_AFSFetchStatus("Status");
				OUT_FS_AFSCallBack();
				OUT_FS_AFSVolSync();
				break;
			case 133: /* Store data */
			case 134: /* Store ACL */
	 		case 135: /* Store status */
			case 136: /* Remove file */
				OUT_FS_AFSFetchStatus("Status");
				OUT_FS_AFSVolSync();
				break;
			case 137: /* create file */
			case 141: /* make dir */
			case 161: /* lookup */
			case 163: /* dfs symlink */
				OUT_FS_AFSFid((opcode == 137)? "New File" : ((opcode == 141)? "New Directory" : "File"));
				OUT_FS_AFSFetchStatus("File Status");
				OUT_FS_AFSFetchStatus("Directory Status");
				OUT_FS_AFSCallBack();
				OUT_FS_AFSVolSync();
				break;
			case 138: /* rename */
				OUT_FS_AFSFetchStatus("Old Directory Status");
				OUT_FS_AFSFetchStatus("New Directory Status");
				OUT_FS_AFSVolSync();
				break;
			case 139: /* symlink */
				OUT_FS_AFSFid("Symlink");
			case 140: /* link */
				OUT_FS_AFSFetchStatus("Symlink Status");
			case 142: /* rmdir */
				OUT_FS_AFSFetchStatus("Directory Status");
				OUT_FS_AFSVolSync();
				break;
			case 143: /* old set lock */
			case 144: /* old extend lock */
			case 145: /* old release lock */
			case 147: /* give up callbacks */
			case 150: /* set volume status */
			case 152: /* check token */
				/* nothing returned */
				break;
			case 146: /* get statistics */
				OUT_FS_ViceStatistics();
				break;
			case 148: /* get volume info */
			case 154: /* n-get-volume-info */
				OUT_FS_VolumeInfo();
				break;
			case 149: /* get volume status */
				OUT_FS_AFSFetchVolumeStatus();
				OUT_RXString(hf_afs_fs_volname);
				OUT_RXString(hf_afs_fs_offlinemsg);
				OUT_RXString(hf_afs_fs_motd);
				break;
			case 151: /* root volume */
				OUT_RXString(hf_afs_fs_volname);
				break;
			case 153: /* get time */
				OUT_TIMESTAMP(hf_afs_fs_timestamp);
				break;
			case 155: /* bulk status */
				OUT_FS_AFSBulkStats();
				SKIP(4);
				OUT_FS_AFSCBs();
				OUT_FS_AFSVolSync();
				break;
			case 156: /* set lock */
			case 157: /* extend lock */
			case 158: /* release lock */
				OUT_FS_AFSVolSync();
				break;
			case 159: /* x-stats-version */
				OUT_UINT(hf_afs_fs_xstats_version);
				break;
			case 160: /* get xstats */
				OUT_UINT(hf_afs_fs_xstats_version);
				OUT_TIMESECS(hf_afs_fs_xstats_timestamp);
				OUT_FS_AFS_CollData();
				break;
			case 162: /* flush cps */
				OUT_UINT(hf_afs_fs_cps_spare2);
				OUT_UINT(hf_afs_fs_cps_spare3);
				break;
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_fs_errcode);
	}
}

static void
dissect_fs_request(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	/* skip the opcode if this is the first packet in the stream */
	if ( rxinfo->seq == 1 )
	{
		offset += 4;  /* skip the opcode */
	}

	switch ( opcode )
	{
		case 130: /* Fetch data */
			OUT_FS_AFSFid("Source");
			OUT_UINT(hf_afs_fs_offset);
			OUT_UINT(hf_afs_fs_length);
			break;
		case 131: /* Fetch ACL */
			OUT_FS_AFSFid("Target");
			break;
		case 132: /* Fetch Status */
			OUT_FS_AFSFid("Target");
			break;
		case 133: /* Store Data */
			if ( rxinfo->seq == 1 )
			{
				OUT_FS_AFSFid("Destination");
				OUT_FS_AFSStoreStatus("Status");
				OUT_UINT(hf_afs_fs_offset);
				OUT_UINT(hf_afs_fs_length);
				OUT_UINT(hf_afs_fs_flength);
			}
			OUT_BYTES_ALL(hf_afs_fs_data);
			break;
		case 134: /* Store ACL */
			OUT_FS_AFSFid("Target");
			offset = dissect_acl(tvb, rxinfo, tree, offset);
			break;
		case 135: /* Store Status */
			OUT_FS_AFSFid("Target");
			OUT_FS_AFSStoreStatus("Status");
			break;
		case 136: /* Remove File */
			OUT_FS_AFSFid("Remove File");
			OUT_RXString(hf_afs_fs_name);
			break;
		case 137: /* Create File */
			OUT_FS_AFSFid("Target");
			OUT_RXString(hf_afs_fs_name);
			OUT_FS_AFSStoreStatus("Status");
			break;
		case 138: /* Rename file */
			OUT_FS_AFSFid("Old");
			OUT_RXString(hf_afs_fs_oldname);
			OUT_FS_AFSFid("New");
			OUT_RXString(hf_afs_fs_newname);
			break;
		case 139: /* Symlink */
			OUT_FS_AFSFid("File");
			OUT_RXString(hf_afs_fs_symlink_name);
			OUT_RXString(hf_afs_fs_symlink_content);
			OUT_FS_AFSStoreStatus("Status");
			break;
		case 140: /* Link */
			OUT_FS_AFSFid("Link To (New File)");
			OUT_RXString(hf_afs_fs_name);
			OUT_FS_AFSFid("Link From (Old File)");
			break;
		case 141: /* Make dir */
			OUT_FS_AFSFid("Target");
			OUT_RXString(hf_afs_fs_name);
			OUT_FS_AFSStoreStatus("Status");
			break;
		case 142: /* Remove dir */
			OUT_FS_AFSFid("Target");
			OUT_RXString(hf_afs_fs_name);
			break;
		case 143: /* Old Set Lock */
			OUT_FS_AFSFid("Target");
			OUT_UINT(hf_afs_fs_vicelocktype);
			OUT_FS_AFSVolSync();
			break;
		case 144: /* Old Extend Lock */
			OUT_FS_AFSFid("Target");
			OUT_FS_AFSVolSync();
			break;
		case 145: /* Old Release Lock */
			OUT_FS_AFSFid("Target");
			OUT_FS_AFSVolSync();
			break;
		case 146: /* Get statistics */
			/* no params */
			break;
		case 147: /* Give up callbacks */
			OUT_FS_AFSCBFids();
			OUT_FS_AFSCBs();
			break;
		case 148: /* Get vol info */
			OUT_RXString(hf_afs_fs_volname);
			break;
		case 149: /* Get vol stats */
			OUT_UINT(hf_afs_fs_volid);
			break;
		case 150: /* Set vol stats */
			OUT_UINT(hf_afs_fs_volid);
			OUT_FS_AFSStoreVolumeStatus();
			OUT_RXString(hf_afs_fs_volname);
			OUT_RXString(hf_afs_fs_offlinemsg);
			OUT_RXString(hf_afs_fs_motd);
			break;
		case 151: /* get root volume */
			/* no params */
			break;
		case 152: /* check token */
			OUT_UINT(hf_afs_fs_viceid);
			OUT_FS_AFSTOKEN();
			break;
		case 153: /* get time */
			/* no params */
			break;
		case 154: /* new get vol info */
			OUT_RXString(hf_afs_fs_volname);
			break;
		case 155: /* bulk stat */
			OUT_FS_AFSCBFids();
			break;
		case 156: /* Set Lock */
			OUT_FS_AFSFid("Target");
			OUT_UINT(hf_afs_fs_vicelocktype);
			break;
		case 157: /* Extend Lock */
			OUT_FS_AFSFid("Target");
			break;
		case 158: /* Release Lock */
			OUT_FS_AFSFid("Target");
			break;
		case 159: /* xstats version */
			/* no params */
			break;
		case 160: /* get xstats */
			OUT_UINT(hf_afs_fs_xstats_clientversion);
			OUT_UINT(hf_afs_fs_xstats_collnumber);
			break;
		case 161: /* lookup */
			OUT_FS_AFSFid("Target");
			OUT_RXString(hf_afs_fs_name);
			break;
		case 162: /* flush cps */
			OUT_FS_ViceIds();
			OUT_FS_IPAddrs();
			OUT_UINT(hf_afs_fs_cps_spare1);
			break;
		case 163: /* dfs symlink */
			OUT_FS_AFSFid("Target");
			OUT_RXString(hf_afs_fs_symlink_name);
			OUT_RXString(hf_afs_fs_symlink_content);
			OUT_FS_AFSStoreStatus("Symlink Status");
			break;
		case 220: /* residencycmd */
			OUT_FS_AFSFid("Target");
			/* need residency inputs here */
			break;
		case 65536: /* inline bulk status */
			OUT_FS_AFSCBFids();
			break;
		case 65537: /* fetch-data-64 */
			OUT_FS_AFSFid("Target");
			OUT_INT64(hf_afs_fs_offset64);
			OUT_INT64(hf_afs_fs_length64);
			/* need more here */
			break;
		case 65538: /* store-data-64 */
			OUT_FS_AFSFid("Target");
			OUT_FS_AFSStoreStatus("Status");
			OUT_INT64(hf_afs_fs_offset64);
			OUT_INT64(hf_afs_fs_length64);
			OUT_INT64(hf_afs_fs_flength64);
			/* need residency inputs here */
			break;
		case 65539: /* give up all cbs */
			break;
		case 65540: /* get capabilities */
			break;
	}
}

/*
 * BOS Helpers
 */
static void
dissect_bos_reply(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 80: /* create bnode */
				/* no output */
				break;
			case 81: /* delete bnode */
				/* no output */
				break;
			case 82: /* set status */
				/* no output */
				break;
			case 83: /* get status */
				OUT_INT(hf_afs_bos_status);
				OUT_RXString(hf_afs_bos_statusdesc);
				break;
			case 84: /* enumerate instance */
				OUT_RXString(hf_afs_bos_instance);
				break;
			case 85: /* get instance info */
				OUT_RXString(hf_afs_bos_type);
				OUT_BOS_STATUS();
				break;
			case 86: /* get instance parm */
				OUT_RXString(hf_afs_bos_parm);
				break;
			case 87: /* add siperuser */
				/* no output */
				break;
			case 88: /* delete superuser */
				/* no output */
				break;
			case 89: /* list superusers */
				OUT_RXString(hf_afs_bos_user);
				break;
			case 90: /* list keys */
				OUT_UINT(hf_afs_bos_kvno);
				OUT_BOS_KEY();
				OUT_BOS_KEYINFO();
				break;
			case 91: /* add key */
				/* no output */
				break;
			case 92: /* delete key */
				/* no output */
				break;
			case 93: /* set cell name */
				/* no output */
				break;
			case 94: /* get cell name */
				OUT_RXString(hf_afs_bos_cell);
				break;
			case 95: /* get cell host */
				OUT_RXString(hf_afs_bos_host);
				break;
			case 96: /* add cell host */
				/* no output */
				break;
			case 97: /* delete cell host */
				/* no output */
				break;
			case 98: /* set tstatus */
				/* no output */
				break;
			case 99: /* shutdown all */
				/* no output */
				break;
			case 100: /* restart all */
				/* no output */
				break;
			case 101: /* startup all */
				/* no output */
				break;
			case 102: /* set noauth flag */
				/* no output */
				break;
			case 103: /* rebozo */
				/* no output */
				break;
			case 104: /* restart */
				/* no output */
				break;
			case 105: /* install */
				/* no output */
				break;
			case 106: /* uninstall */
				/* no output */
				break;
			case 107: /* get dates */
				OUT_TIMESECS(hf_afs_bos_newtime);
				OUT_TIMESECS(hf_afs_bos_baktime);
				OUT_TIMESECS(hf_afs_bos_oldtime);
				break;
			case 108: /* exec */
				/* no output */
				break;
			case 109: /* prune */
				/* no output */
				break;
			case 110: /* set restart time */
				/* no output */
				break;
			case 111: /* get restart time */
				OUT_BOS_TIME();
				break;
			case 112: /* get log */
				/* need to make this dump a big string somehow */
				OUT_BYTES_ALL(hf_afs_bos_data);
				break;
			case 113: /* wait all */
				/* no output */
				break;
			case 114: /* get instance strings */
				OUT_RXString(hf_afs_bos_error);
				OUT_RXString(hf_afs_bos_spare1);
				OUT_RXString(hf_afs_bos_spare2);
				OUT_RXString(hf_afs_bos_spare3);
				break;
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_bos_errcode);
	}
}

static void
dissect_bos_request(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset, int opcode)
{
	offset += 4;  /* skip the opcode */

	switch ( opcode )
	{
		case 80: /* create b node */
			OUT_RXString(hf_afs_bos_type);
			OUT_RXString(hf_afs_bos_instance);
			OUT_RXString(hf_afs_bos_parm);
			OUT_RXString(hf_afs_bos_parm);
			OUT_RXString(hf_afs_bos_parm);
			OUT_RXString(hf_afs_bos_parm);
			OUT_RXString(hf_afs_bos_parm);
			OUT_RXString(hf_afs_bos_parm);
			break;
		case 81: /* delete b node */
			OUT_RXString(hf_afs_bos_instance);
			break;
		case 82: /* set status */
			OUT_RXString(hf_afs_bos_instance);
			OUT_INT(hf_afs_bos_status);
			break;
		case 83: /* get status */
			OUT_RXString(hf_afs_bos_instance);
			break;
		case 84: /* enumerate instance */
			OUT_UINT(hf_afs_bos_num);
			break;
		case 85: /* get instance info */
			OUT_RXString(hf_afs_bos_instance);
			break;
		case 86: /* get instance parm */
			OUT_RXString(hf_afs_bos_instance);
			OUT_UINT(hf_afs_bos_num);
			break;
		case 87: /* add super user */
			OUT_RXString(hf_afs_bos_user);
			break;
		case 88: /* delete super user */
			OUT_RXString(hf_afs_bos_user);
			break;
		case 89: /* list super users */
			OUT_UINT(hf_afs_bos_num);
			break;
		case 90: /* list keys */
			OUT_UINT(hf_afs_bos_num);
			break;
		case 91: /* add key */
			OUT_UINT(hf_afs_bos_num);
			OUT_BOS_KEY();
			break;
		case 92: /* delete key */
			OUT_UINT(hf_afs_bos_num);
			break;
		case 93: /* set cell name */
			OUT_RXString(hf_afs_bos_content);
			break;
		case 95: /* set cell host */
			OUT_UINT(hf_afs_bos_num);
			break;
		case 96: /* add cell host */
			OUT_RXString(hf_afs_bos_content);
			break;
		case 97: /* delete cell host */
			OUT_RXString(hf_afs_bos_content);
			break;
		case 98: /* set t status */
			OUT_RXString(hf_afs_bos_content);
			OUT_INT(hf_afs_bos_status);
			break;
		case 99: /* shutdown all */
			/* no params */
			break;
		case 100: /* restart all */
			/* no params */
			break;
		case 101: /* startup all */
			/* no params */
			break;
		case 102: /* set no-auth flag */
			OUT_UINT(hf_afs_bos_flags);
			break;
		case 103: /* re-bozo? */
			/* no params */
			break;
		case 104: /* restart */
			OUT_RXString(hf_afs_bos_instance);
			break;
		case 105: /* install */
			OUT_RXString(hf_afs_bos_path);
			OUT_UINT(hf_afs_bos_size);
			OUT_UINT(hf_afs_bos_flags);
			OUT_UINT(hf_afs_bos_date);
			break;
		case 106: /* uninstall */
			OUT_RXString(hf_afs_bos_path);
			break;
		case 107: /* get dates */
			OUT_RXString(hf_afs_bos_path);
			break;
		case 108: /* exec */
			OUT_RXString(hf_afs_bos_cmd);
			break;
		case 109: /* prune */
			OUT_UINT(hf_afs_bos_flags);
			break;
		case 110: /* set restart time */
			OUT_UINT(hf_afs_bos_num);
			OUT_BOS_TIME();
			break;
		case 111: /* get restart time */
			OUT_UINT(hf_afs_bos_num);
			break;
		case 112: /* get log */
			OUT_RXString(hf_afs_bos_file);
			break;
		case 113: /* wait all */
			/* no params */
			break;
		case 114: /* get instance strings */
			OUT_RXString(hf_afs_bos_content);
			break;
	}
}

/*
 * VOL Helpers
 */
static void
dissect_vol_reply(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 121:
				/* should loop here maybe */
				OUT_UINT(hf_afs_vol_count);
				OUT_RXStringV(hf_afs_vol_name, 32); /* not sure on  */
				break;
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_vol_errcode);
	}
}

static void
dissect_vol_request(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset, int opcode)
{
	offset += 4;  /* skip the opcode */

	switch ( opcode )
	{
		case 121: /* list one vol */
			OUT_UINT(hf_afs_vol_count);
			OUT_UINT(hf_afs_vol_id);
			break;
	}
}

/*
 * KAUTH Helpers
 */
static void
dissect_kauth_reply(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_kauth_errcode);
	}
}

static void
dissect_kauth_request(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset, int opcode)
{
	offset += 4;  /* skip the opcode */

	switch ( opcode )
	{
		case 1: /* authenticate old */
		case 21: /* authenticate */
		case 22: /* authenticate v2 */
		case 2: /* change pw */
		case 5: /* set fields */
		case 6: /* create user */
		case 7: /* delete user */
		case 8: /* get entry */
		case 14: /* unlock */
		case 15: /* lock status */
			OUT_RXString(hf_afs_kauth_princ);
			OUT_RXString(hf_afs_kauth_realm);
			OUT_BYTES_ALL(hf_afs_kauth_data);
			break;
		case 3: /* getticket-old */
		case 23: /* getticket */
			OUT_KAUTH_GetTicket();
			break;
		case 4: /* set pass */
			OUT_RXString(hf_afs_kauth_princ);
			OUT_RXString(hf_afs_kauth_realm);
			OUT_UINT(hf_afs_kauth_kvno);
			break;
		case 12: /* get pass */
			OUT_RXString(hf_afs_kauth_name);
			break;
	}
}

/*
 * CB Helpers
 */
static void
dissect_cb_reply(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_cb_errcode);
	}
}

static void
dissect_cb_request(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset, int opcode)
{
	offset += 4;  /* skip the opcode */

	switch ( opcode )
	{
		case 204: /* callback */
		{
			unsigned int i,j;

			j = tvb_get_ntohl(tvb, offset);
			offset += 4;

			for (i=0; i<j; i++)
			{
				OUT_CB_AFSFid("Target");
			}

			j = tvb_get_ntohl(tvb, offset);
			offset += 4;
			for (i=0; i<j; i++)
			{
				OUT_CB_AFSCallBack();
			}
		}
	}
}

/*
 * PROT Helpers
 */
static void
dissect_prot_reply(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 504: /* name to id */
				{
					unsigned int i, j;

					j = tvb_get_ntohl(tvb, offset);
					OUT_UINT(hf_afs_prot_count);

					for (i=0; i<j; i++)
					{
						OUT_UINT(hf_afs_prot_id);
					}
				}
				break;
			case 505: /* id to name */
				{
					unsigned int i, j;

					j = tvb_get_ntohl(tvb, offset);
					OUT_UINT(hf_afs_prot_count);

					for (i=0; i<j; i++)
					{
						OUT_RXStringV(hf_afs_prot_name, PRNAMEMAX);
					}
				}
				break;
			case 508: /* get cps */
			case 514: /* list elements */
			case 517: /* list owned */
			case 518: /* get cps2 */
			case 519: /* get host cps */
				{
					unsigned int i, j;

					j = tvb_get_ntohl(tvb, offset);
					OUT_UINT(hf_afs_prot_count);

					for (i=0; i<j; i++)
					{
						OUT_UINT(hf_afs_prot_id);
					}
				}
				break;
			case 510: /* list max */
				OUT_UINT(hf_afs_prot_maxuid);
				OUT_UINT(hf_afs_prot_maxgid);
				break;
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_prot_errcode);
	}
}

static void
dissect_prot_request(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset, int opcode)
{
	offset += 4;  /* skip the opcode */

	switch ( opcode )
	{
		case 500: /* new user */
			OUT_RXString(hf_afs_prot_name);
			OUT_UINT(hf_afs_prot_id);
			OUT_UINT(hf_afs_prot_oldid);
			break;
		case 501: /* where is it */
		case 506: /* delete */
		case 508: /* get cps */
		case 512: /* list entry */
		case 514: /* list elements */
		case 517: /* list owned */
		case 519: /* get host cps */
			OUT_UINT(hf_afs_prot_id);
			break;
		case 502: /* dump entry */
			OUT_UINT(hf_afs_prot_pos);
			break;
		case 503: /* add to group */
		case 507: /* remove from group */
		case 515: /* is a member of? */
			OUT_UINT(hf_afs_prot_uid);
			OUT_UINT(hf_afs_prot_gid);
			break;
		case 504: /* name to id */
			{
				unsigned int i, j;

				j = tvb_get_ntohl(tvb, offset);
				OUT_UINT(hf_afs_prot_count);

				for (i=0; i<j; i++)
				{
					OUT_RXStringV(hf_afs_prot_name,PRNAMEMAX);
				}
			}
			break;
		case 505: /* id to name */
			{
				unsigned int i, j;

				j = tvb_get_ntohl(tvb, offset);
				OUT_UINT(hf_afs_prot_count);

				for (i=0; i<j; i++)
				{
					OUT_UINT(hf_afs_prot_id);
				}
			}
			break;
		case 509: /* new entry */
			OUT_RXString(hf_afs_prot_name);
			OUT_UINT(hf_afs_prot_flag);
			OUT_UINT(hf_afs_prot_oldid);
			break;
		case 511: /* set max */
			OUT_UINT(hf_afs_prot_id);
			OUT_UINT(hf_afs_prot_flag);
			break;
		case 513: /* change entry */
			OUT_UINT(hf_afs_prot_id);
			OUT_RXString(hf_afs_prot_name);
			OUT_UINT(hf_afs_prot_oldid);
			OUT_UINT(hf_afs_prot_newid);
			break;
		case 520: /* update entry */
			OUT_UINT(hf_afs_prot_id);
			OUT_RXString(hf_afs_prot_name);
			break;
	}
}

/*
 * VLDB Helpers
 */
static void
dissect_vldb_reply(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 510: /* list entry */
				OUT_UINT(hf_afs_vldb_count);
				OUT_UINT(hf_afs_vldb_nextindex);
				break;
			case 503: /* get entry by id */
			case 504: /* get entry by name */
				{
					int nservers,i,j;
					OUT_RXStringV(hf_afs_vldb_name, VLNAMEMAX);
					SKIP(4);
					nservers = tvb_get_ntohl(tvb, offset);
					OUT_UINT(hf_afs_vldb_numservers);
					for (i=0; i<8; i++)
					{
						if ( i<nservers )
						{
							OUT_IP(hf_afs_vldb_server);
						}
						else
						{
							SKIP(4);
						}
					}
					for (i=0; i<8; i++)
					{
						char *part;
						part=ep_alloc(8);
						j = tvb_get_ntohl(tvb, offset);
						g_snprintf(part, 8, "/vicepa");
						if ( i<nservers && j<=25 )
						{
							part[6] = 'a' + (char) j;
							proto_tree_add_string(tree, hf_afs_vldb_partition, tvb,
								offset, 4, part);
						}
						SKIP(4);
					}
					SKIP(8 * sizeof(guint32));
					OUT_UINT(hf_afs_vldb_rwvol);
					OUT_UINT(hf_afs_vldb_rovol);
					OUT_UINT(hf_afs_vldb_bkvol);
					OUT_UINT(hf_afs_vldb_clonevol);
					OUT_VLDB_Flags();
				}
				break;
			case 505: /* get new volume id */
				OUT_UINT(hf_afs_vldb_id);
				break;
			case 521: /* list entry */
			case 529: /* list entry U */
				OUT_UINT(hf_afs_vldb_count);
				OUT_UINT(hf_afs_vldb_nextindex);
				break;
			case 518: /* get entry by id n */
			case 519: /* get entry by name N */
				{
					int nservers,i,j;
					OUT_RXStringV(hf_afs_vldb_name, VLNAMEMAX);
					nservers = tvb_get_ntohl(tvb, offset);
					OUT_UINT(hf_afs_vldb_numservers);
					for (i=0; i<13; i++)
					{
						if ( i<nservers )
						{
							OUT_IP(hf_afs_vldb_server);
						}
						else
						{
							SKIP(4);
						}
					}
					for (i=0; i<13; i++)
					{
						char *part;
						part=ep_alloc(8);
						j = tvb_get_ntohl(tvb, offset);
						g_snprintf(part, 8, "/vicepa");
						if ( i<nservers && j<=25 )
						{
							part[6] = 'a' + (char) j;
							proto_tree_add_string(tree, hf_afs_vldb_partition, tvb,
								offset, 4, part);
						}
						SKIP(4);
					}
					SKIP(13 * sizeof(guint32));
					OUT_UINT(hf_afs_vldb_rwvol);
					OUT_UINT(hf_afs_vldb_rovol);
					OUT_UINT(hf_afs_vldb_bkvol);
				}
				break;
			case 526: /* get entry by id u */
			case 527: /* get entry by name u */
				{
					int nservers,i,j;
					OUT_RXStringV(hf_afs_vldb_name, VLNAMEMAX);
					nservers = tvb_get_ntohl(tvb, offset);
					OUT_UINT(hf_afs_vldb_numservers);
					for (i=0; i<13; i++)
					{
						if ( i<nservers )
						{
							OUT_UUID(hf_afs_vldb_serveruuid);
						}
						else
						{
							SKIP_UUID();
						}
					}
					for (i=0; i<13; i++)
					{
						if ( i<nservers )
						{
							OUT_UINT(hf_afs_vldb_serveruniq);
						}
						else
						{
							SKIP(sizeof(guint32));
						}
					}
					for (i=0; i<13; i++)
					{
						char *part;
						part=ep_alloc(8);
						j = tvb_get_ntohl(tvb, offset);
						g_snprintf(part, 8, "/vicepa");
						if ( i<nservers && j<=25 )
						{
							part[6] = 'a' + (char) j;
							proto_tree_add_string(tree, hf_afs_vldb_partition, tvb,
								offset, 4, part);
						}
						SKIP(4);
					}
					for (i=0; i<13; i++)
					{
						if ( i<nservers )
						{
							OUT_UINT(hf_afs_vldb_serverflags);
						}
						else
						{
							SKIP(sizeof(guint32));
						}
					}
					OUT_UINT(hf_afs_vldb_rwvol);
					OUT_UINT(hf_afs_vldb_rovol);
					OUT_UINT(hf_afs_vldb_bkvol);
					OUT_UINT(hf_afs_vldb_clonevol);
					OUT_UINT(hf_afs_vldb_flags);
					OUT_UINT(hf_afs_vldb_spare1);
					OUT_UINT(hf_afs_vldb_spare2);
					OUT_UINT(hf_afs_vldb_spare3);
					OUT_UINT(hf_afs_vldb_spare4);
					OUT_UINT(hf_afs_vldb_spare5);
					OUT_UINT(hf_afs_vldb_spare6);
					OUT_UINT(hf_afs_vldb_spare7);
					OUT_UINT(hf_afs_vldb_spare8);
					OUT_UINT(hf_afs_vldb_spare9);
				}
				break;
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_vldb_errcode);
	}
}

static void
dissect_vldb_request(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset, int opcode)
{
	offset += 4;  /* skip the opcode */

	switch ( opcode )
	{
		case 501: /* create new volume */
		case 517: /* create entry N */
			OUT_RXStringV(hf_afs_vldb_name, VLNAMEMAX);
			break;
		case 502: /* delete entry */
		case 503: /* get entry by id */
		case 507: /* update entry */
		case 508: /* set lock */
		case 509: /* release lock */
		case 518: /* get entry by id */
			OUT_UINT(hf_afs_vldb_id);
			OUT_UINT(hf_afs_vldb_type);
			break;
		case 504: /* get entry by name */
		case 519: /* get entry by name N */
		case 524: /* update entry by name */
		case 527: /* get entry by name U */
			OUT_RXString(hf_afs_vldb_name);
			break;
		case 505: /* get new vol id */
			OUT_UINT(hf_afs_vldb_bump);
			break;
		case 506: /* replace entry */
		case 520: /* replace entry N */
			OUT_UINT(hf_afs_vldb_id);
			OUT_UINT(hf_afs_vldb_type);
			OUT_RXStringV(hf_afs_vldb_name, VLNAMEMAX);
			break;
		case 510: /* list entry */
		case 521: /* list entry N */
			OUT_UINT(hf_afs_vldb_index);
			break;
		case 532: /* regaddr */
			OUT_UUID(hf_afs_vldb_serveruuid);
			OUT_UINT(hf_afs_vldb_spare1);
			OUT_VLDB_BulkAddr();
			break;
	}
}

/*
 * UBIK Helpers
 */
static void
dissect_ubik_reply(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset, int opcode)
{
	switch ( opcode )
	{
		case 10000: /* vote-beacon */
			break;
		case 10001: /* vote-debug-old */
			OUT_UBIK_DebugOld();
			break;
		case 10002: /* vote-sdebug-old */
			OUT_UBIK_SDebugOld();
			break;
		case 10003: /* vote-get syncsite */
			break;
		case 10004: /* vote-debug */
			OUT_UBIK_DebugOld();
			OUT_UBIK_InterfaceAddrs();
			break;
		case 10005: /* vote-sdebug */
			OUT_UBIK_SDebugOld();
			OUT_UBIK_InterfaceAddrs();
			break;
		case 10006: /* vote-xdebug */
			OUT_UBIK_DebugOld();
			OUT_UBIK_InterfaceAddrs();
			OUT_UINT(hf_afs_ubik_isclone);
			break;
		case 10007: /* vote-xsdebug */
			OUT_UBIK_SDebugOld();
			OUT_UBIK_InterfaceAddrs();
			OUT_UINT(hf_afs_ubik_isclone);
			break;
		case 20000: /* disk-begin */
			break;
		case 20004: /* get version */
			OUT_UBIKVERSION("DB Version");
			break;
		case 20010: /* disk-probe */
			break;
		case 20012: /* disk-interfaceaddr */
			OUT_UBIK_InterfaceAddrs();
			break;
	}
}

static void
dissect_ubik_request(tvbuff_t *tvb, struct rxinfo *rxinfo _U_, proto_tree *tree, int offset, int opcode)
{
	offset += 4;  /* skip the opcode */

	switch ( opcode )
	{
		case 10000: /* vote-beacon */
			OUT_UINT(hf_afs_ubik_state);
			OUT_TIMESECS(hf_afs_ubik_votestart);
			OUT_UBIKVERSION("DB Version");
			OUT_UBIKVERSION("TID");
			break;
		case 10001: /* vote-debug-old */
			break;
		case 10002: /* vote-sdebug-old */
			OUT_UINT(hf_afs_ubik_site);
			break;
		case 10003: /* vote-get sync site */
			OUT_IP(hf_afs_ubik_site);
			break;
		case 10004: /* vote-debug */
		case 10005: /* vote-sdebug */
			OUT_IP(hf_afs_ubik_site);
			break;
		case 20000: /* disk-begin */
			OUT_UBIKVERSION("TID");
			break;
		case 20001: /* disk-commit */
			OUT_UBIKVERSION("TID");
			break;
		case 20002: /* disk-lock */
			OUT_UBIKVERSION("TID");
			OUT_UINT(hf_afs_ubik_file);
			OUT_UINT(hf_afs_ubik_pos);
			OUT_UINT(hf_afs_ubik_length);
			OUT_UINT(hf_afs_ubik_locktype);
			break;
		case 20003: /* disk-write */
			OUT_UBIKVERSION("TID");
			OUT_UINT(hf_afs_ubik_file);
			OUT_UINT(hf_afs_ubik_pos);
			break;
		case 20004: /* disk-get version */
			break;
		case 20005: /* disk-get file */
			OUT_UINT(hf_afs_ubik_file);
			break;
		case 20006: /* disk-send file */
			OUT_UINT(hf_afs_ubik_file);
			OUT_UINT(hf_afs_ubik_length);
			OUT_UBIKVERSION("DB Version");
			break;
		case 20007: /* disk-abort */
		case 20008: /* disk-release locks */
		case 20010: /* disk-probe */
			break;
		case 20009: /* disk-truncate */
			OUT_UBIKVERSION("TID");
			OUT_UINT(hf_afs_ubik_file);
			OUT_UINT(hf_afs_ubik_length);
			break;
		case 20011: /* disk-writev */
			OUT_UBIKVERSION("TID");
			break;
		case 20012: /* disk-interfaceaddr */
			OUT_UBIK_InterfaceAddrs();
			break;
		case 20013: /* disk-set version */
			OUT_UBIKVERSION("TID");
			OUT_UBIKVERSION("Old DB Version");
			OUT_UBIKVERSION("New DB Version");
			break;
	}
}

/*
 * BACKUP Helpers
 */
static void
dissect_backup_reply(tvbuff_t *tvb, struct rxinfo *rxinfo, proto_tree *tree, int offset, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		OUT_UINT(hf_afs_backup_errcode);
	}
}

static void
dissect_backup_request(tvbuff_t *tvb _U_, struct rxinfo *rxinfo _U_, proto_tree *tree _U_, int offset, int opcode)
{
	offset += 4;  /* skip the opcode */

	switch ( opcode )
	{
	}
}

/*
 * Registration code for registering the protocol and fields
 */

void
proto_register_afs(void)
{
	static hf_register_info hf[] = {
	{ &hf_afs_fs, {	"File Server", "afs.fs",
		FT_BOOLEAN, BASE_NONE, 0, 0, "File Server", HFILL }},
	{ &hf_afs_cb, {	"Callback", "afs.cb",
		FT_BOOLEAN, BASE_NONE, 0, 0, "Callback", HFILL }},
	{ &hf_afs_prot, { "Protection", "afs.prot",
		FT_BOOLEAN, BASE_NONE, 0, 0, "Protection Server", HFILL }},
	{ &hf_afs_vldb, { "VLDB", "afs.vldb",
		FT_BOOLEAN, BASE_NONE, 0, 0, "Volume Location Database Server", HFILL }},
	{ &hf_afs_kauth, { "KAuth", "afs.kauth",
		FT_BOOLEAN, BASE_NONE, 0, 0, "Kerberos Auth Server", HFILL }},
	{ &hf_afs_vol, { "Volume Server", "afs.vol",
		FT_BOOLEAN, BASE_NONE, 0, 0, "Volume Server", HFILL }},
	{ &hf_afs_error, { "Error", "afs.error",
		FT_BOOLEAN, BASE_NONE, 0, 0, "Error", HFILL }},
	{ &hf_afs_bos, { "BOS", "afs.bos",
		FT_BOOLEAN, BASE_NONE, 0, 0, "Basic Oversee Server", HFILL }},
	{ &hf_afs_update, { "Update", "afs.update",
		FT_BOOLEAN, BASE_NONE, 0, 0, "Update Server", HFILL }},
	{ &hf_afs_rmtsys, { "Rmtsys", "afs.rmtsys",
		FT_BOOLEAN, BASE_NONE, 0, 0, "Rmtsys", HFILL }},
	{ &hf_afs_ubik, { "Ubik", "afs.ubik",
		FT_BOOLEAN, BASE_NONE, 0, 0, "Ubik", HFILL }},
	{ &hf_afs_backup, { "Backup", "afs.backup",
		FT_BOOLEAN, BASE_NONE, 0, 0, "Backup Server", HFILL }},

	{ &hf_afs_fs_opcode, { "Operation", "afs.fs.opcode",
		FT_UINT32, BASE_DEC,
	VALS(fs_req), 0, "Operation", HFILL }},
	{ &hf_afs_cb_opcode, { "Operation", "afs.cb.opcode",
		FT_UINT32, BASE_DEC,
	VALS(cb_req), 0, "Operation", HFILL }},
	{ &hf_afs_prot_opcode, { "Operation", "afs.prot.opcode",
		FT_UINT32, BASE_DEC,
	VALS(prot_req), 0, "Operation", HFILL }},
	{ &hf_afs_vldb_opcode, { "Operation", "afs.vldb.opcode",
		FT_UINT32, BASE_DEC,
	VALS(vldb_req), 0, "Operation", HFILL }},
	{ &hf_afs_kauth_opcode, { "Operation", "afs.kauth.opcode",
		FT_UINT32, BASE_DEC,
	VALS(kauth_req), 0, "Operation", HFILL }},
	{ &hf_afs_vol_opcode, { "Operation", "afs.vol.opcode",
		FT_UINT32, BASE_DEC,
	VALS(vol_req), 0, "Operation", HFILL }},
	{ &hf_afs_bos_opcode, { "Operation", "afs.bos.opcode",
		FT_UINT32, BASE_DEC,
	VALS(bos_req), 0, "Operation", HFILL }},
	{ &hf_afs_update_opcode, { "Operation", "afs.update.opcode",
		FT_UINT32, BASE_DEC,
	VALS(update_req), 0, "Operation", HFILL }},
	{ &hf_afs_rmtsys_opcode, { "Operation", "afs.rmtsys.opcode",
		FT_UINT32, BASE_DEC,
	VALS(rmtsys_req), 0, "Operation", HFILL }},
	{ &hf_afs_error_opcode, { "Operation", "afs.error.opcode",
		FT_UINT32, BASE_DEC,
	0, 0, "Operation", HFILL }},
	{ &hf_afs_backup_opcode, {
	"Operation", "afs.backup.opcode",
		FT_UINT32, BASE_DEC,
	VALS(backup_req), 0, "Operation", HFILL }},
	{ &hf_afs_ubik_opcode, {
	"Operation", "afs.ubik.opcode",
		FT_UINT32, BASE_DEC,
	VALS(ubik_req), 0, "Operation", HFILL }},


/* File Server Fields */
	{ &hf_afs_fs_fid_volume, { "FileID (Volume)", "afs.fs.fid.volume",
		FT_UINT32, BASE_DEC,
	0, 0, "File ID (Volume)", HFILL }},
	{ &hf_afs_fs_fid_vnode, { "FileID (VNode)", "afs.fs.fid.vnode",
		FT_UINT32, BASE_DEC,
	0, 0, "File ID (VNode)", HFILL }},
	{ &hf_afs_fs_fid_uniqifier, { "FileID (Uniqifier)", "afs.fs.fid.uniq",
		FT_UINT32, BASE_DEC,
	0, 0, "File ID (Uniqifier)", HFILL }},
	{ &hf_afs_fs_offset, { "Offset", "afs.fs.offset",
		FT_UINT32, BASE_DEC,
	0, 0, "Offset", HFILL }},
	{ &hf_afs_fs_length, { "Length", "afs.fs.length",
		FT_UINT32, BASE_DEC, 0, 0, "Length", HFILL }},
	{ &hf_afs_fs_flength, { "FLength", "afs.fs.flength",
		FT_UINT32, BASE_DEC, 0, 0, "FLength", HFILL }},
	{ &hf_afs_fs_offset64, { "Offset64", "afs.fs.offset64",
		FT_UINT64, BASE_DEC,
	0, 0, "Offset64", HFILL }},
	{ &hf_afs_fs_length64, { "Length64", "afs.fs.length64",
		FT_UINT64, BASE_DEC, 0, 0, "Length64", HFILL }},
	{ &hf_afs_fs_flength64, { "FLength64", "afs.fs.flength64",
		FT_UINT64, BASE_DEC, 0, 0, "FLength64", HFILL }},
	{ &hf_afs_fs_errcode, { "Error Code", "afs.fs.errcode",
		FT_UINT32, BASE_DEC, VALS(afs_errors), 0, "Error Code", HFILL }},
	{ &hf_afs_fs_data, { "Data", "afs.fs.data",
		FT_BYTES, BASE_HEX, 0, 0, "Data", HFILL }},
	{ &hf_afs_fs_token, { "Token", "afs.fs.token",
		FT_BYTES, BASE_HEX, 0, 0, "Token", HFILL }},
	{ &hf_afs_fs_oldname, { "Old Name", "afs.fs.oldname",
		FT_STRING, BASE_HEX, 0, 0, "Old Name", HFILL }},
	{ &hf_afs_fs_newname, { "New Name", "afs.fs.newname",
		FT_STRING, BASE_HEX, 0, 0, "New Name", HFILL }},
	{ &hf_afs_fs_name, { "Name", "afs.fs.name",
		FT_STRING, BASE_HEX, 0, 0, "Name", HFILL }},
	{ &hf_afs_fs_symlink_name, { "Symlink Name", "afs.fs.symlink.name",
		FT_STRING, BASE_HEX, 0, 0, "Symlink Name", HFILL }},
	{ &hf_afs_fs_symlink_content, { "Symlink Content", "afs.fs.symlink.content",
		FT_STRING, BASE_HEX, 0, 0, "Symlink Content", HFILL }},
	{ &hf_afs_fs_volid, { "Volume ID", "afs.fs.volid",
		FT_UINT32, BASE_DEC, 0, 0, "Volume ID", HFILL }},
	{ &hf_afs_fs_volname, { "Volume Name", "afs.fs.volname",
		FT_STRING, BASE_HEX, 0, 0, "Volume Name", HFILL }},
	{ &hf_afs_fs_timestamp, { "Timestamp", "afs.fs.timestamp",
		FT_ABSOLUTE_TIME, BASE_NONE, 0, 0, "Timestamp", HFILL }},
	{ &hf_afs_fs_offlinemsg, { "Offline Message", "afs.fs.offlinemsg",
		FT_STRING, BASE_HEX, 0, 0, "Volume Name", HFILL }},
	{ &hf_afs_fs_motd, { "Message of the Day", "afs.fs.motd",
		FT_STRING, BASE_HEX, 0, 0, "Message of the Day", HFILL }},
	{ &hf_afs_fs_xstats_version, { "XStats Version", "afs.fs.xstats.version",
		FT_UINT32, BASE_DEC, 0, 0, "XStats Version", HFILL }},
	{ &hf_afs_fs_xstats_clientversion, { "Client Version", "afs.fs.xstats.clientversion",
		FT_UINT32, BASE_DEC, 0, 0, "Client Version", HFILL }},
	{ &hf_afs_fs_xstats_collnumber, { "Collection Number", "afs.fs.xstats.collnumber",
		FT_UINT32, BASE_DEC, VALS(xstat_collections), 0, "Collection Number", HFILL }},
	{ &hf_afs_fs_xstats_timestamp, { "XStats Timestamp", "afs.fs.xstats.timestamp",
		FT_UINT32, BASE_DEC, 0, 0, "XStats Timestamp", HFILL }},
	{ &hf_afs_fs_cps_spare1, { "CPS Spare1", "afs.fs.cps.spare1",
		FT_UINT32, BASE_DEC, 0, 0, "CPS Spare1", HFILL }},
	{ &hf_afs_fs_cps_spare2, { "CPS Spare2", "afs.fs.cps.spare2",
		FT_UINT32, BASE_DEC, 0, 0, "CPS Spare2", HFILL }},
	{ &hf_afs_fs_cps_spare3, { "CPS Spare3", "afs.fs.cps.spare3",
		FT_UINT32, BASE_DEC, 0, 0, "CPS Spare3", HFILL }},
	{ &hf_afs_fs_vicelocktype, { "Vice Lock Type", "afs.fs.vicelocktype",
		FT_UINT32, BASE_DEC, VALS(vice_lock_types), 0, "Vice Lock Type", HFILL }},
/* XXX - is this an IP address? */
	{ &hf_afs_fs_viceid, { "Vice ID", "afs.fs.viceid",
		FT_UINT32, BASE_DEC, 0, 0, "Vice ID", HFILL }},

	{ &hf_afs_fs_status_mask, { "Mask", "afs.fs.status.mask",
		FT_UINT32, BASE_HEX, 0, 0, "Mask", HFILL }},
	{ &hf_afs_fs_status_mask_setmodtime, { "Set Modification Time", "afs.fs.status.mask.setmodtime",
		FT_BOOLEAN, 32, 0, 0x00000001, "Set Modification Time", HFILL }},
	{ &hf_afs_fs_status_mask_setowner, { "Set Owner", "afs.fs.status.mask.setowner",
		FT_BOOLEAN, 32, 0, 0x00000002, "Set Owner", HFILL }},
	{ &hf_afs_fs_status_mask_setgroup, { "Set Group", "afs.fs.status.mask.setgroup",
		FT_BOOLEAN, 32, 0, 0x00000004, "Set Group", HFILL }},
	{ &hf_afs_fs_status_mask_setmode, { "Set Mode", "afs.fs.status.mask.setmode",
		FT_BOOLEAN, 32, 0, 0x00000008, "Set Mode", HFILL }},
	{ &hf_afs_fs_status_mask_setsegsize, { "Set Segment Size", "afs.fs.status.mask.setsegsize",
		FT_BOOLEAN, 32, 0, 0x00000010, "Set Segment Size", HFILL }},
	{ &hf_afs_fs_status_mask_fsync, { "FSync", "afs.fs.status.mask.fsync",
		FT_BOOLEAN, 32, 0, 0x00000400, "FSync", HFILL }},

	{ &hf_afs_fs_status_clientmodtime, { "Client Modification Time", "afs.fs.status.clientmodtime",
		FT_ABSOLUTE_TIME, BASE_NONE, 0, 0, "Client Modification Time", HFILL }},
	{ &hf_afs_fs_status_servermodtime, { "Server Modification Time", "afs.fs.status.servermodtime",
		FT_ABSOLUTE_TIME, BASE_NONE, 0, 0, "Server Modification Time", HFILL }},
	{ &hf_afs_fs_status_owner, { "Owner", "afs.fs.status.owner",
		FT_UINT32, BASE_DEC, 0, 0, "Owner", HFILL }},
	{ &hf_afs_fs_status_group, { "Group", "afs.fs.status.group",
		FT_UINT32, BASE_DEC, 0, 0, "Group", HFILL }},
	{ &hf_afs_fs_status_mode, { "Unix Mode", "afs.fs.status.mode",
		FT_UINT32, BASE_OCT, 0, 0, "Unix Mode", HFILL }},
	{ &hf_afs_fs_status_segsize, { "Segment Size", "afs.fs.status.segsize",
		FT_UINT32, BASE_DEC, 0, 0, "Segment Size", HFILL }},
	{ &hf_afs_fs_status_interfaceversion, { "Interface Version", "afs.fs.status.interfaceversion",
		FT_UINT32, BASE_DEC, 0, 0, "Interface Version", HFILL }},
	{ &hf_afs_fs_status_filetype, { "File Type", "afs.fs.status.filetype",
		FT_UINT32, BASE_DEC, 0, 0, "File Type", HFILL }},
	{ &hf_afs_fs_status_author, { "Author", "afs.fs.status.author",
		FT_UINT32, BASE_DEC, 0, 0, "Author", HFILL }},
	{ &hf_afs_fs_status_calleraccess, { "Caller Access", "afs.fs.status.calleraccess",
		FT_UINT32, BASE_DEC, 0, 0, "Caller Access", HFILL }},
	{ &hf_afs_fs_status_anonymousaccess, { "Anonymous Access", "afs.fs.status.anonymousaccess",
		FT_UINT32, BASE_DEC, 0, 0, "Anonymous Access", HFILL }},
	{ &hf_afs_fs_status_parentvnode, { "Parent VNode", "afs.fs.status.parentvnode",
		FT_UINT32, BASE_DEC, 0, 0, "Parent VNode", HFILL }},
	{ &hf_afs_fs_status_parentunique, { "Parent Unique", "afs.fs.status.parentunique",
		FT_UINT32, BASE_DEC, 0, 0, "Parent Unique", HFILL }},
	{ &hf_afs_fs_status_dataversion, { "Data Version", "afs.fs.status.dataversion",
		FT_UINT32, BASE_DEC, 0, 0, "Data Version", HFILL }},
	{ &hf_afs_fs_status_dataversionhigh, { "Data Version (High)", "afs.fs.status.dataversionhigh",
		FT_UINT32, BASE_DEC, 0, 0, "Data Version (High)", HFILL }},
	{ &hf_afs_fs_status_linkcount, { "Link Count", "afs.fs.status.linkcount",
		FT_UINT32, BASE_DEC, 0, 0, "Link Count", HFILL }},
	{ &hf_afs_fs_status_spare2, { "Spare 2", "afs.fs.status.spare2",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 2", HFILL }},
	{ &hf_afs_fs_status_spare3, { "Spare 3", "afs.fs.status.spare3",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 3", HFILL }},
	{ &hf_afs_fs_status_spare4, { "Spare 4", "afs.fs.status.spare4",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 4", HFILL }},
	{ &hf_afs_fs_status_synccounter, { "Sync Counter", "afs.fs.status.synccounter",
		FT_UINT32, BASE_DEC, 0, 0, "Sync Counter", HFILL }},
	{ &hf_afs_fs_status_length, { "Length", "afs.fs.status.length",
		FT_UINT32, BASE_DEC, 0, 0, "Length", HFILL }},


	{ &hf_afs_fs_volsync_spare1, { "Volume Creation Timestamp", "afs.fs.volsync.spare1",
		FT_ABSOLUTE_TIME, BASE_NONE, 0, 0, "Volume Creation Timestamp", HFILL }},
	{ &hf_afs_fs_volsync_spare2, { "Spare 2", "afs.fs.volsync.spare2",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 2", HFILL }},
	{ &hf_afs_fs_volsync_spare3, { "Spare 3", "afs.fs.volsync.spare3",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 3", HFILL }},
	{ &hf_afs_fs_volsync_spare4, { "Spare 4", "afs.fs.volsync.spare4",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 4", HFILL }},
	{ &hf_afs_fs_volsync_spare5, { "Spare 5", "afs.fs.volsync.spare5",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 5", HFILL }},
	{ &hf_afs_fs_volsync_spare6, { "Spare 6", "afs.fs.volsync.spare6",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 6", HFILL }},


	{ &hf_afs_fs_acl_count_positive, {
	"ACL Count (Positive)", "afs.fs.acl.count.positive",
		FT_UINT32, BASE_DEC, 0, 0, "Number of Positive ACLs", HFILL }},
	{ &hf_afs_fs_acl_count_negative, {
	"ACL Count (Negative)", "afs.fs.acl.count.negative",
		FT_UINT32, BASE_DEC, 0, 0, "Number of Negative ACLs", HFILL }},
	{ &hf_afs_fs_acl_datasize, {
	"ACL Size", "afs.fs.acl.datasize",
		FT_UINT32, BASE_DEC, 0, 0, "ACL Data Size", HFILL }},
	{ &hf_afs_fs_acl_entity, {
	"Entity (User/Group)", "afs.fs.acl.entity",
		FT_STRING, BASE_HEX, 0, 0, "ACL Entity (User/Group)", HFILL }},
	{ &hf_afs_fs_acl_r, {
	"_R_ead", "afs.fs.acl.r",
		FT_BOOLEAN, 8, 0, PRSFS_READ, "Read", HFILL }},
	{ &hf_afs_fs_acl_l, {
	"_L_ookup", "afs.fs.acl.l",
		FT_BOOLEAN, 8, 0, PRSFS_LOOKUP, "Lookup", HFILL }},
	{ &hf_afs_fs_acl_i, {
	"_I_nsert", "afs.fs.acl.i",
		FT_BOOLEAN, 8, 0, PRSFS_INSERT, "Insert", HFILL }},
	{ &hf_afs_fs_acl_d, { "_D_elete", "afs.fs.acl.d",
		FT_BOOLEAN, 8, 0, PRSFS_DELETE, "Delete", HFILL }},
	{ &hf_afs_fs_acl_w, { "_W_rite", "afs.fs.acl.w",
		FT_BOOLEAN, 8, 0, PRSFS_WRITE, "Write", HFILL }},
	{ &hf_afs_fs_acl_k, { "_L_ock", "afs.fs.acl.k",
		FT_BOOLEAN, 8, 0, PRSFS_LOCK, "Lock", HFILL }},
	{ &hf_afs_fs_acl_a, { "_A_dminister", "afs.fs.acl.a",
		FT_BOOLEAN, 8, 0, PRSFS_ADMINISTER, "Administer", HFILL }},

	{ &hf_afs_fs_callback_version, { "Version", "afs.fs.callback.version",
		FT_UINT32, BASE_DEC, 0, 0, "Version", HFILL }},
	{ &hf_afs_fs_callback_expires, { "Expires", "afs.fs.callback.expires",
		FT_RELATIVE_TIME, BASE_NONE, 0, 0, "Expires", HFILL }},
	{ &hf_afs_fs_callback_type, { "Type", "afs.fs.callback.type",
		FT_UINT32, BASE_DEC, VALS(cb_types), 0, "Type", HFILL }},

/* BOS Server Fields */
	{ &hf_afs_bos_errcode, { "Error Code", "afs.bos.errcode",
		FT_UINT32, BASE_DEC, VALS(afs_errors), 0, "Error Code", HFILL }},
	{ &hf_afs_bos_type, { "Type", "afs.bos.type",
		FT_STRING, BASE_HEX, 0, 0, "Type", HFILL }},
	{ &hf_afs_bos_content, { "Content", "afs.bos.content",
		FT_STRING, BASE_HEX, 0, 0, "Content", HFILL }},
	{ &hf_afs_bos_data, { "Data", "afs.bos.data",
		FT_BYTES, BASE_HEX, 0, 0, "Data", HFILL }},
	{ &hf_afs_bos_path, { "Path", "afs.bos.path",
		FT_STRING, BASE_HEX, 0, 0, "Path", HFILL }},
	{ &hf_afs_bos_parm, { "Parm", "afs.bos.parm",
		FT_STRING, BASE_HEX, 0, 0, "Parm", HFILL }},
	{ &hf_afs_bos_error, { "Error", "afs.bos.error",
		FT_STRING, BASE_HEX, 0, 0, "Error", HFILL }},
	{ &hf_afs_bos_spare1, { "Spare1", "afs.bos.spare1",
		FT_STRING, BASE_HEX, 0, 0, "Spare1", HFILL }},
	{ &hf_afs_bos_spare2, { "Spare2", "afs.bos.spare2",
		FT_STRING, BASE_HEX, 0, 0, "Spare2", HFILL }},
	{ &hf_afs_bos_spare3, { "Spare3", "afs.bos.spare3",
		FT_STRING, BASE_HEX, 0, 0, "Spare3", HFILL }},
	{ &hf_afs_bos_file, { "File", "afs.bos.file",
		FT_STRING, BASE_HEX, 0, 0, "File", HFILL }},
	{ &hf_afs_bos_cmd, { "Command", "afs.bos.cmd",
		FT_STRING, BASE_HEX, 0, 0, "Command", HFILL }},
	{ &hf_afs_bos_key, { "Key", "afs.bos.key",
		FT_BYTES, BASE_HEX, 0, 0, "key", HFILL }},
	{ &hf_afs_bos_user, { "User", "afs.bos.user",
		FT_STRING, BASE_HEX, 0, 0, "User", HFILL }},
	{ &hf_afs_bos_instance, { "Instance", "afs.bos.instance",
		FT_STRING, BASE_HEX, 0, 0, "Instance", HFILL }},
	{ &hf_afs_bos_status, { "Status", "afs.bos.status",
		FT_INT32, BASE_DEC, 0, 0, "Status", HFILL }},
	{ &hf_afs_bos_statusdesc, { "Status Description", "afs.bos.statusdesc",
		FT_STRING, BASE_DEC, 0, 0, "Status Description", HFILL }},
	{ &hf_afs_bos_num, { "Number", "afs.bos.number",
		FT_UINT32, BASE_DEC, 0, 0, "Number", HFILL }},
	{ &hf_afs_bos_size, { "Size", "afs.bos.size",
		FT_UINT32, BASE_DEC, 0, 0, "Size", HFILL }},
	{ &hf_afs_bos_flags, { "Flags", "afs.bos.flags",
		FT_UINT32, BASE_DEC, 0, 0, "Flags", HFILL }},
	{ &hf_afs_bos_date, { "Date", "afs.bos.date",
		FT_UINT32, BASE_DEC, 0, 0, "Date", HFILL }},
	{ &hf_afs_bos_kvno, { "Key Version Number", "afs.bos.kvno",
		FT_UINT32, BASE_DEC, 0, 0, "Key Version Number", HFILL }},
	{ &hf_afs_bos_cell, { "Cell", "afs.bos.cell",
		FT_STRING, BASE_HEX, 0, 0, "Cell", HFILL }},
	{ &hf_afs_bos_host, { "Host", "afs.bos.host",
		FT_STRING, BASE_HEX, 0, 0, "Host", HFILL }},
	{ &hf_afs_bos_newtime, { "New Time", "afs.bos.newtime",
		FT_ABSOLUTE_TIME, BASE_NONE, 0, 0, "New Time", HFILL }},
	{ &hf_afs_bos_baktime, { "Backup Time", "afs.bos.baktime",
		FT_ABSOLUTE_TIME, BASE_NONE, 0, 0, "Backup Time", HFILL }},
	{ &hf_afs_bos_oldtime, { "Old Time", "afs.bos.oldtime",
		FT_ABSOLUTE_TIME, BASE_NONE, 0, 0, "Old Time", HFILL }},
	{ &hf_afs_bos_keymodtime, { "Key Modification Time", "afs.bos.keymodtime",
		FT_ABSOLUTE_TIME, BASE_NONE, 0, 0, "Key Modification Time", HFILL }},
	{ &hf_afs_bos_keychecksum, { "Key Checksum", "afs.bos.keychecksum",
		FT_UINT32, BASE_DEC, 0, 0, "Key Checksum", HFILL }},
	{ &hf_afs_bos_keyspare2, { "Key Spare 2", "afs.bos.keyspare2",
		FT_UINT32, BASE_DEC, 0, 0, "Key Spare 2", HFILL }},


/* KAUTH Server Fields */
	{ &hf_afs_kauth_errcode, { "Error Code", "afs.kauth.errcode",
		FT_UINT32, BASE_DEC, VALS(afs_errors), 0, "Error Code", HFILL }},
	{ &hf_afs_kauth_princ, { "Principal", "afs.kauth.princ",
		FT_STRING, BASE_HEX, 0, 0, "Principal", HFILL }},
	{ &hf_afs_kauth_realm, { "Realm", "afs.kauth.realm",
		FT_STRING, BASE_HEX, 0, 0, "Realm", HFILL }},
	{ &hf_afs_kauth_domain, { "Domain", "afs.kauth.domain",
		FT_STRING, BASE_HEX, 0, 0, "Domain", HFILL }},
	{ &hf_afs_kauth_name, { "Name", "afs.kauth.name",
		FT_STRING, BASE_HEX, 0, 0, "Name", HFILL }},
	{ &hf_afs_kauth_data, { "Data", "afs.kauth.data",
		FT_BYTES, BASE_HEX, 0, 0, "Data", HFILL }},
	{ &hf_afs_kauth_kvno, { "Key Version Number", "afs.kauth.kvno",
		FT_UINT32, BASE_DEC, 0, 0, "Key Version Number", HFILL }},

/* VOL Server Fields */
	{ &hf_afs_vol_errcode, { "Error Code", "afs.vol.errcode",
		FT_UINT32, BASE_DEC, VALS(afs_errors), 0, "Error Code", HFILL }},
	{ &hf_afs_vol_id, { "Volume ID", "afs.vol.id",
		FT_UINT32, BASE_DEC, 0, 0, "Volume ID", HFILL }},
	{ &hf_afs_vol_count, { "Volume Count", "afs.vol.count",
		FT_UINT32, BASE_DEC, 0, 0, "Volume Count", HFILL }},
	{ &hf_afs_vol_name, { "Volume Name", "afs.vol.name",
		FT_STRING, BASE_HEX, 0, 0, "Volume Name", HFILL }},

/* VLDB Server Fields */
	{ &hf_afs_vldb_errcode, { "Error Code", "afs.vldb.errcode",
		FT_UINT32, BASE_DEC, VALS(afs_errors), 0, "Error Code", HFILL }},
	{ &hf_afs_vldb_type, { "Volume Type", "afs.vldb.type",
		FT_UINT32, BASE_HEX, VALS(volume_types), 0, "Volume Type", HFILL }},
	{ &hf_afs_vldb_id, { "Volume ID", "afs.vldb.id",
		FT_UINT32, BASE_DEC, 0, 0, "Volume ID", HFILL }},
	{ &hf_afs_vldb_bump, { "Bumped Volume ID", "afs.vldb.bump",
		FT_UINT32, BASE_DEC, 0, 0, "Bumped Volume ID", HFILL }},
	{ &hf_afs_vldb_index, { "Volume Index", "afs.vldb.index",
		FT_UINT32, BASE_DEC, 0, 0, "Volume Index", HFILL }},
	{ &hf_afs_vldb_count, { "Volume Count", "afs.vldb.count",
		FT_UINT32, BASE_DEC, 0, 0, "Volume Count", HFILL }},
	{ &hf_afs_vldb_numservers, { "Number of Servers", "afs.vldb.numservers",
		FT_UINT32, BASE_DEC, 0, 0, "Number of Servers", HFILL }},
	{ &hf_afs_vldb_nextindex, { "Next Volume Index", "afs.vldb.nextindex",
		FT_UINT32, BASE_DEC, 0, 0, "Next Volume Index", HFILL }},
	{ &hf_afs_vldb_rovol, { "Read-Only Volume ID", "afs.vldb.rovol",
		FT_UINT32, BASE_DEC, 0, 0, "Read-Only Volume ID", HFILL }},
	{ &hf_afs_vldb_rwvol, { "Read-Write Volume ID", "afs.vldb.rwvol",
		FT_UINT32, BASE_DEC, 0, 0, "Read-Only Volume ID", HFILL }},
	{ &hf_afs_vldb_bkvol, { "Backup Volume ID", "afs.vldb.bkvol",
		FT_UINT32, BASE_DEC, 0, 0, "Read-Only Volume ID", HFILL }},
	{ &hf_afs_vldb_clonevol, { "Clone Volume ID", "afs.vldb.clonevol",
		FT_UINT32, BASE_DEC, 0, 0, "Clone Volume ID", HFILL }},
	{ &hf_afs_vldb_name, { "Volume Name", "afs.vldb.name",
		FT_STRING, BASE_HEX, 0, 0, "Volume Name", HFILL }},
	{ &hf_afs_vldb_partition, { "Partition", "afs.vldb.partition",
		FT_STRING, BASE_HEX, 0, 0, "Partition", HFILL }},
	{ &hf_afs_vldb_server, { "Server", "afs.vldb.server",
		FT_IPv4, BASE_HEX, 0, 0, "Server", HFILL }},
	{ &hf_afs_vldb_serveruuid, { "Server UUID", "afs.vldb.serveruuid",
		FT_BYTES, BASE_HEX, 0, 0, "Server UUID", HFILL }},
	{ &hf_afs_vldb_serveruniq, { "Server Unique Address", "afs.vldb.serveruniq",
		FT_UINT32, BASE_HEX, 0, 0, "Server Unique Address", HFILL }},
	{ &hf_afs_vldb_serverflags, { "Server Flags", "afs.vldb.serverflags",
		FT_UINT32, BASE_HEX, 0, 0, "Server Flags", HFILL }},
	{ &hf_afs_vldb_serverip, { "Server IP", "afs.vldb.serverip",
		FT_IPv4, BASE_HEX, 0, 0, "Server IP", HFILL }},
	{ &hf_afs_vldb_flags, { "Flags", "afs.vldb.flags",
		FT_UINT32, BASE_HEX, 0, 0, "Flags", HFILL }},

	{ &hf_afs_vldb_flags_rwexists, { "Read/Write Exists", "afs.vldb.flags.rwexists",
		FT_BOOLEAN, 32, 0, 0x1000, "Read/Write Exists", HFILL }},
	{ &hf_afs_vldb_flags_roexists, { "Read-Only Exists", "afs.vldb.flags.roexists",
		FT_BOOLEAN, 32, 0, 0x2000, "Read-Only Exists", HFILL }},
	{ &hf_afs_vldb_flags_bkexists, { "Backup Exists", "afs.vldb.flags.bkexists",
		FT_BOOLEAN, 32, 0, 0x4000, "Backup Exists", HFILL }},
	{ &hf_afs_vldb_flags_dfsfileset, { "DFS Fileset", "afs.vldb.flags.dfsfileset",
		FT_BOOLEAN, 32, 0, 0x8000, "DFS Fileset", HFILL }},

	{ &hf_afs_vldb_spare1, { "Spare 1", "afs.vldb.spare1",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 1", HFILL }},
	{ &hf_afs_vldb_spare2, { "Spare 2", "afs.vldb.spare2",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 2", HFILL }},
	{ &hf_afs_vldb_spare3, { "Spare 3", "afs.vldb.spare3",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 3", HFILL }},
	{ &hf_afs_vldb_spare4, { "Spare 4", "afs.vldb.spare4",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 4", HFILL }},
	{ &hf_afs_vldb_spare5, { "Spare 5", "afs.vldb.spare5",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 5", HFILL }},
	{ &hf_afs_vldb_spare6, { "Spare 6", "afs.vldb.spare6",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 6", HFILL }},
	{ &hf_afs_vldb_spare7, { "Spare 7", "afs.vldb.spare7",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 7", HFILL }},
	{ &hf_afs_vldb_spare8, { "Spare 8", "afs.vldb.spare8",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 8", HFILL }},
	{ &hf_afs_vldb_spare9, { "Spare 9", "afs.vldb.spare9",
		FT_UINT32, BASE_DEC, 0, 0, "Spare 9", HFILL }},

/* BACKUP Server Fields */
	{ &hf_afs_backup_errcode, { "Error Code", "afs.backup.errcode",
		FT_UINT32, BASE_DEC, VALS(afs_errors), 0, "Error Code", HFILL }},

/* CB Server Fields */
	{ &hf_afs_cb_errcode, { "Error Code", "afs.cb.errcode",
		FT_UINT32, BASE_DEC, VALS(afs_errors), 0, "Error Code", HFILL }},
	{ &hf_afs_cb_callback_version, { "Version", "afs.cb.callback.version",
		FT_UINT32, BASE_DEC, 0, 0, "Version", HFILL }},
	{ &hf_afs_cb_callback_expires, { "Expires", "afs.cb.callback.expires",
		FT_ABSOLUTE_TIME, BASE_NONE, 0, 0, "Expires", HFILL }},
	{ &hf_afs_cb_callback_type, { "Type", "afs.cb.callback.type",
		FT_UINT32, BASE_DEC, VALS(cb_types), 0, "Type", HFILL }},
	{ &hf_afs_cb_fid_volume, { "FileID (Volume)", "afs.cb.fid.volume",
		FT_UINT32, BASE_DEC, 0, 0, "File ID (Volume)", HFILL }},
	{ &hf_afs_cb_fid_vnode, { "FileID (VNode)", "afs.cb.fid.vnode",
		FT_UINT32, BASE_DEC, 0, 0, "File ID (VNode)", HFILL }},
	{ &hf_afs_cb_fid_uniqifier, { "FileID (Uniqifier)", "afs.cb.fid.uniq",
		FT_UINT32, BASE_DEC, 0, 0, "File ID (Uniqifier)", HFILL }},

/* PROT Server Fields */
	{ &hf_afs_prot_errcode, { "Error Code", "afs.prot.errcode",
		FT_UINT32, BASE_DEC, VALS(afs_errors), 0, "Error Code", HFILL }},
	{ &hf_afs_prot_name, { "Name", "afs.prot.name",
		FT_STRING, BASE_HEX, 0, 0, "Name", HFILL }},
	{ &hf_afs_prot_id, { "ID", "afs.prot.id",
		FT_UINT32, BASE_DEC, 0, 0, "ID", HFILL }},
	{ &hf_afs_prot_oldid, { "Old ID", "afs.prot.oldid",
		FT_UINT32, BASE_DEC, 0, 0, "Old ID", HFILL }},
	{ &hf_afs_prot_newid, { "New ID", "afs.prot.newid",
		FT_UINT32, BASE_DEC, 0, 0, "New ID", HFILL }},
	{ &hf_afs_prot_gid, { "Group ID", "afs.prot.gid",
		FT_UINT32, BASE_DEC, 0, 0, "Group ID", HFILL }},
	{ &hf_afs_prot_uid, { "User ID", "afs.prot.uid",
		FT_UINT32, BASE_DEC, 0, 0, "User ID", HFILL }},
	{ &hf_afs_prot_count, { "Count", "afs.prot.count",
		FT_UINT32, BASE_DEC, 0, 0, "Count", HFILL }},
	{ &hf_afs_prot_maxgid, { "Maximum Group ID", "afs.prot.maxgid",
		FT_UINT32, BASE_DEC, 0, 0, "Maximum Group ID", HFILL }},
	{ &hf_afs_prot_maxuid, { "Maximum User ID", "afs.prot.maxuid",
		FT_UINT32, BASE_DEC, 0, 0, "Maximum User ID", HFILL }},
	{ &hf_afs_prot_pos, { "Position", "afs.prot.pos",
		FT_UINT32, BASE_DEC, 0, 0, "Position", HFILL }},
	{ &hf_afs_prot_flag, { "Flag", "afs.prot.flag",
		FT_UINT32, BASE_HEX, 0, 0, "Flag", HFILL }},

/* UBIK Fields */
	{ &hf_afs_ubik_errcode, { "Error Code", "afs.ubik.errcode",
		FT_UINT32, BASE_DEC, VALS(afs_errors), 0, "Error Code", HFILL }},
	{ &hf_afs_ubik_state, { "State", "afs.ubik.state",
		FT_UINT32, BASE_HEX, 0, 0, "State", HFILL }},
	{ &hf_afs_ubik_version_epoch, { "Epoch", "afs.ubik.version.epoch",
		FT_ABSOLUTE_TIME, BASE_NONE, 0, 0, "Epoch", HFILL }},
	{ &hf_afs_ubik_version_counter, { "Counter", "afs.ubik.version.counter",
		FT_UINT32, BASE_DEC, 0, 0, "Counter", HFILL }},
	{ &hf_afs_ubik_votestart, { "Vote Started", "afs.ubik.votestart",
		FT_ABSOLUTE_TIME, BASE_NONE, 0, 0, "Vote Started", HFILL }},
	{ &hf_afs_ubik_voteend, { "Vote Ends", "afs.ubik.voteend",
		FT_ABSOLUTE_TIME, BASE_NONE, 0, 0, "Vote Ends", HFILL }},
	{ &hf_afs_ubik_file, { "File", "afs.ubik.file",
		FT_UINT32, BASE_DEC, 0, 0, "File", HFILL }},
	{ &hf_afs_ubik_pos, { "Position", "afs.ubik.position",
		FT_UINT32, BASE_DEC, 0, 0, "Position", HFILL }},
	{ &hf_afs_ubik_length, { "Length", "afs.ubik.length",
		FT_UINT32, BASE_DEC, 0, 0, "Length", HFILL }},
	{ &hf_afs_ubik_locktype, { "Lock Type", "afs.ubik.locktype",
		FT_UINT32, BASE_DEC, VALS(ubik_lock_types), 0, "Lock Type", HFILL }},
	{ &hf_afs_ubik_votetype, { "Vote Type", "afs.ubik.votetype",
		FT_UINT32, BASE_HEX, 0, 0, "Vote Type", HFILL }},
	{ &hf_afs_ubik_site, { "Site", "afs.ubik.site",
		FT_IPv4, BASE_HEX, 0, 0, "Site", HFILL }},
	{ &hf_afs_ubik_interface, { "Interface Address", "afs.ubik.interface",
		FT_IPv4, BASE_HEX, 0, 0, "Interface Address", HFILL }},

	{ &hf_afs_ubik_now, { "Now", "afs.ubik.now",
		FT_ABSOLUTE_TIME, BASE_HEX, 0, 0, "Now", HFILL }},
	{ &hf_afs_ubik_lastyestime, { "Last Yes Time", "afs.ubik.lastyesttime",
		FT_ABSOLUTE_TIME, BASE_HEX, 0, 0, "Last Yes Time", HFILL }},
	{ &hf_afs_ubik_lastyeshost, { "Last Yes Host", "afs.ubik.lastyeshost",
		FT_IPv4, BASE_HEX, 0, 0, "Last Yes Host", HFILL }},
	{ &hf_afs_ubik_lastyesstate, { "Last Yes State", "afs.ubik.lastyesstate",
		FT_UINT32, BASE_HEX, 0, 0, "Last Yes State", HFILL }},
	{ &hf_afs_ubik_lastyesclaim, { "Last Yes Claim", "afs.ubik.lastyesclaim",
		FT_ABSOLUTE_TIME, BASE_HEX, 0, 0, "Last Yes Claim", HFILL }},
	{ &hf_afs_ubik_lowesthost, { "Lowest Host", "afs.ubik.lowesthost",
		FT_IPv4, BASE_HEX, 0, 0, "Lowest Host", HFILL }},
	{ &hf_afs_ubik_lowesttime, { "Lowest Time", "afs.ubik.lowesttime",
		FT_ABSOLUTE_TIME, BASE_HEX, 0, 0, "Lowest Time", HFILL }},
	{ &hf_afs_ubik_synchost, { "Sync Host", "afs.ubik.synchost",
		FT_IPv4, BASE_HEX, 0, 0, "Sync Host", HFILL }},
	{ &hf_afs_ubik_addr, { "Address", "afs.ubik.addr",
		FT_IPv4, BASE_HEX, 0, 0, "Address", HFILL }},
	{ &hf_afs_ubik_synctime, { "Sync Time", "afs.ubik.synctime",
		FT_ABSOLUTE_TIME, BASE_HEX, 0, 0, "Sync Time", HFILL }},
	{ &hf_afs_ubik_lastvotetime, { "Last Vote Time", "afs.ubik.lastvotetime",
		FT_ABSOLUTE_TIME, BASE_HEX, 0, 0, "Last Vote Time", HFILL }},
	{ &hf_afs_ubik_lastbeaconsent, { "Last Beacon Sent", "afs.ubik.lastbeaconsent",
		FT_ABSOLUTE_TIME, BASE_HEX, 0, 0, "Last Beacon Sent", HFILL }},
	{ &hf_afs_ubik_lastvote, { "Last Vote", "afs.ubik.lastvote",
		FT_UINT32, BASE_HEX, 0, 0, "Last Vote", HFILL }},
	{ &hf_afs_ubik_currentdb, { "Current DB", "afs.ubik.currentdb",
		FT_UINT32, BASE_HEX, 0, 0, "Current DB", HFILL }},
	{ &hf_afs_ubik_up, { "Up", "afs.ubik.up",
		FT_UINT32, BASE_HEX, 0, 0, "Up", HFILL }},
	{ &hf_afs_ubik_beaconsincedown, { "Beacon Since Down", "afs.ubik.beaconsincedown",
		FT_UINT32, BASE_HEX, 0, 0, "Beacon Since Down", HFILL }},
	{ &hf_afs_ubik_amsyncsite, { "Am Sync Site", "afs.ubik.amsyncsite",
		FT_UINT32, BASE_HEX, 0, 0, "Am Sync Site", HFILL }},
	{ &hf_afs_ubik_syncsiteuntil, { "Sync Site Until", "afs.ubik.syncsiteuntil",
		FT_ABSOLUTE_TIME, BASE_HEX, 0, 0, "Sync Site Until", HFILL }},
	{ &hf_afs_ubik_nservers, { "Number of Servers", "afs.ubik.nservers",
		FT_UINT32, BASE_HEX, 0, 0, "Number of Servers", HFILL }},
	{ &hf_afs_ubik_lockedpages, { "Locked Pages", "afs.ubik.lockedpages",
		FT_UINT32, BASE_HEX, 0, 0, "Locked Pages", HFILL }},
	{ &hf_afs_ubik_writelockedpages, { "Write Locked Pages", "afs.ubik.writelockedpages",
		FT_UINT32, BASE_HEX, 0, 0, "Write Locked Pages", HFILL }},
	{ &hf_afs_ubik_activewrite, { "Active Write", "afs.ubik.activewrite",
		FT_UINT32, BASE_HEX, 0, 0, "Active Write", HFILL }},
	{ &hf_afs_ubik_tidcounter, { "TID Counter", "afs.ubik.tidcounter",
		FT_UINT32, BASE_HEX, 0, 0, "TID Counter", HFILL }},
	{ &hf_afs_ubik_anyreadlocks, { "Any Read Locks", "afs.ubik.anyreadlocks",
		FT_UINT32, BASE_HEX, 0, 0, "Any Read Locks", HFILL }},
	{ &hf_afs_ubik_anywritelocks, { "Any Write Locks", "afs.ubik.anywritelocks",
		FT_UINT32, BASE_HEX, 0, 0, "Any Write Locks", HFILL }},
	{ &hf_afs_ubik_recoverystate, { "Recovery State", "afs.ubik.recoverystate",
		FT_UINT32, BASE_HEX, 0, 0, "Recovery State", HFILL }},
	{ &hf_afs_ubik_currenttrans, { "Current Transaction", "afs.ubik.currenttran",
		FT_UINT32, BASE_HEX, 0, 0, "Current Transaction", HFILL }},
	{ &hf_afs_ubik_writetrans, { "Write Transaction", "afs.ubik.writetran",
		FT_UINT32, BASE_HEX, 0, 0, "Write Transaction", HFILL }},
	{ &hf_afs_ubik_epochtime, { "Epoch Time", "afs.ubik.epochtime",
		FT_ABSOLUTE_TIME, BASE_HEX, 0, 0, "Epoch Time", HFILL }},
	{ &hf_afs_ubik_isclone, { "Is Clone", "afs.ubik.isclone",
		FT_UINT32, BASE_HEX, 0, 0, "Is Clone", HFILL }},
	{ &hf_afs_reqframe, { "Request Frame", "afs.reqframe",
		FT_FRAMENUM, BASE_NONE, NULL, 0, "Request Frame", HFILL }},
	{ &hf_afs_repframe, { "Reply Frame", "afs.repframe", 
		FT_FRAMENUM, BASE_NONE,	NULL, 0, "Reply Frame", HFILL }},
	{ &hf_afs_time, { "Time from request", "afs.time", 
		FT_RELATIVE_TIME, BASE_NONE, NULL, 0, "Time between Request and Reply for AFS calls", HFILL }},
	};
	static gint *ett[] = {
		&ett_afs,
		&ett_afs_op,
		&ett_afs_acl,
		&ett_afs_fid,
		&ett_afs_callback,
		&ett_afs_ubikver,
		&ett_afs_status,
		&ett_afs_status_mask,
		&ett_afs_volsync,
		&ett_afs_volumeinfo,
		&ett_afs_vicestat,
		&ett_afs_vldb_flags,
	};

	proto_afs = proto_register_protocol("Andrew File System (AFS)",
	    "AFS (RX)", "afs");
	proto_register_field_array(proto_afs, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_init_routine(&afs_init_protocol);

	register_dissector("afs", dissect_afs, proto_afs);
}
