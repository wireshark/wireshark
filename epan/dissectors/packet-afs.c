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
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/reassemble.h>
#include <epan/ptvcursor.h>

#include "packet-rx.h"

/* Forward declarations */
void proto_register_afs(void);

#define AFS_PORT_FS     7000
#define AFS_PORT_CB     7001
#define AFS_PORT_PROT   7002
#define AFS_PORT_VLDB   7003
#define AFS_PORT_KAUTH  7004
#define AFS_PORT_VOL    7005
#define AFS_PORT_ERROR  7006            /* Doesn't seem to be used */
#define AFS_PORT_BOS    7007
#define AFS_PORT_UPDATE 7008
#define AFS_PORT_RMTSYS 7009
#define AFS_PORT_BACKUP 7021

#ifndef AFSNAMEMAX
#define AFSNAMEMAX 256
#endif

#ifndef AFSOPAQUEMAX
#define AFSOPAQUEMAX 1024
#endif

#define PRNAMEMAX   64
#define VLNAMEMAX   65
#define KANAMEMAX   64
#define BOSNAMEMAX 256

#define PRSFS_READ               1 /* Read files */
#define PRSFS_WRITE              2 /* Write files */
#define PRSFS_INSERT             4 /* Insert files into a directory */
#define PRSFS_LOOKUP             8 /* Lookup files into a directory */
#define PRSFS_DELETE            16 /* Delete files */
#define PRSFS_LOCK              32 /* Lock files */
#define PRSFS_ADMINISTER        64 /* Change ACL's */

#define CB_TYPE_EXCLUSIVE 1
#define CB_TYPE_SHARED 2
#define CB_TYPE_DROPPED 3

#define OPCODE_LOW          0
#define OPCODE_HIGH     66000 /* arbitrary, is just a fuzzy check for encrypted traffic */
#define VOTE_LOW        10000
#define VOTE_HIGH       10007
#define DISK_LOW        20000
#define DISK_HIGH       20013

#define FILE_TYPE_FILE 1
#define FILE_TYPE_DIR  2
#define FILE_TYPE_LINK 3

struct afs_header {
	guint32 opcode;
};

struct afs_volsync {
	guint32 spare1;
	guint32 spare2;
	guint32 spare3;
	guint32 spare4;
	guint32 spare5;
	guint32 spare6;
};

struct afs_status {
	guint32 InterfaceVersion;
	guint32 FileType;
	guint32 LinkCount;
	guint32 Length;
	guint32 DataVersion;
	guint32 Author;
	guint32 Owner;
	guint32 CallerAccess;
	guint32 AnonymousAccess;
	guint32 UnixModeBits;
	guint32 ParentVnode;
	guint32 ParentUnique;
	guint32 SegSize;
	guint32 ClientModTime;
	guint32 ServerModTime;
	guint32 Group;
	guint32 SyncCount;
	guint32 spare1;
	guint32 spare2;
	guint32 spare3;
	guint32 spare4;
};

struct afs_volumeinfo {
	guint32 Vid;
	guint32 Type;
	guint32 Type0;
	guint32 Type1;
	guint32 Type2;
	guint32 Type3;
	guint32 Type4;
	guint32 ServerCount;
	guint32 Server0;
	guint32 Server1;
	guint32 Server2;
	guint32 Server3;
	guint32 Server4;
	guint32 Server5;
	guint32 Server6;
	guint32 Server7;
	guint16 Part0;
	guint16 Part1;
	guint16 Part2;
	guint16 Part3;
	guint16 Part4;
	guint16 Part5;
	guint16 Part6;
	guint16 Part7;
};

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
static int hf_afs_service = -1;

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
static int hf_afs_vldb_name_uint_string = -1;
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

static int hf_afs_cm_uuid = -1;
static int hf_afs_cm_numint = -1;
static int hf_afs_cm_ipaddr = -1;
static int hf_afs_cm_netmask = -1;
static int hf_afs_cm_mtu = -1;
static int hf_afs_cm_numcap = -1;
static int hf_afs_cm_capabilities = -1;
static int hf_afs_cm_cap_errortrans = -1;

static int hf_afs_prot_errcode = -1;
static int hf_afs_prot_name = -1;
static int hf_afs_prot_name_uint_string = -1;
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

/* static int hf_afs_ubik_errcode = -1; */
static int hf_afs_ubik_version_epoch = -1;
static int hf_afs_ubik_version_counter = -1;
static int hf_afs_ubik_votestart = -1;
static int hf_afs_ubik_state = -1;
static int hf_afs_ubik_site = -1;
static int hf_afs_ubik_interface = -1;
static int hf_afs_ubik_null_addresses = -1;
static int hf_afs_ubik_file = -1;
static int hf_afs_ubik_pos = -1;
static int hf_afs_ubik_length = -1;
static int hf_afs_ubik_locktype = -1;
/* static int hf_afs_ubik_voteend = -1; */
/* static int hf_afs_ubik_votetype = -1; */

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

static int hf_afs_fragments = -1;
static int hf_afs_fragment = -1;
static int hf_afs_fragment_overlap = -1;
static int hf_afs_fragment_overlap_conflicts = -1;
static int hf_afs_fragment_multiple_tails = -1;
static int hf_afs_fragment_too_long_fragment = -1;
static int hf_afs_fragment_error = -1;
static int hf_afs_fragment_count = -1;
static int hf_afs_reassembled_in = -1;
static int hf_afs_reassembled_length = -1;

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

static gint ett_afs_fragment = -1;
static gint ett_afs_fragments = -1;
static gint ett_afs_cm_interfaces = -1;
static gint ett_afs_cm_capabilities = -1;

static const fragment_items afs_frag_items = {
	/* Fragment subtrees */
	&ett_afs_fragment,
	&ett_afs_fragments,
	/* Fragment fields */
	&hf_afs_fragments,
	&hf_afs_fragment,
	&hf_afs_fragment_overlap,
	&hf_afs_fragment_overlap_conflicts,
	&hf_afs_fragment_multiple_tails,
	&hf_afs_fragment_too_long_fragment,
	&hf_afs_fragment_error,
	&hf_afs_fragment_count,
	/* Reassembled in field */
	&hf_afs_reassembled_in,
	/* Reassembled length field */
	&hf_afs_reassembled_length,
	/* Reassembled data field */
	NULL,
	/* Tag */
	"RX fragments"
};


/*
 * Macros for helper dissection routines
 *
 * The macros are here to save on coding. They assume that
 * the current offset is in 'offset', and that the offset
 * should be incremented after performing the macro's operation.
 */

/* Output a simple rx array */
static void OUT_RXArray8(ptvcursor_t *cursor, int field, int field_size, int encoding)
{
	unsigned int i,
		size = tvb_get_guint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));

	ptvcursor_advance(cursor, 1);
	for (i=0; i<size; i++) {
		ptvcursor_add(cursor, field, field_size, encoding);
	}
}

/* Output a simple rx array */
#define OUT_RXArray32(func) \
	{ \
		unsigned int j,i; \
		j = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor)); \
		ptvcursor_advance(cursor, 4); \
		for (i=0; i<j; i++) { \
			func; \
		} \
	}

/* Output a UNIX seconds/microseconds timestamp, after converting to an
   nstime_t */
static void OUT_TIMESTAMP(ptvcursor_t *cursor, int field)
{
	nstime_t ts;

	ts.secs = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
	ts.nsecs = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor)+4)*1000;

	proto_tree_add_time(ptvcursor_tree(cursor), field, ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), 8, &ts);
	ptvcursor_advance(cursor, 8);
}

/* Output a seconds-only time value, after converting to an nstime_t;
   this can be an absolute time as a UNIX time-since-epoch, or a
   relative time in seconds */
static void OUT_TIMESECS(ptvcursor_t *cursor, int field)
{
	nstime_t ts;

	ts.secs = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
	ts.nsecs = 0;
	proto_tree_add_time(ptvcursor_tree(cursor), field, ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), 4, &ts);
	ptvcursor_advance(cursor, 4);
}

/* Output a rx style string, up to a maximum length first
   4 bytes - length, then char data */
static void OUT_RXString(ptvcursor_t *cursor, int field)
{
	int offset = ptvcursor_current_offset(cursor),
		new_offset;

	ptvcursor_add(cursor, field, 4, ENC_BIG_ENDIAN);
	new_offset = ptvcursor_current_offset(cursor);

	/* strings are padded to 32-bit boundary */
	ptvcursor_advance(cursor, 4-((new_offset-offset)&3));
}

/* Output a fixed length vectorized string (each char is a 32 bit int) */
static void OUT_RXStringV(ptvcursor_t *cursor, int field, guint32 length)
{
	tvbuff_t* tvb = ptvcursor_tvbuff(cursor);
	char* str = (char*)wmem_alloc(wmem_packet_scope(), length+1);
	int offset = ptvcursor_current_offset(cursor),
		start_offset = offset;
	guint32 idx;

	for (idx = 0; idx<length; idx++)
	{
		str[idx] = (char)tvb_get_ntohl(tvb, offset);
		offset += 4;
	}
	str[length] = '\0';
	proto_tree_add_string(ptvcursor_tree(cursor), field, tvb, start_offset, length*4, str);
	ptvcursor_advance(cursor, length*4);
}


/* Output a callback */
static void OUT_FS_AFSCallBack(ptvcursor_t *cursor)
{
	ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_afs_callback, "Callback");
	ptvcursor_add(cursor, hf_afs_fs_callback_version, 4, ENC_BIG_ENDIAN);
	OUT_TIMESECS(cursor, hf_afs_fs_callback_expires);
	ptvcursor_add(cursor, hf_afs_fs_callback_type, 4, ENC_BIG_ENDIAN);
	ptvcursor_pop_subtree(cursor);
}


/* Output cache manager interfaces */
static void OUT_CM_INTERFACES(ptvcursor_t *cursor)
{
	unsigned int i;
	unsigned int maxint = 32,
				numint = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));

	ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_afs_cm_interfaces, "Interfaces");
	ptvcursor_add(cursor, hf_afs_cm_numint, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_cm_uuid, 4*11, ENC_NA);
	for ( i=0; i<numint; i++ ) {
		ptvcursor_add(cursor, hf_afs_cm_ipaddr, 4, ENC_BIG_ENDIAN);
	}
	ptvcursor_advance(cursor, 4*(maxint-numint));
	for ( i=0; i<numint; i++ ) {
		ptvcursor_add(cursor, hf_afs_cm_netmask, 4, ENC_BIG_ENDIAN);
	}
	ptvcursor_advance(cursor, 4*(maxint-numint));
	for ( i=0; i<numint; i++ ) {
		ptvcursor_add(cursor, hf_afs_cm_mtu, 4, ENC_BIG_ENDIAN);
	}
	ptvcursor_advance(cursor, 4*(maxint-numint));
	ptvcursor_pop_subtree(cursor);
}

/* Output CM capabilities */
static void OUT_CM_CAPABILITIES(ptvcursor_t *cursor)
{
	ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_afs_cm_capabilities, "Capabilities");
	ptvcursor_add(cursor, hf_afs_cm_numcap, 4, ENC_BIG_ENDIAN);
	ptvcursor_add_no_advance(cursor, hf_afs_cm_capabilities, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_cm_cap_errortrans, 4, ENC_BIG_ENDIAN);
	ptvcursor_pop_subtree(cursor);
}

/* Output a callback */
static void OUT_CB_AFSCallBack(ptvcursor_t *cursor)
{
	ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH,
		ett_afs_callback, "Callback");
	ptvcursor_add(cursor, hf_afs_cb_callback_version, 4, ENC_BIG_ENDIAN);
	OUT_TIMESECS(cursor, hf_afs_cb_callback_expires);
	ptvcursor_add(cursor, hf_afs_cb_callback_type, 4, ENC_BIG_ENDIAN);
	ptvcursor_pop_subtree(cursor);
}

/* Output a File ID */
static void OUT_FS_AFSFid(ptvcursor_t *cursor, const char* label)
{
	ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH,
		ett_afs_fid, "FileID (%s)", label);
	ptvcursor_add(cursor, hf_afs_fs_fid_volume, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_fid_vnode, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_fid_uniqifier, 4, ENC_BIG_ENDIAN);
	ptvcursor_pop_subtree(cursor);
}


/* Output a File ID */
static void OUT_CB_AFSFid(ptvcursor_t *cursor, const char* label)
{
	ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH,
		ett_afs_fid, "FileID (%s)", label);

	ptvcursor_add(cursor, hf_afs_cb_fid_volume, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_cb_fid_vnode, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_cb_fid_uniqifier, 4, ENC_BIG_ENDIAN);
	ptvcursor_pop_subtree(cursor);
}

/* Output a StoreStatus */
static void OUT_FS_AFSStoreStatus(ptvcursor_t *cursor, const char* label)
{
	static const int * status_mask_flags[] = {
		&hf_afs_fs_status_mask_setmodtime,
		&hf_afs_fs_status_mask_setowner,
		&hf_afs_fs_status_mask_setgroup,
		&hf_afs_fs_status_mask_setmode,
		&hf_afs_fs_status_mask_setsegsize,
		&hf_afs_fs_status_mask_fsync,
		NULL
	};

	ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH,
		ett_afs_status, "%s", label);
	proto_tree_add_bitmask(ptvcursor_tree(cursor), ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor),
						hf_afs_fs_status_mask, ett_afs_status_mask, status_mask_flags, ENC_BIG_ENDIAN);
	ptvcursor_advance(cursor, 4);
	OUT_TIMESECS(cursor, hf_afs_fs_status_clientmodtime);
	ptvcursor_add(cursor, hf_afs_fs_status_owner, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_group, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_mode, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_segsize, 4, ENC_BIG_ENDIAN);

	ptvcursor_pop_subtree(cursor);
}

/* Output a FetchStatus */
static void OUT_FS_AFSFetchStatus(ptvcursor_t *cursor, const char* label)
{
	ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH,
		ett_afs_status, "%s", label);

	ptvcursor_add(cursor, hf_afs_fs_status_interfaceversion, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_filetype, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_linkcount, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_length, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_dataversion, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_author, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_owner, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_calleraccess, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_anonymousaccess, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_mode, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_parentvnode, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_parentunique, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_segsize, 4, ENC_BIG_ENDIAN);
	OUT_TIMESECS(cursor, hf_afs_fs_status_clientmodtime);
	OUT_TIMESECS(cursor, hf_afs_fs_status_servermodtime);
	ptvcursor_add(cursor, hf_afs_fs_status_group, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_synccounter, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_dataversionhigh, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_spare2, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_spare3, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_status_spare4, 4, ENC_BIG_ENDIAN);

	ptvcursor_pop_subtree(cursor);
}

/* Output a VolSync */
static void OUT_FS_AFSVolSync(ptvcursor_t *cursor)
{
	ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH,
		ett_afs_status, "VolSync");
	OUT_TIMESECS(cursor, hf_afs_fs_volsync_spare1);
	ptvcursor_add(cursor, hf_afs_fs_volsync_spare2, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_volsync_spare3, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_volsync_spare4, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_volsync_spare5, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_fs_volsync_spare6, 4, ENC_BIG_ENDIAN);

	ptvcursor_pop_subtree(cursor);
}

/* Output a AFS acl */
#define ACLOUT(who, positive, acl, bytes) \
	{ 	proto_tree *save; \
		int tmpoffset; \
		int acllen; \
		char tmp[10]; \
		tmp[0] = 0; \
		if ( acl & PRSFS_READ ) g_strlcat(tmp, "r", 10);	\
		if ( acl & PRSFS_LOOKUP ) g_strlcat(tmp, "l", 10);	\
		if ( acl & PRSFS_INSERT ) g_strlcat(tmp, "i", 10);	\
		if ( acl & PRSFS_DELETE ) g_strlcat(tmp, "d", 10);	\
		if ( acl & PRSFS_WRITE ) g_strlcat(tmp, "w", 10);	\
		if ( acl & PRSFS_LOCK ) g_strlcat(tmp, "k", 10);	\
		if ( acl & PRSFS_ADMINISTER ) g_strlcat(tmp, "a", 10);  \
		save = tree; \
		tree = proto_tree_add_subtree_format(tree, tvb, offset, bytes, \
			ett_afs_acl, NULL, "ACL:  %s %s%s", \
			who, tmp, positive ? "" : " (negative)"); \
		proto_tree_add_string(tree,hf_afs_fs_acl_entity, tvb,offset,(int)strlen(who), who);\
		tmpoffset = offset + (int)strlen(who) + 1; \
		acllen = bytes - (int)strlen(who) - 1; \
		proto_tree_add_boolean(tree,hf_afs_fs_acl_r, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_boolean(tree,hf_afs_fs_acl_l, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_boolean(tree,hf_afs_fs_acl_i, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_boolean(tree,hf_afs_fs_acl_d, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_boolean(tree,hf_afs_fs_acl_w, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_boolean(tree,hf_afs_fs_acl_k, tvb,tmpoffset,acllen,acl);\
		proto_tree_add_boolean(tree,hf_afs_fs_acl_a, tvb,tmpoffset,acllen,acl);\
		tree = save; \
	}

/* output a bozo_key */
static void OUT_BOS_KEYINFO(ptvcursor_t *cursor)
{
	OUT_TIMESTAMP(cursor, hf_afs_bos_keymodtime);
	ptvcursor_add(cursor, hf_afs_bos_keychecksum, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_bos_keyspare2, 4, ENC_BIG_ENDIAN);
}

/* output a ubik interface addr array */
static void OUT_UBIK_InterfaceAddrs(ptvcursor_t *cursor)
{
	unsigned int i,j,seen_null=0;

	for (i=0; i<255; i++) {
		j = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
		if ( j != 0 ) {
			ptvcursor_add(cursor, hf_afs_ubik_interface, 4, ENC_BIG_ENDIAN);
			seen_null = 0;
		} else {
			if ( ! seen_null ) {
				ptvcursor_add_no_advance(cursor, hf_afs_ubik_null_addresses, -1, ENC_NA);
				seen_null = 1;
			}
			ptvcursor_advance(cursor, 4);
		}
	}
}

/* Output a UBIK version code */
static void OUT_UBIKVERSION(ptvcursor_t *cursor, const char* label)
{
	unsigned int epoch,counter;
	nstime_t ts;
	epoch = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
	counter = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor)+4);
	ts.secs = epoch;
	ts.nsecs = 0;

	ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH,
		ett_afs_ubikver, "UBIK Version (%s): %u.%u", label, epoch, counter);
	if ( epoch != 0 )
		proto_tree_add_time(ptvcursor_tree(cursor), hf_afs_ubik_version_epoch, ptvcursor_tvbuff(cursor),
				ptvcursor_current_offset(cursor), 4, &ts);
	else
		proto_tree_add_time_format_value(ptvcursor_tree(cursor), hf_afs_ubik_version_epoch, ptvcursor_tvbuff(cursor),
				ptvcursor_current_offset(cursor), 4, &ts, "0");
	ptvcursor_advance(cursor, 4);

	ptvcursor_add(cursor, hf_afs_ubik_version_counter, 4, ENC_BIG_ENDIAN);

	ptvcursor_pop_subtree(cursor);
}

static void OUT_UBIK_DebugOld(ptvcursor_t *cursor)
{
	OUT_TIMESECS(cursor, hf_afs_ubik_now);
	OUT_TIMESECS(cursor, hf_afs_ubik_lastyestime);
	ptvcursor_add(cursor, hf_afs_ubik_lastyeshost, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_ubik_lastyesstate, 4, ENC_BIG_ENDIAN);
	OUT_TIMESECS(cursor, hf_afs_ubik_lastyesclaim);
	ptvcursor_add(cursor, hf_afs_ubik_lowesthost, 4, ENC_BIG_ENDIAN);
	OUT_TIMESECS(cursor, hf_afs_ubik_lowesttime);
	ptvcursor_add(cursor, hf_afs_ubik_synchost, 4, ENC_BIG_ENDIAN);
	OUT_TIMESECS(cursor, hf_afs_ubik_synctime);
	OUT_UBIKVERSION(cursor, "Sync Version");
	OUT_UBIKVERSION(cursor, "Sync TID");
	ptvcursor_add(cursor, hf_afs_ubik_amsyncsite, 4, ENC_BIG_ENDIAN);
	OUT_TIMESECS(cursor, hf_afs_ubik_syncsiteuntil);
	ptvcursor_add(cursor, hf_afs_ubik_nservers, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_ubik_lockedpages, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_ubik_writelockedpages, 4, ENC_BIG_ENDIAN);
	OUT_UBIKVERSION(cursor, "Local Version");
	ptvcursor_add(cursor, hf_afs_ubik_activewrite, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_ubik_tidcounter, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_ubik_anyreadlocks, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_ubik_anywritelocks, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_ubik_recoverystate, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_ubik_currenttrans, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_ubik_writetrans, 4, ENC_BIG_ENDIAN);
	OUT_TIMESECS(cursor, hf_afs_ubik_epochtime);
}

static void OUT_UBIK_SDebugOld(ptvcursor_t *cursor)
{
	ptvcursor_add(cursor, hf_afs_ubik_addr, 4, ENC_BIG_ENDIAN);
	OUT_TIMESECS(cursor, hf_afs_ubik_lastvotetime);
	OUT_TIMESECS(cursor, hf_afs_ubik_lastbeaconsent);
	ptvcursor_add(cursor, hf_afs_ubik_lastvote, 4, ENC_BIG_ENDIAN);
	OUT_UBIKVERSION(cursor, "Remote Version");
	ptvcursor_add(cursor, hf_afs_ubik_currentdb, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_ubik_beaconsincedown, 4, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_afs_ubik_up, 4, ENC_BIG_ENDIAN);
}

/* Output a kauth getticket request */
static void OUT_KAUTH_GetTicket(ptvcursor_t *cursor)
{
	int len;

	ptvcursor_add(cursor, hf_afs_kauth_kvno, 4, ENC_BIG_ENDIAN);
	OUT_RXString(cursor, hf_afs_kauth_domain);
	len = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
	ptvcursor_advance(cursor, 4);
	ptvcursor_add(cursor, hf_afs_kauth_data, len, ENC_NA);
	OUT_RXString(cursor, hf_afs_kauth_princ);
	OUT_RXString(cursor, hf_afs_kauth_realm);
}

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
static value_string_ext fs_req_ext = VALUE_STRING_EXT_INIT(fs_req);

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
static value_string_ext cb_req_ext = VALUE_STRING_EXT_INIT(cb_req);

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
static value_string_ext prot_req_ext = VALUE_STRING_EXT_INIT(prot_req);

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
static value_string_ext vldb_req_ext = VALUE_STRING_EXT_INIT(vldb_req);

static const value_string kauth_req[] = {
	{ 1,		"auth-old" },
	{ 2,		"change-pw" },
	{ 3,		"get-ticket-old" },
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
	{ 21,		"authenticate" },
	{ 22,		"authenticate-v2" },
	{ 23,		"get-ticket" },
	{ 0,		NULL },
};
static value_string_ext kauth_req_ext = VALUE_STRING_EXT_INIT(kauth_req);

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
static value_string_ext vol_req_ext = VALUE_STRING_EXT_INIT(vol_req);

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
static value_string_ext bos_req_ext = VALUE_STRING_EXT_INIT(bos_req);

static const value_string update_req[] = {
	{ 1,		"fetch-file" },
	{ 2,		"fetch-info" },
	{ 0,		NULL },
};
static value_string_ext update_req_ext = VALUE_STRING_EXT_INIT(update_req);

static const value_string rmtsys_req[] = {
	{ 1,		"setpag" },
	{ 2,		"pioctl" },
	{ 0,		NULL },
};
static value_string_ext rmtsys_req_ext = VALUE_STRING_EXT_INIT(rmtsys_req);

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
static value_string_ext backup_req_ext = VALUE_STRING_EXT_INIT(backup_req);

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
static value_string_ext ubik_req_ext = VALUE_STRING_EXT_INIT(ubik_req);

static const value_string cb_types[] = {
	{ CB_TYPE_EXCLUSIVE, "exclusive" },
	{ CB_TYPE_SHARED, "shared" },
	{ CB_TYPE_DROPPED, "dropped" },
	{ 0, NULL },
};

static const value_string afs_errors[] = {
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
static value_string_ext afs_errors_ext = VALUE_STRING_EXT_INIT(afs_errors);

static const value_string port_types[] = {
	{ AFS_PORT_FS,     "File Server" },
	{ AFS_PORT_CB,     "Callback Server" },
	{ AFS_PORT_PROT,   "Protection Server" },
	{ AFS_PORT_VLDB,   "Volume Location Database Server" },
	{ AFS_PORT_KAUTH,  "Kerberos Authentication Server" },
	{ AFS_PORT_VOL,    "Volume Server" },
	{ AFS_PORT_ERROR,  "Error Server" },
	{ AFS_PORT_BOS,    "BOS Server" },
	{ AFS_PORT_UPDATE, "Update? Server" },
	{ AFS_PORT_RMTSYS, "Rmtsys? Server" },
	{ AFS_PORT_BACKUP, "Backup Server" },
	{ 0, NULL }
};
static value_string_ext port_types_ext = VALUE_STRING_EXT_INIT(port_types);

static const value_string port_types_short[] = {
	{ AFS_PORT_FS,     "FS" },
	{ AFS_PORT_CB,     "CB" },
	{ AFS_PORT_PROT,   "PROT" },
	{ AFS_PORT_VLDB,   "VLDB" },
	{ AFS_PORT_KAUTH,  "KAUTH" },
	{ AFS_PORT_VOL,    "VOL" },
	{ AFS_PORT_ERROR,  "ERR" },
	{ AFS_PORT_BOS,    "BOS" },
	{ AFS_PORT_UPDATE, "UPD" },
	{ AFS_PORT_RMTSYS, "RMT" },
	{ AFS_PORT_BACKUP, "BKUP" },
	{ 0, NULL }
};
static value_string_ext port_types_short_ext = VALUE_STRING_EXT_INIT(port_types_short);

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
	guint32 conversation, epoch, cid, callnumber;
	guint16 service;
};

struct afs_request_val {
	guint32 opcode;
	guint req_num;
	guint rep_num;
	nstime_t req_time;
};

static GHashTable *afs_request_hash = NULL;

/*static GHashTable *afs_fragment_table = NULL; */
/*static GHashTable *afs_reassembled_table = NULL; */
static reassembly_table afs_reassembly_table;

/*
 * Hash Functions
 */
static gint
afs_equal(gconstpointer v, gconstpointer w)
{
	const struct afs_request_key *v1 = (const struct afs_request_key *)v;
	const struct afs_request_key *v2 = (const struct afs_request_key *)w;

	if (v1 -> conversation == v2 -> conversation &&
	    v1 -> epoch == v2 -> epoch &&
	    v1 -> cid == v2 -> cid &&
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

	val = key -> conversation + key -> epoch + key -> cid + key -> callnumber;

	return val;
}

/*
 * Protocol initialization
 */
static void
afs_init_protocol(void)
{
	afs_request_hash = g_hash_table_new(afs_hash, afs_equal);
	reassembly_table_init(&afs_reassembly_table,
			      &addresses_reassembly_table_functions);
}

static void
afs_cleanup_protocol(void)
{
	reassembly_table_destroy(&afs_reassembly_table);
	g_hash_table_destroy(afs_request_hash);
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
 * Should this just scan the string itself, rather than using "sscanf()"?
 */
#define GETSTR (tvb_format_text(tvb,ptvcursor_current_offset(cursor),tvb_captured_length_remaining(tvb,ptvcursor_current_offset(cursor))))

static void
dissect_acl(ptvcursor_t *cursor, struct rxinfo *rxinfo _U_)
{
	int old_offset = ptvcursor_current_offset(cursor), offset;
	gint32 bytes;
	int i, n, pos, neg, acl;
	proto_tree* tree = ptvcursor_tree(cursor);
	tvbuff_t* tvb = ptvcursor_tvbuff(cursor);
	char user[128] = "[Unknown]"; /* Be sure to adjust sscanf()s below if length is changed... */

	bytes = tvb_get_ntohl(tvb, ptvcursor_current_offset(cursor));
	ptvcursor_add(cursor, hf_afs_fs_acl_datasize, 4, ENC_BIG_ENDIAN);

	if (sscanf(GETSTR, "%d %n", &pos, &n) != 1) {
		/* does not matter what we return, if this fails,
		 * we can't dissect anything else in the packet either.
		 */
		return;
	}
	proto_tree_add_uint(tree, hf_afs_fs_acl_count_positive, tvb,
		ptvcursor_current_offset(cursor), n, pos);
	ptvcursor_advance(cursor, n);

	if (sscanf(GETSTR, "%d %n", &neg, &n) != 1) {
		return;
	}
	proto_tree_add_uint(tree, hf_afs_fs_acl_count_negative, tvb,
		ptvcursor_current_offset(cursor), n, neg);
	ptvcursor_advance(cursor, n);

	/*
	 * This wacky order preserves the order used by the "fs" command
	 */
	offset = ptvcursor_current_offset(cursor);
	for (i = 0; i < pos; i++) {
		if (sscanf(GETSTR, "%127s %d %n", user, &acl, &n) != 2) {
			return;
		}
		ACLOUT(user,1,acl,n);
		offset += n;
	}
	for (i = 0; i < neg; i++) {
		if (sscanf(GETSTR, "%127s %d %n", user, &acl, &n) != 2) {
			return;
		}
		ACLOUT(user,0,acl,n);
		offset += n;
		if (offset >= old_offset+bytes ) {
			return;
		}
	}
}

/*
 * Here are the helper dissection routines
 */

static void
dissect_fs_reply(ptvcursor_t *cursor, struct rxinfo *rxinfo, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 130: /* fetch data */
				OUT_FS_AFSFetchStatus(cursor, "Status");
				OUT_FS_AFSCallBack(cursor);
				OUT_FS_AFSVolSync(cursor);
				ptvcursor_add(cursor, hf_afs_fs_data, -1, ENC_NA);
				break;
			case 131: /* fetch acl */
				dissect_acl(cursor, rxinfo);
				OUT_FS_AFSFetchStatus(cursor, "Status");
				OUT_FS_AFSVolSync(cursor);
				break;
			case 132: /* Fetch status */
				OUT_FS_AFSFetchStatus(cursor, "Status");
				OUT_FS_AFSCallBack(cursor);
				OUT_FS_AFSVolSync(cursor);
				break;
			case 133: /* Store data */
			case 134: /* Store ACL */
	 		case 135: /* Store status */
			case 136: /* Remove file */
				OUT_FS_AFSFetchStatus(cursor, "Status");
				OUT_FS_AFSVolSync(cursor);
				break;
			case 137: /* create file */
			case 141: /* make dir */
			case 161: /* lookup */
			case 163: /* dfs symlink */
				OUT_FS_AFSFid(cursor, (opcode == 137)? "New File" : ((opcode == 141)? "New Directory" : "File"));
				OUT_FS_AFSFetchStatus(cursor, "File Status");
				OUT_FS_AFSFetchStatus(cursor, "Directory Status");
				OUT_FS_AFSCallBack(cursor);
				OUT_FS_AFSVolSync(cursor);
				break;
			case 138: /* rename */
				OUT_FS_AFSFetchStatus(cursor, "Old Directory Status");
				OUT_FS_AFSFetchStatus(cursor, "New Directory Status");
				OUT_FS_AFSVolSync(cursor);
				break;
			case 139: /* symlink */
				OUT_FS_AFSFid(cursor, "Symlink");
				break;
			case 140: /* link */
				OUT_FS_AFSFetchStatus(cursor, "Symlink Status");
				break;
			case 142: /* rmdir */
				OUT_FS_AFSFetchStatus(cursor, "Directory Status");
				OUT_FS_AFSVolSync(cursor);
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
				/* OUT_FS_ViceStatistics(); */
				break;
			case 148: /* get volume info */
			case 154: /* n-get-volume-info */
				/* OUT_FS_VolumeInfo(); */
				break;
			case 149: /* get volume status */
				/* OUT_FS_AFSFetchVolumeStatus(); */
				OUT_RXString(cursor, hf_afs_fs_volname);
				OUT_RXString(cursor, hf_afs_fs_offlinemsg);
				OUT_RXString(cursor, hf_afs_fs_motd);
				break;
			case 151: /* root volume */
				OUT_RXString(cursor, hf_afs_fs_volname);
				break;
			case 153: /* get time */
				OUT_TIMESTAMP(cursor, hf_afs_fs_timestamp);
				break;
			case 155: /* bulk status */
				OUT_RXArray32(OUT_FS_AFSFetchStatus(cursor, "Status"));
				ptvcursor_advance(cursor, 4); /* skip */
				OUT_RXArray32(OUT_FS_AFSCallBack(cursor));
				OUT_FS_AFSVolSync(cursor);
				break;
			case 156: /* set lock */
			case 157: /* extend lock */
			case 158: /* release lock */
				OUT_FS_AFSVolSync(cursor);
				break;
			case 159: /* x-stats-version */
				ptvcursor_add(cursor, hf_afs_fs_xstats_version, 4, ENC_BIG_ENDIAN);
				break;
			case 160: /* get xstats */
				ptvcursor_add(cursor, hf_afs_fs_xstats_version, 4, ENC_BIG_ENDIAN);
				OUT_TIMESECS(cursor, hf_afs_fs_xstats_timestamp);
				/* OUT_FS_AFS_CollData(); */
				break;
			case 162: /* flush cps */
				ptvcursor_add(cursor, hf_afs_fs_cps_spare2, 4, ENC_BIG_ENDIAN);
				ptvcursor_add(cursor, hf_afs_fs_cps_spare3, 4, ENC_BIG_ENDIAN);
				break;
			case 65536: /* inline bulk status */
				OUT_RXArray32(OUT_FS_AFSFetchStatus(cursor, "Status"));
				OUT_RXArray32(OUT_FS_AFSCallBack(cursor));
				OUT_FS_AFSVolSync(cursor);
				break;
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		ptvcursor_add(cursor, hf_afs_fs_errcode, 4, ENC_BIG_ENDIAN);
	}
}

static void
dissect_fs_request(ptvcursor_t *cursor, struct rxinfo *rxinfo, int opcode)
{
	ptvcursor_advance(cursor, 4); /* skip the opcode */

	switch ( opcode )
	{
		case 130: /* Fetch data */
			OUT_FS_AFSFid(cursor, "Source");
			ptvcursor_add(cursor, hf_afs_fs_offset, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_fs_length, 4, ENC_BIG_ENDIAN);
			break;
		case 131: /* Fetch ACL */
			OUT_FS_AFSFid(cursor, "Target");
			break;
		case 132: /* Fetch Status */
			OUT_FS_AFSFid(cursor, "Target");
			break;
		case 133: /* Store Data */
			OUT_FS_AFSFid(cursor, "Destination");
			OUT_FS_AFSStoreStatus(cursor, "Status");
			ptvcursor_add(cursor, hf_afs_fs_offset, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_fs_length, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_fs_flength, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_fs_data, -1, ENC_NA);
			break;
		case 134: /* Store ACL */
			OUT_FS_AFSFid(cursor, "Target");
			dissect_acl(cursor, rxinfo);
			break;
		case 135: /* Store Status */
			OUT_FS_AFSFid(cursor, "Target");
			OUT_FS_AFSStoreStatus(cursor, "Status");
			break;
		case 136: /* Remove File */
			OUT_FS_AFSFid(cursor, "Remove File");
			OUT_RXString(cursor, hf_afs_fs_name);
			break;
		case 137: /* Create File */
			OUT_FS_AFSFid(cursor, "Target");
			OUT_RXString(cursor, hf_afs_fs_name);
			OUT_FS_AFSStoreStatus(cursor, "Status");
			break;
		case 138: /* Rename file */
			OUT_FS_AFSFid(cursor, "Old");
			OUT_RXString(cursor, hf_afs_fs_oldname);
			OUT_FS_AFSFid(cursor, "New");
			OUT_RXString(cursor, hf_afs_fs_newname);
			break;
		case 139: /* Symlink */
			OUT_FS_AFSFid(cursor, "File");
			OUT_RXString(cursor, hf_afs_fs_symlink_name);
			OUT_RXString(cursor, hf_afs_fs_symlink_content);
			OUT_FS_AFSStoreStatus(cursor, "Status");
			break;
		case 140: /* Link */
			OUT_FS_AFSFid(cursor, "Link To (New File)");
			OUT_RXString(cursor, hf_afs_fs_name);
			OUT_FS_AFSFid(cursor, "Link From (Old File)");
			break;
		case 141: /* Make dir */
			OUT_FS_AFSFid(cursor, "Target");
			OUT_RXString(cursor, hf_afs_fs_name);
			OUT_FS_AFSStoreStatus(cursor, "Status");
			break;
		case 142: /* Remove dir */
			OUT_FS_AFSFid(cursor, "Target");
			OUT_RXString(cursor, hf_afs_fs_name);
			break;
		case 143: /* Old Set Lock */
			OUT_FS_AFSFid(cursor, "Target");
			ptvcursor_add(cursor, hf_afs_fs_vicelocktype, 4, ENC_BIG_ENDIAN);
			OUT_FS_AFSVolSync(cursor);
			break;
		case 144: /* Old Extend Lock */
			OUT_FS_AFSFid(cursor, "Target");
			OUT_FS_AFSVolSync(cursor);
			break;
		case 145: /* Old Release Lock */
			OUT_FS_AFSFid(cursor, "Target");
			OUT_FS_AFSVolSync(cursor);
			break;
		case 146: /* Get statistics */
			/* no params */
			break;
		case 147: /* Give up callbacks */
			OUT_RXArray32(OUT_FS_AFSFid(cursor, "Target"));
			OUT_RXArray32(OUT_FS_AFSCallBack(cursor));
			break;
		case 148: /* Get vol info */
			OUT_RXString(cursor, hf_afs_fs_volname);
			break;
		case 149: /* Get vol stats */
			ptvcursor_add(cursor, hf_afs_fs_volid, 4, ENC_BIG_ENDIAN);
			break;
		case 150: /* Set vol stats */
			ptvcursor_add(cursor, hf_afs_fs_volid, 4, ENC_BIG_ENDIAN);
			/* OUT_FS_AFSStoreVolumeStatus(); */
			OUT_RXString(cursor, hf_afs_fs_volname);
			OUT_RXString(cursor, hf_afs_fs_offlinemsg);
			OUT_RXString(cursor, hf_afs_fs_motd);
			break;
		case 151: /* get root volume */
			/* no params */
			break;
		case 152: /* check token */
			ptvcursor_add(cursor, hf_afs_fs_viceid, 4, ENC_BIG_ENDIAN);
			/* Output an AFS Token - might just be bytes though */
			OUT_RXStringV(cursor, hf_afs_fs_token, 1024);
			break;
		case 153: /* get time */
			/* no params */
			break;
		case 154: /* new get vol info */
			OUT_RXString(cursor, hf_afs_fs_volname);
			break;
		case 155: /* bulk stat */
			OUT_RXArray32(OUT_FS_AFSFid(cursor, "Target"));
			break;
		case 156: /* Set Lock */
			OUT_FS_AFSFid(cursor, "Target");
			ptvcursor_add(cursor, hf_afs_fs_vicelocktype, 4, ENC_BIG_ENDIAN);
			break;
		case 157: /* Extend Lock */
			OUT_FS_AFSFid(cursor, "Target");
			break;
		case 158: /* Release Lock */
			OUT_FS_AFSFid(cursor, "Target");
			break;
		case 159: /* xstats version */
			/* no params */
			break;
		case 160: /* get xstats */
			ptvcursor_add(cursor, hf_afs_fs_xstats_clientversion, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_fs_xstats_collnumber, 4, ENC_BIG_ENDIAN);
			break;
		case 161: /* lookup */
			OUT_FS_AFSFid(cursor, "Target");
			OUT_RXString(cursor, hf_afs_fs_name);
			break;
		case 162: /* flush cps */
			OUT_RXArray8(cursor, hf_afs_fs_viceid, 4, ENC_BIG_ENDIAN);
			OUT_RXArray8(cursor, hf_afs_fs_ipaddr, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_fs_cps_spare1, 4, ENC_BIG_ENDIAN);
			break;
		case 163: /* dfs symlink */
			OUT_FS_AFSFid(cursor, "Target");
			OUT_RXString(cursor, hf_afs_fs_symlink_name);
			OUT_RXString(cursor, hf_afs_fs_symlink_content);
			OUT_FS_AFSStoreStatus(cursor, "Symlink Status");
			break;
		case 220: /* residencycmd */
			OUT_FS_AFSFid(cursor, "Target");
			/* need residency inputs here */
			break;
		case 65536: /* inline bulk status */
			OUT_RXArray32(OUT_FS_AFSFid(cursor, "Target"));
			break;
		case 65537: /* fetch-data-64 */
			OUT_FS_AFSFid(cursor, "Target");
			ptvcursor_add(cursor, hf_afs_fs_offset64, 8, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_fs_length64, 8, ENC_BIG_ENDIAN);
			/* need more here */
			break;
		case 65538: /* store-data-64 */
			OUT_FS_AFSFid(cursor, "Target");
			OUT_FS_AFSStoreStatus(cursor, "Status");
			ptvcursor_add(cursor, hf_afs_fs_offset64, 8, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_fs_length64, 8, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_fs_flength64, 8, ENC_BIG_ENDIAN);
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
dissect_bos_reply(ptvcursor_t *cursor, struct rxinfo *rxinfo, int opcode)
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
				ptvcursor_add(cursor, hf_afs_bos_status, 4, ENC_BIG_ENDIAN);
				OUT_RXString(cursor, hf_afs_bos_statusdesc);
				break;
			case 84: /* enumerate instance */
				OUT_RXString(cursor, hf_afs_bos_instance);
				break;
			case 85: /* get instance info */
				OUT_RXString(cursor, hf_afs_bos_type);
				ptvcursor_advance(cursor, 4*10);
				break;
			case 86: /* get instance parm */
				OUT_RXString(cursor, hf_afs_bos_parm);
				break;
			case 87: /* add siperuser */
				/* no output */
				break;
			case 88: /* delete superuser */
				/* no output */
				break;
			case 89: /* list superusers */
				OUT_RXString(cursor, hf_afs_bos_user);
				break;
			case 90: /* list keys */
				ptvcursor_add(cursor, hf_afs_bos_kvno, 4, ENC_BIG_ENDIAN);
				ptvcursor_add(cursor, hf_afs_bos_key, 8, ENC_NA);
				OUT_BOS_KEYINFO(cursor);
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
				OUT_RXString(cursor, hf_afs_bos_cell);
				break;
			case 95: /* get cell host */
				OUT_RXString(cursor, hf_afs_bos_host);
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
				OUT_TIMESECS(cursor, hf_afs_bos_newtime);
				OUT_TIMESECS(cursor, hf_afs_bos_baktime);
				OUT_TIMESECS(cursor, hf_afs_bos_oldtime);
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
				ptvcursor_advance(cursor, 12);
				break;
			case 112: /* get log */
				/* need to make this dump a big string somehow */
				ptvcursor_add(cursor, hf_afs_bos_data, -1, ENC_NA);
				break;
			case 113: /* wait all */
				/* no output */
				break;
			case 114: /* get instance strings */
				OUT_RXString(cursor, hf_afs_bos_error);
				OUT_RXString(cursor, hf_afs_bos_spare1);
				OUT_RXString(cursor, hf_afs_bos_spare2);
				OUT_RXString(cursor, hf_afs_bos_spare3);
				break;
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		ptvcursor_add(cursor, hf_afs_bos_errcode, 4, ENC_BIG_ENDIAN);
	}
}

static void
dissect_bos_request(ptvcursor_t *cursor, struct rxinfo *rxinfo _U_, int opcode)
{
	ptvcursor_advance(cursor, 4); /* skip the opcode */

	switch ( opcode )
	{
		case 80: /* create b node */
			OUT_RXString(cursor, hf_afs_bos_type);
			OUT_RXString(cursor, hf_afs_bos_instance);
			OUT_RXString(cursor, hf_afs_bos_parm);
			OUT_RXString(cursor, hf_afs_bos_parm);
			OUT_RXString(cursor, hf_afs_bos_parm);
			OUT_RXString(cursor, hf_afs_bos_parm);
			OUT_RXString(cursor, hf_afs_bos_parm);
			OUT_RXString(cursor, hf_afs_bos_parm);
			break;
		case 81: /* delete b node */
			OUT_RXString(cursor, hf_afs_bos_instance);
			break;
		case 82: /* set status */
			OUT_RXString(cursor, hf_afs_bos_instance);
			ptvcursor_add(cursor, hf_afs_bos_status, 4, ENC_BIG_ENDIAN);
			break;
		case 83: /* get status */
			OUT_RXString(cursor, hf_afs_bos_instance);
			break;
		case 84: /* enumerate instance */
			ptvcursor_add(cursor, hf_afs_bos_num, 4, ENC_BIG_ENDIAN);
			break;
		case 85: /* get instance info */
			OUT_RXString(cursor, hf_afs_bos_instance);
			break;
		case 86: /* get instance parm */
			OUT_RXString(cursor, hf_afs_bos_instance);
			ptvcursor_add(cursor, hf_afs_bos_num, 4, ENC_BIG_ENDIAN);
			break;
		case 87: /* add super user */
			OUT_RXString(cursor, hf_afs_bos_user);
			break;
		case 88: /* delete super user */
			OUT_RXString(cursor, hf_afs_bos_user);
			break;
		case 89: /* list super users */
			ptvcursor_add(cursor, hf_afs_bos_num, 4, ENC_BIG_ENDIAN);
			break;
		case 90: /* list keys */
			ptvcursor_add(cursor, hf_afs_bos_num, 4, ENC_BIG_ENDIAN);
			break;
		case 91: /* add key */
			ptvcursor_add(cursor, hf_afs_bos_num, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_bos_key, 8, ENC_NA);
			break;
		case 92: /* delete key */
			ptvcursor_add(cursor, hf_afs_bos_num, 4, ENC_BIG_ENDIAN);
			break;
		case 93: /* set cell name */
			OUT_RXString(cursor, hf_afs_bos_content);
			break;
		case 95: /* set cell host */
			ptvcursor_add(cursor, hf_afs_bos_num, 4, ENC_BIG_ENDIAN);
			break;
		case 96: /* add cell host */
			OUT_RXString(cursor, hf_afs_bos_content);
			break;
		case 97: /* delete cell host */
			OUT_RXString(cursor, hf_afs_bos_content);
			break;
		case 98: /* set t status */
			OUT_RXString(cursor, hf_afs_bos_content);
			ptvcursor_add(cursor, hf_afs_bos_status, 4, ENC_BIG_ENDIAN);
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
			ptvcursor_add(cursor, hf_afs_bos_flags, 4, ENC_BIG_ENDIAN);
			break;
		case 103: /* re-bozo? */
			/* no params */
			break;
		case 104: /* restart */
			OUT_RXString(cursor, hf_afs_bos_instance);
			break;
		case 105: /* install */
			OUT_RXString(cursor, hf_afs_bos_path);
			ptvcursor_add(cursor, hf_afs_bos_size, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_bos_flags, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_bos_date, 4, ENC_BIG_ENDIAN);
			break;
		case 106: /* uninstall */
			OUT_RXString(cursor, hf_afs_bos_path);
			break;
		case 107: /* get dates */
			OUT_RXString(cursor, hf_afs_bos_path);
			break;
		case 108: /* exec */
			OUT_RXString(cursor, hf_afs_bos_cmd);
			break;
		case 109: /* prune */
			ptvcursor_add(cursor, hf_afs_bos_flags, 4, ENC_BIG_ENDIAN);
			break;
		case 110: /* set restart time */
			ptvcursor_add(cursor, hf_afs_bos_num, 4, ENC_BIG_ENDIAN);
			ptvcursor_advance(cursor, 12);
			break;
		case 111: /* get restart time */
			ptvcursor_add(cursor, hf_afs_bos_num, 4, ENC_BIG_ENDIAN);
			break;
		case 112: /* get log */
			OUT_RXString(cursor, hf_afs_bos_file);
			break;
		case 113: /* wait all */
			/* no params */
			break;
		case 114: /* get instance strings */
			OUT_RXString(cursor, hf_afs_bos_content);
			break;
	}
}

/*
 * VOL Helpers
 */
static void
dissect_vol_reply(ptvcursor_t *cursor, struct rxinfo *rxinfo, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 121:
				/* should loop here maybe */
				ptvcursor_add(cursor, hf_afs_vol_count, 4, ENC_BIG_ENDIAN);
				OUT_RXStringV(cursor, hf_afs_vol_name, 32); /* not sure on  */
				break;
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		ptvcursor_add(cursor, hf_afs_vol_errcode, 4, ENC_BIG_ENDIAN);
	}
}

static void
dissect_vol_request(ptvcursor_t *cursor, struct rxinfo *rxinfo _U_, int opcode)
{
	ptvcursor_advance(cursor, 4); /* skip the opcode */

	switch ( opcode )
	{
		case 121: /* list one vol */
			ptvcursor_add(cursor, hf_afs_vol_count, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_vol_id, 4, ENC_BIG_ENDIAN);
			break;
	}
}

/*
 * KAUTH Helpers
 */
static void
dissect_kauth_reply(ptvcursor_t *cursor, struct rxinfo *rxinfo, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		ptvcursor_add(cursor, hf_afs_kauth_errcode, 4, ENC_BIG_ENDIAN);
	}
}

static void
dissect_kauth_request(ptvcursor_t *cursor, struct rxinfo *rxinfo _U_, int opcode)
{
	ptvcursor_advance(cursor, 4); /* skip the opcode */

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
			OUT_RXString(cursor, hf_afs_kauth_princ);
			OUT_RXString(cursor, hf_afs_kauth_realm);
			ptvcursor_add(cursor, hf_afs_kauth_data, -1, ENC_NA);
			break;
		case 3: /* getticket-old */
		case 23: /* getticket */
			OUT_KAUTH_GetTicket(cursor);
			break;
		case 4: /* set pass */
			OUT_RXString(cursor, hf_afs_kauth_princ);
			OUT_RXString(cursor, hf_afs_kauth_realm);
			ptvcursor_add(cursor, hf_afs_kauth_kvno, 4, ENC_BIG_ENDIAN);
			break;
		case 12: /* get pass */
			OUT_RXString(cursor, hf_afs_kauth_name);
			break;
	}
}

/*
 * CB Helpers
 */
static void
dissect_cb_reply(ptvcursor_t *cursor, struct rxinfo *rxinfo, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode ) {
			case 65538: /* get-capabilites */
				OUT_CM_INTERFACES(cursor);
				OUT_CM_CAPABILITIES(cursor);
				break;
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		ptvcursor_add(cursor, hf_afs_cb_errcode, 4, ENC_BIG_ENDIAN);
	}
}

static void
dissect_cb_request(ptvcursor_t *cursor, struct rxinfo *rxinfo _U_, int opcode)
{
	ptvcursor_advance(cursor, 4); /* skip the opcode */

	switch ( opcode )
	{
	case 204: /* callback */
		OUT_RXArray32(OUT_CB_AFSFid(cursor, "Target"));
		OUT_RXArray32(OUT_CB_AFSCallBack(cursor));
		break;
	}
}

/*
 * PROT Helpers
 */
static void
dissect_prot_reply(ptvcursor_t *cursor, struct rxinfo *rxinfo, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 504: /* name to id */
				{
					unsigned int i, size;

					size = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
					ptvcursor_add(cursor, hf_afs_prot_count, 4, ENC_BIG_ENDIAN);

					for (i=0; i<size; i++)
					{
						ptvcursor_add(cursor, hf_afs_prot_id, 4, ENC_BIG_ENDIAN);
					}
				}
				break;
			case 505: /* id to name */
				{
					unsigned int i, size;

					size = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
					ptvcursor_add(cursor, hf_afs_prot_count, 4, ENC_BIG_ENDIAN);

					for (i=0; i<size; i++)
					{
						OUT_RXStringV(cursor, hf_afs_prot_name, PRNAMEMAX);
					}
				}
				break;
			case 508: /* get cps */
			case 514: /* list elements */
			case 517: /* list owned */
			case 518: /* get cps2 */
			case 519: /* get host cps */
				{
					unsigned int i, size;

					size = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
					ptvcursor_add(cursor, hf_afs_prot_count, 4, ENC_BIG_ENDIAN);

					for (i=0; i<size; i++)
					{
						ptvcursor_add(cursor, hf_afs_prot_id, 4, ENC_BIG_ENDIAN);
					}
				}
				break;
			case 510: /* list max */
				ptvcursor_add(cursor, hf_afs_prot_maxuid, 4, ENC_BIG_ENDIAN);
				ptvcursor_add(cursor, hf_afs_prot_maxgid, 4, ENC_BIG_ENDIAN);
				break;
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		ptvcursor_add(cursor, hf_afs_prot_errcode, 4, ENC_BIG_ENDIAN);
	}
}

static void
dissect_prot_request(ptvcursor_t *cursor, struct rxinfo *rxinfo _U_, int opcode)
{
	ptvcursor_advance(cursor, 4); /* skip the opcode */

	switch ( opcode )
	{
		case 500: /* new user */
			OUT_RXString(cursor, hf_afs_prot_name_uint_string);
			ptvcursor_add(cursor, hf_afs_prot_id, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_prot_oldid, 4, ENC_BIG_ENDIAN);
			break;
		case 501: /* where is it */
		case 506: /* delete */
		case 508: /* get cps */
		case 512: /* list entry */
		case 514: /* list elements */
		case 517: /* list owned */
		case 519: /* get host cps */
			ptvcursor_add(cursor, hf_afs_prot_id, 4, ENC_BIG_ENDIAN);
			break;
		case 502: /* dump entry */
			ptvcursor_add(cursor, hf_afs_prot_pos, 4, ENC_BIG_ENDIAN);
			break;
		case 503: /* add to group */
		case 507: /* remove from group */
		case 515: /* is a member of? */
			ptvcursor_add(cursor, hf_afs_prot_uid, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_prot_gid, 4, ENC_BIG_ENDIAN);
			break;
		case 504: /* name to id */
			{
				unsigned int i, size;

				size = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
				ptvcursor_add(cursor, hf_afs_prot_count, 4, ENC_BIG_ENDIAN);
				for (i=0; i<size; i++)
				{
					OUT_RXStringV(cursor, hf_afs_prot_name,PRNAMEMAX);
				}
			}
			break;
		case 505: /* id to name */
			{
				unsigned int i, size;

				size = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
				ptvcursor_add(cursor, hf_afs_prot_count, 4, ENC_BIG_ENDIAN);

				for (i=0; i<size; i++)
				{
					ptvcursor_add(cursor, hf_afs_prot_id, 4, ENC_BIG_ENDIAN);
				}
			}
			break;
		case 509: /* new entry */
			OUT_RXString(cursor, hf_afs_prot_name_uint_string);
			ptvcursor_add(cursor, hf_afs_prot_flag, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_prot_oldid, 4, ENC_BIG_ENDIAN);
			break;
		case 511: /* set max */
			ptvcursor_add(cursor, hf_afs_prot_id, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_prot_flag, 4, ENC_BIG_ENDIAN);
			break;
		case 513: /* change entry */
			ptvcursor_add(cursor, hf_afs_prot_id, 4, ENC_BIG_ENDIAN);
			OUT_RXString(cursor, hf_afs_prot_name_uint_string);
			ptvcursor_add(cursor, hf_afs_prot_oldid, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_prot_newid, 4, ENC_BIG_ENDIAN);
			break;
		case 520: /* update entry */
			ptvcursor_add(cursor, hf_afs_prot_id, 4, ENC_BIG_ENDIAN);
			OUT_RXString(cursor, hf_afs_prot_name_uint_string);
			break;
	}
}

/*
 * VLDB Helpers
 */
static void
dissect_vldb_reply(ptvcursor_t *cursor, struct rxinfo *rxinfo, int opcode)
{
	static const int * vldb_flags[] = {
		&hf_afs_vldb_flags_rwexists,
		&hf_afs_vldb_flags_roexists,
		&hf_afs_vldb_flags_bkexists,
		&hf_afs_vldb_flags_dfsfileset,
		NULL
	};

	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 510: /* list entry */
				ptvcursor_add(cursor, hf_afs_vldb_count, 4, ENC_BIG_ENDIAN);
				ptvcursor_add(cursor, hf_afs_vldb_nextindex, 4, ENC_BIG_ENDIAN);
				break;
			case 503: /* get entry by id */
			case 504: /* get entry by name */
				{
					int nservers,i,j;
					OUT_RXStringV(cursor, hf_afs_vldb_name, VLNAMEMAX);
					ptvcursor_advance(cursor, 4);
					nservers = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
					ptvcursor_add(cursor, hf_afs_vldb_numservers, 4, ENC_BIG_ENDIAN);
					for (i=0; i<8; i++)
					{
						if ( i<nservers )
						{
							ptvcursor_add(cursor, hf_afs_vldb_server, 4, ENC_BIG_ENDIAN);
						}
						else
						{
							ptvcursor_advance(cursor, 4);
						}
					}
					for (i=0; i<8; i++)
					{
						char *part = wmem_strdup(wmem_packet_scope(), "/vicepa");
						j = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
						if ( i<nservers && j<=25 )
						{
							part[6] = 'a' + (char) j;
							proto_tree_add_string(ptvcursor_tree(cursor), hf_afs_vldb_partition, ptvcursor_tvbuff(cursor),
								ptvcursor_current_offset(cursor), 4, part);
						}
						ptvcursor_advance(cursor, 4);
					}
					ptvcursor_advance(cursor, 8*4);
					ptvcursor_add(cursor, hf_afs_vldb_rwvol, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_rovol, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_bkvol, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_clonevol, 4, ENC_BIG_ENDIAN);
					proto_tree_add_bitmask(ptvcursor_tree(cursor), ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), hf_afs_vldb_flags,
										ett_afs_vldb_flags, vldb_flags, ENC_BIG_ENDIAN);
					ptvcursor_advance(cursor, 4);
				}
				break;
			case 505: /* get new volume id */
				ptvcursor_add(cursor, hf_afs_vldb_id, 4, ENC_BIG_ENDIAN);
				break;
			case 521: /* list entry */
			case 529: /* list entry U */
				ptvcursor_add(cursor, hf_afs_vldb_count, 4, ENC_BIG_ENDIAN);
				ptvcursor_add(cursor, hf_afs_vldb_nextindex, 4, ENC_BIG_ENDIAN);
				break;
			case 518: /* get entry by id n */
			case 519: /* get entry by name N */
				{
					int nservers,i,j;
					OUT_RXStringV(cursor, hf_afs_vldb_name, VLNAMEMAX);
					nservers = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
					ptvcursor_add(cursor, hf_afs_vldb_numservers, 4, ENC_BIG_ENDIAN);
					for (i=0; i<13; i++)
					{
						if ( i<nservers )
						{
							ptvcursor_add(cursor, hf_afs_vldb_server, 4, ENC_BIG_ENDIAN);
						}
						else
						{
							ptvcursor_advance(cursor, 4);
						}
					}
					for (i=0; i<13; i++)
					{
						char *part = wmem_strdup(wmem_packet_scope(), "/vicepa");
						j = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
						if ( i<nservers && j<=25 )
						{
							part[6] = 'a' + (char) j;
							proto_tree_add_string(ptvcursor_tree(cursor), hf_afs_vldb_partition, ptvcursor_tvbuff(cursor),
								ptvcursor_current_offset(cursor), 4, part);
						}
						ptvcursor_advance(cursor, 4);
					}
					ptvcursor_advance(cursor, 13*4);
					ptvcursor_add(cursor, hf_afs_vldb_rwvol, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_rovol, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_bkvol, 4, ENC_BIG_ENDIAN);
				}
				break;
			case 526: /* get entry by id u */
			case 527: /* get entry by name u */
				{
					int nservers,i,j;
					OUT_RXStringV(cursor, hf_afs_vldb_name, VLNAMEMAX);
					nservers = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
					ptvcursor_add(cursor, hf_afs_vldb_numservers, 4, ENC_BIG_ENDIAN);
					for (i=0; i<13; i++)
					{
						if ( i<nservers )
						{
							ptvcursor_add(cursor, hf_afs_vldb_serveruuid, 4*11, ENC_NA);
						}
						else
						{
							ptvcursor_advance(cursor, 4*11);
						}
					}
					for (i=0; i<13; i++)
					{
						if ( i<nservers )
						{
							ptvcursor_add(cursor, hf_afs_vldb_serveruniq, 4, ENC_BIG_ENDIAN);
						}
						else
						{
							ptvcursor_advance(cursor, 4);
						}
					}
					for (i=0; i<13; i++)
					{
						char *part = wmem_strdup(wmem_packet_scope(), "/vicepa");
						j = tvb_get_ntohl(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
						if ( i<nservers && j<=25 )
						{
							part[6] = 'a' + (char) j;
							proto_tree_add_string(ptvcursor_tree(cursor), hf_afs_vldb_partition, ptvcursor_tvbuff(cursor),
								ptvcursor_current_offset(cursor), 4, part);
						}
						ptvcursor_advance(cursor, 4);
					}
					for (i=0; i<13; i++)
					{
						if ( i<nservers )
						{
							ptvcursor_add(cursor, hf_afs_vldb_serverflags, 4, ENC_BIG_ENDIAN);
						}
						else
						{
							ptvcursor_advance(cursor, 4);
						}
					}
					ptvcursor_add(cursor, hf_afs_vldb_rwvol, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_rovol, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_bkvol, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_clonevol, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_flags, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_spare1, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_spare2, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_spare3, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_spare4, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_spare5, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_spare6, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_spare7, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_spare8, 4, ENC_BIG_ENDIAN);
					ptvcursor_add(cursor, hf_afs_vldb_spare9, 4, ENC_BIG_ENDIAN);
				}
				break;
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		ptvcursor_add(cursor, hf_afs_vldb_errcode, 4, ENC_BIG_ENDIAN);
	}
}

static void
dissect_vldb_request(ptvcursor_t *cursor, struct rxinfo *rxinfo _U_, int opcode)
{
	ptvcursor_advance(cursor, 4); /* skip the opcode */

	switch ( opcode )
	{
		case 501: /* create new volume */
		case 517: /* create entry N */
			OUT_RXStringV(cursor, hf_afs_vldb_name, VLNAMEMAX);
			break;
		case 502: /* delete entry */
		case 503: /* get entry by id */
		case 507: /* update entry */
		case 508: /* set lock */
		case 509: /* release lock */
		case 518: /* get entry by id */
			ptvcursor_add(cursor, hf_afs_vldb_id, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_vldb_type, 4, ENC_BIG_ENDIAN);
			break;
		case 504: /* get entry by name */
		case 519: /* get entry by name N */
		case 524: /* update entry by name */
		case 527: /* get entry by name U */
			OUT_RXString(cursor, hf_afs_vldb_name_uint_string);
			break;
		case 505: /* get new vol id */
			ptvcursor_add(cursor, hf_afs_vldb_bump, 4, ENC_BIG_ENDIAN);
			break;
		case 506: /* replace entry */
		case 520: /* replace entry N */
			ptvcursor_add(cursor, hf_afs_vldb_id, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_vldb_type, 4, ENC_BIG_ENDIAN);
			OUT_RXStringV(cursor, hf_afs_vldb_name, VLNAMEMAX);
			break;
		case 510: /* list entry */
		case 521: /* list entry N */
			ptvcursor_add(cursor, hf_afs_vldb_index, 4, ENC_BIG_ENDIAN);
			break;
		case 532: /* regaddr */
			ptvcursor_add(cursor, hf_afs_vldb_serveruuid, 4*11, ENC_NA);
			ptvcursor_add(cursor, hf_afs_vldb_spare1, 4, ENC_BIG_ENDIAN);
			OUT_RXArray32(ptvcursor_add(cursor, hf_afs_vldb_serverip, 4, ENC_BIG_ENDIAN));
			break;
	}
}

/*
 * UBIK Helpers
 */
static void
dissect_ubik_reply(ptvcursor_t *cursor, struct rxinfo *rxinfo _U_, int opcode)
{
	switch ( opcode )
	{
		case 10000: /* vote-beacon */
			break;
		case 10001: /* vote-debug-old */
			OUT_UBIK_DebugOld(cursor);
			break;
		case 10002: /* vote-sdebug-old */
			OUT_UBIK_SDebugOld(cursor);
			break;
		case 10003: /* vote-get syncsite */
			break;
		case 10004: /* vote-debug */
			OUT_UBIK_DebugOld(cursor);
			OUT_UBIK_InterfaceAddrs(cursor);
			break;
		case 10005: /* vote-sdebug */
			OUT_UBIK_SDebugOld(cursor);
			OUT_UBIK_InterfaceAddrs(cursor);
			break;
		case 10006: /* vote-xdebug */
			OUT_UBIK_DebugOld(cursor);
			OUT_UBIK_InterfaceAddrs(cursor);
			ptvcursor_add(cursor, hf_afs_ubik_isclone, 4, ENC_BIG_ENDIAN);
			break;
		case 10007: /* vote-xsdebug */
			OUT_UBIK_SDebugOld(cursor);
			OUT_UBIK_InterfaceAddrs(cursor);
			ptvcursor_add(cursor, hf_afs_ubik_isclone, 4, ENC_BIG_ENDIAN);
			break;
		case 20000: /* disk-begin */
			break;
		case 20004: /* get version */
			OUT_UBIKVERSION(cursor, "DB Version");
			break;
		case 20010: /* disk-probe */
			break;
		case 20012: /* disk-interfaceaddr */
			OUT_UBIK_InterfaceAddrs(cursor);
			break;
	}
}

static void
dissect_ubik_request(ptvcursor_t *cursor, struct rxinfo *rxinfo _U_, int opcode)
{
	ptvcursor_advance(cursor, 4); /* skip the opcode */

	switch ( opcode )
	{
		case 10000: /* vote-beacon */
			ptvcursor_add(cursor, hf_afs_ubik_state, 4, ENC_BIG_ENDIAN);
			OUT_TIMESECS(cursor, hf_afs_ubik_votestart);
			OUT_UBIKVERSION(cursor, "DB Version");
			OUT_UBIKVERSION(cursor, "TID");
			break;
		case 10001: /* vote-debug-old */
			break;
		case 10002: /* vote-sdebug-old */
			ptvcursor_add(cursor, hf_afs_ubik_site, 4, ENC_BIG_ENDIAN);
			break;
		case 10003: /* vote-get sync site */
			ptvcursor_add(cursor, hf_afs_ubik_site, 4, ENC_BIG_ENDIAN);
			break;
		case 10004: /* vote-debug */
		case 10005: /* vote-sdebug */
			ptvcursor_add(cursor, hf_afs_ubik_site, 4, ENC_BIG_ENDIAN);
			break;
		case 20000: /* disk-begin */
			OUT_UBIKVERSION(cursor, "TID");
			break;
		case 20001: /* disk-commit */
			OUT_UBIKVERSION(cursor, "TID");
			break;
		case 20002: /* disk-lock */
			OUT_UBIKVERSION(cursor, "TID");
			ptvcursor_add(cursor, hf_afs_ubik_file, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_ubik_pos, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_ubik_length, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_ubik_locktype, 4, ENC_BIG_ENDIAN);
			break;
		case 20003: /* disk-write */
			OUT_UBIKVERSION(cursor, "TID");
			ptvcursor_add(cursor, hf_afs_ubik_file, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_ubik_pos, 4, ENC_BIG_ENDIAN);
			break;
		case 20004: /* disk-get version */
			break;
		case 20005: /* disk-get file */
			ptvcursor_add(cursor, hf_afs_ubik_file, 4, ENC_BIG_ENDIAN);
			break;
		case 20006: /* disk-send file */
			ptvcursor_add(cursor, hf_afs_ubik_file, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_ubik_length, 4, ENC_BIG_ENDIAN);
			OUT_UBIKVERSION(cursor, "DB Version");
			break;
		case 20007: /* disk-abort */
		case 20008: /* disk-release locks */
		case 20010: /* disk-probe */
			break;
		case 20009: /* disk-truncate */
			OUT_UBIKVERSION(cursor, "TID");
			ptvcursor_add(cursor, hf_afs_ubik_file, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_afs_ubik_length, 4, ENC_BIG_ENDIAN);
			break;
		case 20011: /* disk-writev */
			OUT_UBIKVERSION(cursor, "TID");
			break;
		case 20012: /* disk-interfaceaddr */
			OUT_UBIK_InterfaceAddrs(cursor);
			break;
		case 20013: /* disk-set version */
			OUT_UBIKVERSION(cursor, "TID");
			OUT_UBIKVERSION(cursor, "Old DB Version");
			OUT_UBIKVERSION(cursor, "New DB Version");
			break;
	}
}

/*
 * BACKUP Helpers
 */
static void
dissect_backup_reply(ptvcursor_t *cursor, struct rxinfo *rxinfo, int opcode)
{
	if ( rxinfo->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
		}
	}
	else if ( rxinfo->type == RX_PACKET_TYPE_ABORT )
	{
		ptvcursor_add(cursor, hf_afs_backup_errcode, 4, ENC_BIG_ENDIAN);
	}
}

static void
dissect_backup_request(ptvcursor_t *cursor, struct rxinfo *rxinfo _U_, int opcode)
{
	ptvcursor_advance(cursor, 4); /* skip the opcode */

	switch ( opcode )
	{
	}
}


/*
 * Dissection routines
 */

static int
dissect_afs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	struct rxinfo *rxinfo = (struct rxinfo *)data;
	int reply = 0;
	conversation_t *conversation;
	struct afs_request_key request_key, *new_request_key;
	struct afs_request_val *request_val=NULL;
	proto_tree      *afs_tree, *afs_op_tree, *ti;
	proto_item		*hidden_item;
	int port, node, typenode, opcode;
	value_string_ext *vals_ext;
	int offset = 0;
	nstime_t delta_ts;
	guint8 save_fragmented;
	int reassembled = 0;
	ptvcursor_t *cursor;

	void (*dissector)(ptvcursor_t *cursor, struct rxinfo *rxinfo, int opcode);

	/* Reject the packet if data is NULL */
	if (data == NULL)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "AFS (RX)");
	col_clear(pinfo->cinfo, COL_INFO);

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
	conversation = find_or_create_conversation(pinfo);

	request_key.conversation = conversation->conv_index;
	request_key.service = rxinfo->serviceid;
	request_key.epoch = rxinfo->epoch;
	request_key.cid = rxinfo->cid;
	request_key.callnumber = rxinfo->callnumber;

	request_val = (struct afs_request_val *) g_hash_table_lookup(
		afs_request_hash, &request_key);

	/* only allocate a new hash element when it's a request */
	opcode = 0;
	if(!pinfo->fd->flags.visited){
		if ( !request_val && !reply) {
			new_request_key = wmem_new(wmem_file_scope(), struct afs_request_key);
			*new_request_key = request_key;

			request_val = wmem_new(wmem_file_scope(), struct afs_request_val);
			request_val -> opcode = tvb_get_ntohl(tvb, offset);
			request_val -> req_num = pinfo->num;
			request_val -> rep_num = 0;
			request_val -> req_time = pinfo->abs_ts;

			g_hash_table_insert(afs_request_hash, new_request_key,
				request_val);
		}
		if( request_val && reply ) {
			request_val -> rep_num = pinfo->num;
		}
	}

	if ( request_val ) {
		opcode = request_val->opcode;
	}


	node = 0;
	typenode = 0;
	vals_ext = NULL;
	dissector = NULL;
	switch (port) {
		case AFS_PORT_FS:
			typenode = hf_afs_fs;
			node = hf_afs_fs_opcode;
			vals_ext = &fs_req_ext;
			dissector = reply ? dissect_fs_reply : dissect_fs_request;
			break;
		case AFS_PORT_CB:
			typenode = hf_afs_cb;
			node = hf_afs_cb_opcode;
			vals_ext = &cb_req_ext;
			dissector = reply ? dissect_cb_reply : dissect_cb_request;
			break;
		case AFS_PORT_PROT:
			typenode = hf_afs_prot;
			node = hf_afs_prot_opcode;
			vals_ext = &prot_req_ext;
			dissector = reply ? dissect_prot_reply : dissect_prot_request;
			break;
		case AFS_PORT_VLDB:
			typenode = hf_afs_vldb;
			node = hf_afs_vldb_opcode;
			vals_ext = &vldb_req_ext;
			dissector = reply ? dissect_vldb_reply : dissect_vldb_request;
			break;
		case AFS_PORT_KAUTH:
			typenode = hf_afs_kauth;
			node = hf_afs_kauth_opcode;
			vals_ext = &kauth_req_ext;
			dissector = reply ? dissect_kauth_reply : dissect_kauth_request;
			break;
		case AFS_PORT_VOL:
			typenode = hf_afs_vol;
			node = hf_afs_vol_opcode;
			vals_ext = &vol_req_ext;
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
			vals_ext = &bos_req_ext;
			dissector = reply ? dissect_bos_reply : dissect_bos_request;
			break;
		case AFS_PORT_UPDATE:
			typenode = hf_afs_update;
			node = hf_afs_update_opcode;
			vals_ext = &update_req_ext;
			/* dissector = reply ? dissect_update_reply : dissect_update_request; */
			break;
		case AFS_PORT_RMTSYS:
			typenode = hf_afs_rmtsys;
			node = hf_afs_rmtsys_opcode;
			vals_ext = &rmtsys_req_ext;
			/* dissector = reply ? dissect_rmtsys_reply : dissect_rmtsys_request; */
			break;
		case AFS_PORT_BACKUP:
			typenode = hf_afs_backup;
			node = hf_afs_backup_opcode;
			vals_ext = &backup_req_ext;
			dissector = reply ? dissect_backup_reply : dissect_backup_request;
			break;
	}

	if ( (opcode >= VOTE_LOW && opcode <= VOTE_HIGH) ||
		(opcode >= DISK_LOW && opcode <= DISK_HIGH) ) {
		typenode = hf_afs_ubik;
		node = hf_afs_ubik_opcode;
		vals_ext = &ubik_req_ext;
		dissector = reply ? dissect_ubik_reply : dissect_ubik_request;
	}


	if ( VALID_OPCODE(opcode) ) {
		if ( vals_ext ) {
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s%s %s: %s (%d)",
				typenode == hf_afs_ubik ? "UBIK-" : "",
				val_to_str_ext(port, &port_types_short_ext, "Unknown(%d)"),
				reply ? "Reply" : "Request",
				val_to_str_ext(opcode, vals_ext, "Unknown(%d)"), opcode);
		} else {
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s%s %s: Unknown(%d)",
				typenode == hf_afs_ubik ? "UBIK-" : "",
				val_to_str_ext(port, &port_types_short_ext, "Unknown(%d)"),
				reply ? "Reply" : "Request",
				opcode);
		}
	} else {
		col_add_fstr(pinfo->cinfo, COL_INFO, "Encrypted %s %s",
			val_to_str_ext(port, &port_types_short_ext, "Unknown(%d)"),
			reply ? "Reply" : "Request"
			);
	}

	ti = proto_tree_add_item(tree, proto_afs, tvb, offset,
			tvb_reported_length_remaining(tvb, offset),
			ENC_NA);
	afs_tree = proto_item_add_subtree(ti, ett_afs);

	save_fragmented = pinfo->fragmented;
	if( (! (rxinfo->flags & RX_LAST_PACKET) || rxinfo->seq > 1 )) {   /* Fragmented */
		tvbuff_t * new_tvb = NULL;
		fragment_head * frag_msg = NULL;
		guint32 afs_seqid = rxinfo->callnumber ^ rxinfo->cid;
		pinfo->fragmented = TRUE;

		frag_msg = fragment_add_seq_check(&afs_reassembly_table,
				tvb, offset, pinfo, afs_seqid, NULL,
				rxinfo->seq-1, tvb_captured_length_remaining(tvb, offset),
				! ( rxinfo->flags & RX_LAST_PACKET ) );

		new_tvb = process_reassembled_data( tvb, offset, pinfo, "Reassembled RX", frag_msg,
				&afs_frag_items, NULL, afs_tree );

		if (new_tvb) {
			tvb = new_tvb;
			reassembled = 1;
			col_append_str(pinfo->cinfo, COL_INFO, " [AFS reassembled]");
		} else {
			col_set_str(pinfo->cinfo, COL_INFO, "[AFS segment of a reassembled PDU]");
			return tvb_captured_length(tvb);
		}
	}

	pinfo->fragmented = save_fragmented;

	if (tree) {
		proto_tree_add_uint_format_value(afs_tree, hf_afs_service, tvb, 0, 0,
			opcode, "%s%s%s %s",
			VALID_OPCODE(opcode) ? "" : "Encrypted ",
			typenode == hf_afs_ubik ? "UBIK - " : "",
			val_to_str_ext(port, &port_types_ext, "Unknown(%d)"),
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
			nstime_delta(&delta_ts, &pinfo->abs_ts, &request_val->req_time);
			proto_tree_add_time(afs_tree, hf_afs_time, tvb, offset, 0,
				&delta_ts);
		}


		if ( VALID_OPCODE(opcode) ) {
			/* until we do cache, can't handle replies */
			ti = NULL;
			if ( !reply && node != 0 ) {
				if ( rxinfo->seq == 1 || reassembled )
				{
					ti = proto_tree_add_uint(afs_tree,
						node, tvb, offset, 4, opcode);
				} else {
					ti = proto_tree_add_uint(afs_tree,
						node, tvb, 0, 0, opcode);
				}
				afs_op_tree = proto_item_add_subtree(ti, ett_afs_op);
			} else if ( reply && node != 0 ) {
				/* the opcode isn't in this packet */
				ti = proto_tree_add_uint(afs_tree,
					node, tvb, 0, 0, opcode);
				afs_op_tree = proto_item_add_subtree(ti, ett_afs_op);
			} else {
				afs_op_tree = proto_tree_add_subtree(afs_tree, tvb, 0, 0, ett_afs_op, &ti, "Operation: Unknown");
			}

			if ( typenode != 0 ) {
				/* indicate the type of request */
				hidden_item = proto_tree_add_boolean(afs_tree, typenode, tvb, offset, 0, 1);
				PROTO_ITEM_SET_HIDDEN(hidden_item);
			}

			/* Process the packet according to what service it is */
			/* Only for first packet in an rx data stream or the full reassembled stream */
			if ( dissector && ( rxinfo->seq == 1 || reassembled ) ) {
				cursor = ptvcursor_new(afs_op_tree, tvb, offset);
				(*dissector)(cursor, rxinfo, opcode);
			}
		}
	}

	/* if it's the last packet, and it's a reply, remove opcode
		from hash */
	/* ignoring for now, I'm not sure how the chunk deallocation works */
	if ( rxinfo->flags & RX_LAST_PACKET && reply ){

	}

	return tvb_captured_length(tvb);
}

/*
 * Registration code for registering the protocol and fields
 */

void
proto_register_afs(void)
{
	static hf_register_info hf[] = {
	{ &hf_afs_fs, {	"File Server", "afs.fs",
		FT_BOOLEAN, BASE_NONE, 0, 0x0, NULL, HFILL }},
	{ &hf_afs_cb, {	"Callback", "afs.cb",
		FT_BOOLEAN, BASE_NONE, 0, 0x0, NULL, HFILL }},
	{ &hf_afs_prot, { "Protection", "afs.prot",
		FT_BOOLEAN, BASE_NONE, 0, 0x0, "Protection Server", HFILL }},
	{ &hf_afs_vldb, { "VLDB", "afs.vldb",
		FT_BOOLEAN, BASE_NONE, 0, 0x0, "Volume Location Database Server", HFILL }},
	{ &hf_afs_kauth, { "KAuth", "afs.kauth",
		FT_BOOLEAN, BASE_NONE, 0, 0x0, "Kerberos Auth Server", HFILL }},
	{ &hf_afs_vol, { "Volume Server", "afs.vol",
		FT_BOOLEAN, BASE_NONE, 0, 0x0, NULL, HFILL }},
	{ &hf_afs_error, { "Error", "afs.error",
		FT_BOOLEAN, BASE_NONE, 0, 0x0, NULL, HFILL }},
	{ &hf_afs_bos, { "BOS", "afs.bos",
		FT_BOOLEAN, BASE_NONE, 0, 0x0, "Basic Oversee Server", HFILL }},
	{ &hf_afs_update, { "Update", "afs.update",
		FT_BOOLEAN, BASE_NONE, 0, 0x0, "Update Server", HFILL }},
	{ &hf_afs_rmtsys, { "Rmtsys", "afs.rmtsys",
		FT_BOOLEAN, BASE_NONE, 0, 0x0, NULL, HFILL }},
	{ &hf_afs_ubik, { "Ubik", "afs.ubik",
		FT_BOOLEAN, BASE_NONE, 0, 0x0, NULL, HFILL }},
	{ &hf_afs_backup, { "Backup", "afs.backup",
		FT_BOOLEAN, BASE_NONE, 0, 0x0, "Backup Server", HFILL }},
	{ &hf_afs_service, { "Service", "afs.service",
		FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},
	{ &hf_afs_fs_opcode, { "Operation", "afs.fs.opcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING,
		&fs_req_ext, 0, NULL, HFILL }},
	{ &hf_afs_cb_opcode, { "Operation", "afs.cb.opcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING,
		&cb_req_ext, 0, NULL, HFILL }},
	{ &hf_afs_prot_opcode, { "Operation", "afs.prot.opcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING,
		&prot_req_ext, 0, NULL, HFILL }},
	{ &hf_afs_vldb_opcode, { "Operation", "afs.vldb.opcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING,
		&vldb_req_ext, 0, NULL, HFILL }},
	{ &hf_afs_kauth_opcode, { "Operation", "afs.kauth.opcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING,
		&kauth_req_ext, 0, NULL, HFILL }},
	{ &hf_afs_vol_opcode, { "Operation", "afs.vol.opcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING,
		&vol_req_ext, 0, NULL, HFILL }},
	{ &hf_afs_bos_opcode, { "Operation", "afs.bos.opcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING,
		&bos_req_ext, 0, NULL, HFILL }},
	{ &hf_afs_update_opcode, { "Operation", "afs.update.opcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING,
		&update_req_ext, 0, NULL, HFILL }},
	{ &hf_afs_rmtsys_opcode, { "Operation", "afs.rmtsys.opcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING,
		&rmtsys_req_ext, 0, NULL, HFILL }},

	{ &hf_afs_error_opcode, { "Operation", "afs.error.opcode",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_backup_opcode, { "Operation", "afs.backup.opcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING,
		&backup_req_ext, 0, NULL, HFILL }},
	{ &hf_afs_ubik_opcode, { "Operation", "afs.ubik.opcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING,
		&ubik_req_ext, 0, NULL, HFILL }},


/* File Server Fields */
	{ &hf_afs_fs_fid_volume, { "FileID (Volume)", "afs.fs.fid.volume",
		FT_UINT32, BASE_DEC, 0, 0, "File ID (Volume)", HFILL }},
	{ &hf_afs_fs_fid_vnode, { "FileID (VNode)", "afs.fs.fid.vnode",
		FT_UINT32, BASE_DEC, 0, 0, "File ID (VNode)", HFILL }},
	{ &hf_afs_fs_fid_uniqifier, { "FileID (Uniqifier)", "afs.fs.fid.uniq",
		FT_UINT32, BASE_DEC, 0, 0, "File ID (Uniqifier)", HFILL }},
	{ &hf_afs_fs_offset, { "Offset", "afs.fs.offset",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_length, { "Length", "afs.fs.length",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_flength, { "FLength", "afs.fs.flength",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_offset64, { "Offset64", "afs.fs.offset64",
		FT_UINT64, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_length64, { "Length64", "afs.fs.length64",
		FT_UINT64, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_flength64, { "FLength64", "afs.fs.flength64",
		FT_UINT64, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_errcode, { "Error Code", "afs.fs.errcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING, &afs_errors_ext, 0, NULL, HFILL }},
	{ &hf_afs_fs_data, { "Data", "afs.fs.data",
		FT_BYTES, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_token, { "Token", "afs.fs.token",
		FT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_oldname, { "Old Name", "afs.fs.oldname",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_newname, { "New Name", "afs.fs.newname",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_name, { "Name", "afs.fs.name",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_symlink_name, { "Symlink Name", "afs.fs.symlink.name",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_symlink_content, { "Symlink Content", "afs.fs.symlink.content",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_volid, { "Volume ID", "afs.fs.volid",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_volname, { "Volume Name", "afs.fs.volname",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_timestamp, { "Timestamp", "afs.fs.timestamp",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_offlinemsg, { "Offline Message", "afs.fs.offlinemsg",
		FT_UINT_STRING, BASE_NONE, 0, 0, "Volume Name", HFILL }},
	{ &hf_afs_fs_motd, { "Message of the Day", "afs.fs.motd",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_xstats_version, { "XStats Version", "afs.fs.xstats.version",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_xstats_clientversion, { "Client Version", "afs.fs.xstats.clientversion",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_xstats_collnumber, { "Collection Number", "afs.fs.xstats.collnumber",
		FT_UINT32, BASE_DEC, VALS(xstat_collections), 0, NULL, HFILL }},
	{ &hf_afs_fs_xstats_timestamp, { "XStats Timestamp", "afs.fs.xstats.timestamp",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_cps_spare1, { "CPS Spare1", "afs.fs.cps.spare1",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_cps_spare2, { "CPS Spare2", "afs.fs.cps.spare2",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_cps_spare3, { "CPS Spare3", "afs.fs.cps.spare3",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_vicelocktype, { "Vice Lock Type", "afs.fs.vicelocktype",
		FT_UINT32, BASE_DEC, VALS(vice_lock_types), 0, NULL, HFILL }},
/* XXX - is this an IP address? */
	{ &hf_afs_fs_viceid, { "Vice ID", "afs.fs.viceid",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_ipaddr, { "IP Addr", "afs.fs.ipaddr",
		FT_IPv4, BASE_NONE, 0, 0, NULL, HFILL }},

	{ &hf_afs_fs_status_mask, { "Mask", "afs.fs.status.mask",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_mask_setmodtime, { "Set Modification Time", "afs.fs.status.mask.setmodtime",
		FT_BOOLEAN, 32, 0, 0x00000001, NULL, HFILL }},
	{ &hf_afs_fs_status_mask_setowner, { "Set Owner", "afs.fs.status.mask.setowner",
		FT_BOOLEAN, 32, 0, 0x00000002, NULL, HFILL }},
	{ &hf_afs_fs_status_mask_setgroup, { "Set Group", "afs.fs.status.mask.setgroup",
		FT_BOOLEAN, 32, 0, 0x00000004, NULL, HFILL }},
	{ &hf_afs_fs_status_mask_setmode, { "Set Mode", "afs.fs.status.mask.setmode",
		FT_BOOLEAN, 32, 0, 0x00000008, NULL, HFILL }},
	{ &hf_afs_fs_status_mask_setsegsize, { "Set Segment Size", "afs.fs.status.mask.setsegsize",
		FT_BOOLEAN, 32, 0, 0x00000010, NULL, HFILL }},
	{ &hf_afs_fs_status_mask_fsync, { "FSync", "afs.fs.status.mask.fsync",
		FT_BOOLEAN, 32, 0, 0x00000400, NULL, HFILL }},

	{ &hf_afs_fs_status_clientmodtime, { "Client Modification Time", "afs.fs.status.clientmodtime",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_servermodtime, { "Server Modification Time", "afs.fs.status.servermodtime",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_owner, { "Owner", "afs.fs.status.owner",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_group, { "Group", "afs.fs.status.group",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_mode, { "Unix Mode", "afs.fs.status.mode",
		FT_UINT32, BASE_OCT, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_segsize, { "Segment Size", "afs.fs.status.segsize",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_interfaceversion, { "Interface Version", "afs.fs.status.interfaceversion",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_filetype, { "File Type", "afs.fs.status.filetype",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_author, { "Author", "afs.fs.status.author",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_calleraccess, { "Caller Access", "afs.fs.status.calleraccess",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_anonymousaccess, { "Anonymous Access", "afs.fs.status.anonymousaccess",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_parentvnode, { "Parent VNode", "afs.fs.status.parentvnode",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_parentunique, { "Parent Unique", "afs.fs.status.parentunique",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_dataversion, { "Data Version", "afs.fs.status.dataversion",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_dataversionhigh, { "Data Version (High)", "afs.fs.status.dataversionhigh",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_linkcount, { "Link Count", "afs.fs.status.linkcount",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_spare2, { "Spare 2", "afs.fs.status.spare2",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_spare3, { "Spare 3", "afs.fs.status.spare3",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_spare4, { "Spare 4", "afs.fs.status.spare4",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_synccounter, { "Sync Counter", "afs.fs.status.synccounter",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_status_length, { "Length", "afs.fs.status.length",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},


	{ &hf_afs_fs_volsync_spare1, { "Volume Creation Timestamp", "afs.fs.volsync.spare1",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_volsync_spare2, { "Spare 2", "afs.fs.volsync.spare2",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_volsync_spare3, { "Spare 3", "afs.fs.volsync.spare3",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_volsync_spare4, { "Spare 4", "afs.fs.volsync.spare4",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_volsync_spare5, { "Spare 5", "afs.fs.volsync.spare5",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_volsync_spare6, { "Spare 6", "afs.fs.volsync.spare6",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},


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
		FT_STRING, BASE_NONE, 0, 0, "ACL Entity (User/Group)", HFILL }},
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
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_callback_expires, { "Expires", "afs.fs.callback.expires",
		FT_RELATIVE_TIME, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_fs_callback_type, { "Type", "afs.fs.callback.type",
		FT_UINT32, BASE_DEC, VALS(cb_types), 0, NULL, HFILL }},

/* BOS Server Fields */
	{ &hf_afs_bos_errcode, { "Error Code", "afs.bos.errcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING, &afs_errors_ext, 0, NULL, HFILL }},
	{ &hf_afs_bos_type, { "Type", "afs.bos.type",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_content, { "Content", "afs.bos.content",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_data, { "Data", "afs.bos.data",
		FT_BYTES, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_path, { "Path", "afs.bos.path",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_parm, { "Parm", "afs.bos.parm",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_error, { "Error", "afs.bos.error",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_spare1, { "Spare1", "afs.bos.spare1",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_spare2, { "Spare2", "afs.bos.spare2",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_spare3, { "Spare3", "afs.bos.spare3",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_file, { "File", "afs.bos.file",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_cmd, { "Command", "afs.bos.cmd",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_key, { "Key", "afs.bos.key",
		FT_BYTES, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_user, { "User", "afs.bos.user",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_instance, { "Instance", "afs.bos.instance",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_status, { "Status", "afs.bos.status",
		FT_INT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_statusdesc, { "Status Description", "afs.bos.statusdesc",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_num, { "Number", "afs.bos.number",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_size, { "Size", "afs.bos.size",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_flags, { "Flags", "afs.bos.flags",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_date, { "Date", "afs.bos.date",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_kvno, { "Key Version Number", "afs.bos.kvno",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_cell, { "Cell", "afs.bos.cell",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_host, { "Host", "afs.bos.host",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_newtime, { "New Time", "afs.bos.newtime",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_baktime, { "Backup Time", "afs.bos.baktime",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_oldtime, { "Old Time", "afs.bos.oldtime",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_keymodtime, { "Key Modification Time", "afs.bos.keymodtime",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_keychecksum, { "Key Checksum", "afs.bos.keychecksum",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_bos_keyspare2, { "Key Spare 2", "afs.bos.keyspare2",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},


/* KAUTH Server Fields */
	{ &hf_afs_kauth_errcode, { "Error Code", "afs.kauth.errcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING, &afs_errors_ext, 0, NULL, HFILL }},
	{ &hf_afs_kauth_princ, { "Principal", "afs.kauth.princ",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_kauth_realm, { "Realm", "afs.kauth.realm",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_kauth_domain, { "Domain", "afs.kauth.domain",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_kauth_name, { "Name", "afs.kauth.name",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_kauth_data, { "Data", "afs.kauth.data",
		FT_BYTES, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_kauth_kvno, { "Key Version Number", "afs.kauth.kvno",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},

/* VOL Server Fields */
	{ &hf_afs_vol_errcode, { "Error Code", "afs.vol.errcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING, &afs_errors_ext, 0, NULL, HFILL }},
	{ &hf_afs_vol_id, { "Volume ID", "afs.vol.id",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vol_count, { "Volume Count", "afs.vol.count",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vol_name, { "Volume Name", "afs.vol.name",
		FT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},

/* VLDB Server Fields */
	{ &hf_afs_vldb_errcode, { "Error Code", "afs.vldb.errcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING, &afs_errors_ext, 0, NULL, HFILL }},
	{ &hf_afs_vldb_type, { "Volume Type", "afs.vldb.type",
		FT_UINT32, BASE_HEX, VALS(volume_types), 0, NULL, HFILL }},
	{ &hf_afs_vldb_id, { "Volume ID", "afs.vldb.id",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_bump, { "Bumped Volume ID", "afs.vldb.bump",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_index, { "Volume Index", "afs.vldb.index",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_count, { "Volume Count", "afs.vldb.count",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_numservers, { "Number of Servers", "afs.vldb.numservers",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_nextindex, { "Next Volume Index", "afs.vldb.nextindex",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_rovol, { "Read-Only Volume ID", "afs.vldb.rovol",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_rwvol, { "Read-Write Volume ID", "afs.vldb.rwvol",
		FT_UINT32, BASE_DEC, 0, 0, "Read-Only Volume ID", HFILL }},
	{ &hf_afs_vldb_bkvol, { "Backup Volume ID", "afs.vldb.bkvol",
		FT_UINT32, BASE_DEC, 0, 0, "Read-Only Volume ID", HFILL }},
	{ &hf_afs_vldb_clonevol, { "Clone Volume ID", "afs.vldb.clonevol",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_name, { "Volume Name", "afs.vldb.name",
		FT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_name_uint_string, { "Volume Name", "afs.vldb.name",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_partition, { "Partition", "afs.vldb.partition",
		FT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_server, { "Server", "afs.vldb.server",
		FT_IPv4, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_serveruuid, { "Server UUID", "afs.vldb.serveruuid",
		FT_BYTES, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_serveruniq, { "Server Unique Address", "afs.vldb.serveruniq",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_serverflags, { "Server Flags", "afs.vldb.serverflags",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_serverip, { "Server IP", "afs.vldb.serverip",
		FT_IPv4, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_flags, { "Flags", "afs.vldb.flags",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},

	{ &hf_afs_vldb_flags_rwexists, { "Read/Write Exists", "afs.vldb.flags.rwexists",
		FT_BOOLEAN, 32, 0, 0x1000, NULL, HFILL }},
	{ &hf_afs_vldb_flags_roexists, { "Read-Only Exists", "afs.vldb.flags.roexists",
		FT_BOOLEAN, 32, 0, 0x2000, NULL, HFILL }},
	{ &hf_afs_vldb_flags_bkexists, { "Backup Exists", "afs.vldb.flags.bkexists",
		FT_BOOLEAN, 32, 0, 0x4000, NULL, HFILL }},
	{ &hf_afs_vldb_flags_dfsfileset, { "DFS Fileset", "afs.vldb.flags.dfsfileset",
		FT_BOOLEAN, 32, 0, 0x8000, NULL, HFILL }},

	{ &hf_afs_vldb_spare1, { "Spare 1", "afs.vldb.spare1",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_spare2, { "Spare 2", "afs.vldb.spare2",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_spare3, { "Spare 3", "afs.vldb.spare3",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_spare4, { "Spare 4", "afs.vldb.spare4",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_spare5, { "Spare 5", "afs.vldb.spare5",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_spare6, { "Spare 6", "afs.vldb.spare6",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_spare7, { "Spare 7", "afs.vldb.spare7",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_spare8, { "Spare 8", "afs.vldb.spare8",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_vldb_spare9, { "Spare 9", "afs.vldb.spare9",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},

/* BACKUP Server Fields */
	{ &hf_afs_backup_errcode, { "Error Code", "afs.backup.errcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING, &afs_errors_ext, 0, NULL, HFILL }},

/* CB Server Fields */
	{ &hf_afs_cb_errcode, { "Error Code", "afs.cb.errcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING, &afs_errors_ext, 0, NULL, HFILL }},
	{ &hf_afs_cb_callback_version, { "Version", "afs.cb.callback.version",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_cb_callback_expires, { "Expires", "afs.cb.callback.expires",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_cb_callback_type, { "Type", "afs.cb.callback.type",
		FT_UINT32, BASE_DEC, VALS(cb_types), 0, NULL, HFILL }},
	{ &hf_afs_cb_fid_volume, { "FileID (Volume)", "afs.cb.fid.volume",
		FT_UINT32, BASE_DEC, 0, 0, "File ID (Volume)", HFILL }},
	{ &hf_afs_cb_fid_vnode, { "FileID (VNode)", "afs.cb.fid.vnode",
		FT_UINT32, BASE_DEC, 0, 0, "File ID (VNode)", HFILL }},
	{ &hf_afs_cb_fid_uniqifier, { "FileID (Uniqifier)", "afs.cb.fid.uniq",
		FT_UINT32, BASE_DEC, 0, 0, "File ID (Uniqifier)", HFILL }},

/* CM Fields  */
	{ &hf_afs_cm_uuid, { "UUID", "afs.cm.uuid",
		FT_BYTES, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_cm_numint, { "Number of Interfaces", "afs.cm.numint",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_cm_ipaddr, { "IP Address", "afs.cm.ipaddr",
		FT_IPv4, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_cm_netmask, { "Netmask", "afs.cm.netmask",
		FT_IPv4, BASE_NETMASK, 0, 0, NULL, HFILL }},
	{ &hf_afs_cm_mtu, { "MTU", "afs.cm.mtu",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},

	{ &hf_afs_cm_numcap, { "Number of Capability Words", "afs.cm.numcap",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_cm_capabilities, { "Capabilities", "afs.cm.capabilities",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_cm_cap_errortrans, { "ERRORTRANS", "afs.cm.capabilities.errortrans",
		FT_BOOLEAN, 32, 0, 0x0001, NULL, HFILL }},

/* PROT Server Fields */
	{ &hf_afs_prot_errcode, { "Error Code", "afs.prot.errcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING, &afs_errors_ext, 0, NULL, HFILL }},
	{ &hf_afs_prot_name, { "Name", "afs.prot.name",
		FT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_prot_name_uint_string, { "Name", "afs.prot.name",
		FT_UINT_STRING, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_prot_id, { "ID", "afs.prot.id",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_prot_oldid, { "Old ID", "afs.prot.oldid",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_prot_newid, { "New ID", "afs.prot.newid",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_prot_gid, { "Group ID", "afs.prot.gid",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_prot_uid, { "User ID", "afs.prot.uid",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_prot_count, { "Count", "afs.prot.count",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_prot_maxgid, { "Maximum Group ID", "afs.prot.maxgid",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_prot_maxuid, { "Maximum User ID", "afs.prot.maxuid",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_prot_pos, { "Position", "afs.prot.pos",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_prot_flag, { "Flag", "afs.prot.flag",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},

/* UBIK Fields */
#if 0
	{ &hf_afs_ubik_errcode, { "Error Code", "afs.ubik.errcode",
		FT_UINT32, BASE_DEC|BASE_EXT_STRING, &afs_errors_ext, 0, NULL, HFILL }},
#endif
	{ &hf_afs_ubik_state, { "State", "afs.ubik.state",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_version_epoch, { "Epoch", "afs.ubik.version.epoch",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_version_counter, { "Counter", "afs.ubik.version.counter",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_votestart, { "Vote Started", "afs.ubik.votestart",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
#if 0
	{ &hf_afs_ubik_voteend, { "Vote Ends", "afs.ubik.voteend",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
#endif
	{ &hf_afs_ubik_file, { "File", "afs.ubik.file",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_pos, { "Position", "afs.ubik.position",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_length, { "Length", "afs.ubik.length",
		FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_locktype, { "Lock Type", "afs.ubik.locktype",
		FT_UINT32, BASE_DEC, VALS(ubik_lock_types), 0, NULL, HFILL }},
#if 0
	{ &hf_afs_ubik_votetype, { "Vote Type", "afs.ubik.votetype",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
#endif
	{ &hf_afs_ubik_site, { "Site", "afs.ubik.site",
		FT_IPv4, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_interface, { "Interface Address", "afs.ubik.interface",
		FT_IPv4, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_null_addresses, { "Null Interface Addresses", "afs.ubik.null_addresses",
		FT_NONE, BASE_NONE, 0, 0, NULL, HFILL }},

	{ &hf_afs_ubik_now, { "Now", "afs.ubik.now",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_lastyestime, { "Last Yes Time", "afs.ubik.lastyesttime",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_lastyeshost, { "Last Yes Host", "afs.ubik.lastyeshost",
		FT_IPv4, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_lastyesstate, { "Last Yes State", "afs.ubik.lastyesstate",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_lastyesclaim, { "Last Yes Claim", "afs.ubik.lastyesclaim",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_lowesthost, { "Lowest Host", "afs.ubik.lowesthost",
		FT_IPv4, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_lowesttime, { "Lowest Time", "afs.ubik.lowesttime",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_synchost, { "Sync Host", "afs.ubik.synchost",
		FT_IPv4, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_addr, { "Address", "afs.ubik.addr",
		FT_IPv4, BASE_NONE, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_synctime, { "Sync Time", "afs.ubik.synctime",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_lastvotetime, { "Last Vote Time", "afs.ubik.lastvotetime",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_lastbeaconsent, { "Last Beacon Sent", "afs.ubik.lastbeaconsent",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_lastvote, { "Last Vote", "afs.ubik.lastvote",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_currentdb, { "Current DB", "afs.ubik.currentdb",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_up, { "Up", "afs.ubik.up",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_beaconsincedown, { "Beacon Since Down", "afs.ubik.beaconsincedown",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_amsyncsite, { "Am Sync Site", "afs.ubik.amsyncsite",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_syncsiteuntil, { "Sync Site Until", "afs.ubik.syncsiteuntil",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_nservers, { "Number of Servers", "afs.ubik.nservers",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_lockedpages, { "Locked Pages", "afs.ubik.lockedpages",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_writelockedpages, { "Write Locked Pages", "afs.ubik.writelockedpages",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_activewrite, { "Active Write", "afs.ubik.activewrite",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_tidcounter, { "TID Counter", "afs.ubik.tidcounter",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_anyreadlocks, { "Any Read Locks", "afs.ubik.anyreadlocks",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_anywritelocks, { "Any Write Locks", "afs.ubik.anywritelocks",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_recoverystate, { "Recovery State", "afs.ubik.recoverystate",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_currenttrans, { "Current Transaction", "afs.ubik.currenttran",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_writetrans, { "Write Transaction", "afs.ubik.writetran",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_epochtime, { "Epoch Time", "afs.ubik.epochtime",
		FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, 0, 0, NULL, HFILL }},
	{ &hf_afs_ubik_isclone, { "Is Clone", "afs.ubik.isclone",
		FT_UINT32, BASE_HEX, 0, 0, NULL, HFILL }},
	{ &hf_afs_reqframe, { "Request Frame", "afs.reqframe",
		FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_afs_repframe, { "Reply Frame", "afs.repframe",
		FT_FRAMENUM, BASE_NONE,	NULL, 0, NULL, HFILL }},
	{ &hf_afs_time, { "Time from request", "afs.time",
		FT_RELATIVE_TIME, BASE_NONE, NULL, 0, "Time between Request and Reply for AFS calls", HFILL }},

	{&hf_afs_fragments, {"Message fragments", "afs.fragments",
		FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
	{&hf_afs_fragment, {"Message fragment", "afs.fragment",
		FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
	{&hf_afs_fragment_overlap, {"Message fragment overlap", "afs.fragment.overlap",
		FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
	{&hf_afs_fragment_overlap_conflicts, {"Message fragment overlapping with conflicting data", "afs.fragment.overlap.conflicts",
		FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
	{&hf_afs_fragment_multiple_tails, {"Message has multiple tail fragments", "afs.fragment.multiple_tails",
		FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
	{&hf_afs_fragment_too_long_fragment, {"Message fragment too long", "afs.fragment.too_long_fragment",
		FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
	{&hf_afs_fragment_error, {"Message defragmentation error", "afs.fragment.error",
		FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
	{&hf_afs_fragment_count, {"Message fragment count", "afs.fragment.count",
		FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
	{&hf_afs_reassembled_in, {"Reassembled in", "afs.reassembled.in",
		FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
	{&hf_afs_reassembled_length, {"Reassembled length", "afs.reassembled.length",
		FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
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
		&ett_afs_fragment,
		&ett_afs_fragments,
		&ett_afs_cm_interfaces,
		&ett_afs_cm_capabilities,
	};

	proto_afs = proto_register_protocol("Andrew File System (AFS)",
	    "AFS (RX)", "afs");
	proto_register_field_array(proto_afs, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_init_routine(&afs_init_protocol);
	register_cleanup_routine(&afs_cleanup_protocol);

	register_dissector("afs", dissect_afs, proto_afs);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
