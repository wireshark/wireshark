/* packet-afs.c
 * Routines for AFS packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 * Based on routines from tcpdump patches by
 *   Ken Hornstein <kenh@cmf.nrl.navy.mil>
 * Portions based on information retrieved from the RX definitions
 *   in Arla, the free AFS client at http://www.stacken.kth.se/project/arla/
 *
 * $Id: packet-afs.c,v 1.16 2000/11/02 16:15:53 nneul Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "conversation.h"
#include "packet-rx.h"
#include "packet-afs.h"
#include "resolv.h"

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
	{ 143,		"oldsetlock" },
	{ 144,		"oldextlock" },
	{ 145,		"oldrellock" },
	{ 146,		"get-stats" },
	{ 147,		"give-cbs" },
	{ 148,		"get-vlinfo" },
	{ 149,		"get-vlstats" },
	{ 150,		"set-vlstats" },
	{ 151,		"get-rootvl" },
	{ 152,		"check-token" },
	{ 153,		"get-time" },
	{ 154,		"nget-vlinfo" },
	{ 155,		"bulk-stat" },
	{ 156,		"setlock" },
	{ 157,		"extlock" },
	{ 158,		"rellock" },
	{ 159,		"xstat-ver" },
	{ 160,		"get-xstat" },
	{ 161,		"dfs-lookup" },
	{ 162,		"dfs-flushcps" },
	{ 163,		"dfs-symlink" },
	{ 0,		NULL },
};

static const value_string cb_req[] = {
	{ 204,		"callback" },
	{ 205,		"initcb" },
	{ 206,		"probe" },
	{ 207,		"getlock" },
	{ 208,		"getce" },
	{ 209,		"xstatver" },
	{ 210,		"getxstat" },
	{ 211,		"initcb2" },
	{ 212,		"whoareyou" },
	{ 213,		"initcb3" },
	{ 214,		"probeuuid" },
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
	{ 508,		"setlock" },
	{ 509,		"releaselock" },
	{ 510,		"list-entry" },
	{ 511,		"list-attrib" },
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
	{ 105,		"start-bozo-install" },
	{ 106,		"uninstall" },
	{ 107,		"get-dates" },
	{ 108,		"exec" },
	{ 109,		"prune" },
	{ 110,		"set-restart-time" },
	{ 111,		"get-restart-time" },
	{ 112,		"start-bozo-log" },
	{ 113,		"wait-all" },
	{ 114,		"get-instance-strings" },
	{ 0,		NULL },
};

static const value_string ubik_req[] = {
	{ 10000,	"vote-beacon" },
	{ 10001,	"vote-debug-old" },
	{ 10002,	"vote-sdebug-old" },
	{ 10003,	"vote-getsyncsite" },
	{ 10004,	"vote-debug" },
	{ 10005,	"vote-sdebug" },
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

static const value_string volume_types[] = {
	{ 0,		"read-write" },
	{ 1,		"read-only" },
	{ 2,		"backup" },
	{ 0,		NULL },
};

int afs_packet_init_count = 100;

struct afs_request_key {
  guint32 conversation, callnumber;
  guint16 service;
};

struct afs_request_val {
  guint32 opcode;
};

GHashTable *afs_request_hash = NULL;
GMemChunk *afs_request_keys = NULL;
GMemChunk *afs_request_vals = NULL;

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
static int hf_afs_bos_num = -1;
static int hf_afs_bos_size = -1;
static int hf_afs_bos_flags = -1;
static int hf_afs_bos_date = -1;
static int hf_afs_bos_content = -1;

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
static int hf_afs_vldb_partition = -1;
static int hf_afs_vldb_rovol = -1;
static int hf_afs_vldb_rwvol = -1;
static int hf_afs_vldb_bkvol = -1;

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
static int hf_afs_ubik_syncsite = -1;
static int hf_afs_ubik_site = -1;
static int hf_afs_ubik_file = -1;
static int hf_afs_ubik_pos = -1;
static int hf_afs_ubik_length = -1;
static int hf_afs_ubik_locktype = -1;
static int hf_afs_ubik_voteend = -1;
static int hf_afs_ubik_votetype = -1;

static gint ett_afs = -1;
static gint ett_afs_op = -1;
static gint ett_afs_acl = -1;
static gint ett_afs_fid = -1;
static gint ett_afs_callback = -1;
static gint ett_afs_ubikver = -1;

/*
 * Dissector prototypes
 */
static void dissect_fs_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_fs_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_cb_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_cb_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_bos_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_bos_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_vol_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_vol_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_ubik_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_ubik_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_kauth_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_kauth_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_prot_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_prot_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_vldb_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_vldb_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_backup_request(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);
static void dissect_backup_reply(const u_char *pd,
	int offset, frame_data *fd, proto_tree *tree, int opcode);


/*
 * Hash Functions
 */
static gint
afs_equal(gconstpointer v, gconstpointer w)
{
  struct afs_request_key *v1 = (struct afs_request_key *)v;
  struct afs_request_key *v2 = (struct afs_request_key *)w;

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
	struct afs_request_key *key = (struct afs_request_key *)v;
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
	if (afs_request_keys)
		g_mem_chunk_destroy(afs_request_keys);
	if (afs_request_vals)
		g_mem_chunk_destroy(afs_request_vals);

	afs_request_hash = g_hash_table_new(afs_hash, afs_equal);
	afs_request_keys = g_mem_chunk_new("afs_request_keys",
		sizeof(struct afs_request_key),
		afs_packet_init_count * sizeof(struct afs_request_key),
		G_ALLOC_AND_FREE);
	afs_request_vals = g_mem_chunk_new("afs_request_vals",
		sizeof(struct afs_request_val),
		afs_packet_init_count * sizeof(struct afs_request_val),
		G_ALLOC_AND_FREE);
}



/*
 * Dissection routines
 */

void
dissect_afs(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree      *afs_tree, *afs_op_tree, *ti;
	struct rx_header *rxh;
	struct afs_header *afsh;
	int port, node, typenode, opcode;
	value_string const *vals;
	int reply = 0;
	int doffset = 0;
	conversation_t *conversation;
	struct afs_request_key request_key, *new_request_key;
	struct afs_request_val *request_val;
	void (*dissector)(const u_char *pd, int offset,
		frame_data *fd, proto_tree *tree, int opcode);

	OLD_CHECK_DISPLAY_AS_DATA(proto_afs, pd, offset, fd, tree);

	rxh = (struct rx_header *) &pd[offset];
	doffset = offset + sizeof(struct rx_header);
	afsh = (struct afs_header *) &pd[doffset];

	/* get at least a full packet structure */
	if ( !BYTES_ARE_IN_FRAME(offset, sizeof(struct rx_header)) )
		return;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "AFS (RX)");

	reply = (rxh->flags & RX_CLIENT_INITIATED) == 0;
	port = ((reply == 0) ? pi.destport : pi.srcport );

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
	conversation = find_conversation(&pi.src, &pi.dst, pi.ptype,
	    pi.srcport, pi.destport, 0);
	if (conversation == NULL) {
		/* It's not part of any conversation - create a new one. */
		conversation = conversation_new(&pi.src, &pi.dst, pi.ptype,
		    pi.srcport, pi.destport, NULL, 0);
	}

	request_key.conversation = conversation->index;	
	request_key.service = pntohs(&rxh->serviceId);
	request_key.callnumber = pntohl(&rxh->callNumber);

	request_val = (struct afs_request_val *) g_hash_table_lookup(
		afs_request_hash, &request_key);

	/* only allocate a new hash element when it's a request */
	opcode = 0;
	if ( !request_val && !reply)
	{
		new_request_key = g_mem_chunk_alloc(afs_request_keys);
		*new_request_key = request_key;

		request_val = g_mem_chunk_alloc(afs_request_vals);
		request_val -> opcode = pntohl(&afsh->opcode);
		opcode = request_val->opcode;

		g_hash_table_insert(afs_request_hash, new_request_key,
			request_val);
	}

	if ( request_val )
	{
		opcode = request_val->opcode;
	}

	node = 0;
	typenode = 0;
	vals = NULL;
	dissector = NULL;
	switch (port)
	{
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
			/* dissector = reply ? dissect_update_reply : dissect_update_request; */
			break;
		case AFS_PORT_RMTSYS:
			typenode = hf_afs_rmtsys;
			node = hf_afs_rmtsys_opcode;
			/* dissector = reply ? dissect_rmtsys_reply : dissect_rmtsys_request; */
			break;
		case AFS_PORT_BACKUP:
			typenode = hf_afs_backup;
			node = hf_afs_backup_opcode;
			dissector = reply ? dissect_backup_reply : dissect_backup_request;
			break;
	}
	if ( (opcode >= VOTE_LOW && opcode <= VOTE_HIGH) ||
		(opcode >= DISK_LOW && opcode <= DISK_HIGH) )
	{
		typenode = hf_afs_ubik;
		node = hf_afs_ubik_opcode;
		vals = ubik_req;
		dissector = reply ? dissect_ubik_reply : dissect_ubik_request;
	}

	if ( vals )
	{
		if (check_col(fd, COL_INFO))
			col_add_fstr(fd, COL_INFO, "%s %s: %s (%d)",
			val_to_str(port, port_types_short, "Unknown(%d)"),
			reply ? "Reply" : "Request",
			val_to_str(opcode, vals, "Unknown(%d)"), opcode);
	}
	else
	{
		if (check_col(fd, COL_INFO))
			col_add_fstr(fd, COL_INFO, "%s %s: Unknown(%d)",
			val_to_str(port, port_types_short, "Unknown(%d)"),
			reply ? "Reply" : "Request",
			opcode);
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_afs, NullTVB, doffset, END_OF_FRAME, FALSE);
		afs_tree = proto_item_add_subtree(ti, ett_afs);

		if ( !BYTES_ARE_IN_FRAME(offset, sizeof(struct rx_header) +
			sizeof(struct afs_header)) )
		{
			proto_tree_add_text(afs_tree, NullTVB, doffset, END_OF_FRAME,
				"Service: %s %s (Truncated)",
				val_to_str(port, port_types, "Unknown(%d)"),
				reply ? "Reply" : "Request");
				return;
		}
		else
		{
			proto_tree_add_text(afs_tree, NullTVB, doffset, END_OF_FRAME,
				"Service: %s %s",
				val_to_str(port, port_types, "Unknown(%d)"),
				reply ? "Reply" : "Request");
		}

		/* until we do cache, can't handle replies */
		ti = NULL;
		if ( !reply && node != 0 )
		{
			ti = proto_tree_add_uint(afs_tree,
				node, NullTVB, doffset, 4, opcode);
		}
		else if ( reply && node != 0 )
		{
			/* the opcode isn't in this packet */
			ti = proto_tree_add_uint(afs_tree,
				node, NullTVB, doffset, 0, opcode);
		}
		else
		{
			ti = proto_tree_add_text(afs_tree, NullTVB,
				doffset, 0, "Operation: Unknown");
		}

		/* Add the subtree for this particular service */
		afs_op_tree = proto_item_add_subtree(ti, ett_afs_op);

		if ( typenode != 0 )
		{
			/* indicate the type of request */
			proto_tree_add_boolean_hidden(afs_tree, typenode, NullTVB, doffset, 0, 1);
		}

		/* Process the packet according to what service it is */
		if ( dissector )
		{
			(*dissector)(pd,offset,fd,afs_op_tree,opcode);
		}
	}

	/* if it's the last packet, and it's a reply, remove opcode
		from hash */
	/* ignoring for now, I'm not sure how the chunk deallocation works */
	if ( rxh->flags & RX_LAST_PACKET && reply )
	{

	}
}

/*
 * Macros for helper dissection routines
 *
 * The macros are here to save on coding. They assume that
 * the current offset is in 'curoffset', and that the offset
 * should be incremented after performing the macro's operation.
 */

/* Get the next available integer, be sure and call TRUNC beforehand */
#define GETINT() (pntohl(&pd[curoffset]))

/* Check if enough bytes are present, if not, return to caller
   after adding a 'Truncated' message to tree */
#define TRUNC(bytes) \
	if(!BYTES_ARE_IN_FRAME(curoffset,(bytes))) \
	{ proto_tree_add_text(tree, NullTVB,curoffset,END_OF_FRAME,"Truncated"); \
	return; }

/* Output a unsigned integer, stored into field 'field'
   Assumes it is in network byte order, converts to host before using */
#define UINTOUT(field) \
	TRUNC(sizeof(guint32)) \
	proto_tree_add_uint(tree,field, NullTVB,curoffset,sizeof(guint32), GETINT()); \
	curoffset += 4;

/* Output an IPv4 address, stored into field 'field' */
#define IPOUT(field) \
	TRUNC(sizeof(gint32)) \
	proto_tree_add_ipv4(tree,field, NullTVB,curoffset,sizeof(gint32),\
		*((int*)&pd[curoffset]));\
	curoffset += 4;

/* Output a UNIX seconds/microseconds timestamp, after converting to a timeval */
#define BIGDATEOUT(field) \
	{ struct timeval tv; \
	TRUNC(2*sizeof(guint32)); \
	tv.tv_sec = GETINT(); \
	tv.tv_usec = GETINT(); \
	proto_tree_add_time(tree,field, NullTVB,curoffset,2*sizeof(guint32),&tv); \
	curoffset += 8; \
	}

/* Output a UNIX seconds-only timestamp, after converting to a timeval */
#define DATEOUT(field) \
	{ struct timeval tv; \
	TRUNC(sizeof(guint32)); \
	tv.tv_sec = GETINT(); \
	tv.tv_usec = 0; \
	proto_tree_add_time(tree,field, NullTVB,curoffset,sizeof(guint32),&tv); \
	curoffset += 4; \
	}

/* Output a callback */
#define FS_CALLBACKOUT() \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, NullTVB, curoffset, 3*4, "Callback"); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_callback); \
		TRUNC(3*sizeof(guint32)); \
		UINTOUT(hf_afs_fs_callback_version); \
		BIGDATEOUT(hf_afs_fs_callback_expires); \
		UINTOUT(hf_afs_fs_callback_type); \
		tree = save; \
	}

/* Output a callback */
#define CB_CALLBACKOUT() \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, NullTVB, curoffset, 3*4, "Callback"); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_callback); \
		TRUNC(3*sizeof(guint32)); \
		UINTOUT(hf_afs_cb_callback_version); \
		DATEOUT(hf_afs_cb_callback_expires); \
		UINTOUT(hf_afs_cb_callback_type); \
		tree = save; \
	}


/* Output a File ID */
#define FS_FIDOUT(label) \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, NullTVB, curoffset, 3*4, \
			"FileID (%s)", label); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_fid); \
		UINTOUT(hf_afs_fs_fid_volume); \
		UINTOUT(hf_afs_fs_fid_vnode); \
		UINTOUT(hf_afs_fs_fid_uniqifier); \
		tree = save; \
	}

/* Output a File ID */
#define CB_FIDOUT(label) \
	{ 	proto_tree *save, *ti; \
		ti = proto_tree_add_text(tree, NullTVB, curoffset, 3*4, \
			"FileID (%s)", label); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_fid); \
		UINTOUT(hf_afs_cb_fid_volume); \
		UINTOUT(hf_afs_cb_fid_vnode); \
		UINTOUT(hf_afs_cb_fid_uniqifier); \
		tree = save; \
	}

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
		ti = proto_tree_add_text(tree, NullTVB, curoffset, bytes, \
			"ACL:  %s %s%s", \
			who, tmp, positive ? "" : " (negative)"); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_acl); \
		proto_tree_add_string(tree,hf_afs_fs_acl_entity, NullTVB,curoffset,strlen(who), who);\
		tmpoffset = curoffset + strlen(who) + 1; \
		acllen = bytes - strlen(who) - 1; \
		proto_tree_add_uint(tree,hf_afs_fs_acl_r, NullTVB,tmpoffset,acllen,acl);\
		proto_tree_add_uint(tree,hf_afs_fs_acl_l, NullTVB,tmpoffset,acllen,acl);\
		proto_tree_add_uint(tree,hf_afs_fs_acl_i, NullTVB,tmpoffset,acllen,acl);\
		proto_tree_add_uint(tree,hf_afs_fs_acl_d, NullTVB,tmpoffset,acllen,acl);\
		proto_tree_add_uint(tree,hf_afs_fs_acl_w, NullTVB,tmpoffset,acllen,acl);\
		proto_tree_add_uint(tree,hf_afs_fs_acl_k, NullTVB,tmpoffset,acllen,acl);\
		proto_tree_add_uint(tree,hf_afs_fs_acl_a, NullTVB,tmpoffset,acllen,acl);\
		tree = save; \
	}

/* Skip a certain number of bytes */
#define SKIP(bytes) \
	TRUNC(bytes) \
	curoffset += bytes;

/* Raw data - to end of frame */
#define RAWOUT(field) BYTESOUT(field, offset+END_OF_FRAME-curoffset)

/* Raw data */
#define BYTESOUT(field, bytes) \
	TRUNC(bytes); \
	proto_tree_add_bytes(tree,field, NullTVB,curoffset,bytes,\
		(void *)&pd[curoffset]); \
	curoffset += bytes;

/* Output a rx style string, up to a maximum length first 
   4 bytes - length, then char data */
#define STROUT(field) \
	{	int i; \
		TRUNC(4); \
		i = pntohl(&pd[curoffset]); \
		curoffset += 4; \
		TRUNC(i); \
		if ( i > 0 ) { \
			proto_tree_add_string(tree, field, NullTVB, curoffset-4, i+4, \
			(void *)&pd[curoffset]); \
		} else { \
			proto_tree_add_string(tree, field, NullTVB, curoffset-4, 4, \
			""); \
		} \
		curoffset += i; \
	}

/* Output a fixed length vectorized string (each char is a 32 bit int) */
#define VECOUT(field, length) \
	{ 	char tmp[length+1]; \
		int i,soff; \
		soff = curoffset;\
		TRUNC(length * sizeof(guint32));\
		for (i=0; i<length; i++)\
		{\
			tmp[i] = (char) GETINT();\
			curoffset += sizeof(guint32);\
		}\
		tmp[length] = '\0';\
		proto_tree_add_string(tree, field, NullTVB, soff, length, tmp);\
	}

/* Output a UBIK version code */
#define UBIK_VERSIONOUT(label) \
	{ 	proto_tree *save, *ti; \
		unsigned int epoch,counter; \
		struct timeval tv; \
		TRUNC(8); \
		epoch = GETINT(); \
		curoffset += 4; \
		counter = GETINT(); \
		curoffset += 4; \
		tv.tv_sec = epoch; \
		tv.tv_usec = 0; \
		ti = proto_tree_add_text(tree, NullTVB, curoffset, 3*4, \
			"UBIK Version (%s): %u.%u", label, epoch, counter ); \
		save = tree; \
		tree = proto_item_add_subtree(ti, ett_afs_ubikver); \
		proto_tree_add_time(tree,hf_afs_ubik_version_epoch, NullTVB,curoffset-8, \
			sizeof(guint32),&tv); \
		proto_tree_add_uint(tree,hf_afs_ubik_version_counter, NullTVB,curoffset-4, \
			sizeof(guint32),counter); \
		tree = save; \
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

static void dissect_acl(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	int pos, neg, acl;
	int n, i, bytes;
	u_char const *s;
	u_char const *end;
	char user[128];
	int curoffset;
	int soff,eoff;

	curoffset = offset;

	TRUNC(sizeof(guint32));
	bytes = pntohl(&pd[curoffset]);
	UINTOUT(hf_afs_fs_acl_datasize);

	TRUNC(bytes);

	soff = curoffset;
	eoff = curoffset+bytes;

	s = &pd[soff];
	end = &pd[eoff];

	if (sscanf((char *) s, "%d %n", &pos, &n) != 1)
		return;
	s += n;
	TRUNC(1);
	proto_tree_add_uint(tree, hf_afs_fs_acl_count_positive, NullTVB, curoffset, n, pos);
	curoffset += n;

	if (sscanf((char *) s, "%d %n", &neg, &n) != 1)
		return;
	s += n;
	TRUNC(1);
	proto_tree_add_uint(tree, hf_afs_fs_acl_count_negative, NullTVB, curoffset, n, neg);
	curoffset += n;


	/*
	 * This wacky order preserves the order used by the "fs" command
	 */

	for (i = 0; i < pos; i++) {
		if (sscanf((char *) s, "%s %d %n", user, &acl, &n) != 2)
			return;
		s += n;
		ACLOUT(user,1,acl,n);
		curoffset += n;
		TRUNC(1);
	}

	for (i = 0; i < neg; i++) {
		if (sscanf((char *) s, "%s %d %n", user, &acl, &n) != 2)
			return;
		s += n;
		ACLOUT(user,0,acl,n);
		curoffset += n;
		if (s > end)
			return;
	}
}

/*
 * Here are the helper dissection routines
 */

static void
dissect_fs_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 130: /* fetch data */
				RAWOUT(hf_afs_fs_data);
				break;
			case 131: /* fetch acl */
				dissect_acl(pd,curoffset,fd,tree);
				break;
			case 137: /* create file */
				FS_FIDOUT("New File");
				break;
			case 141: /* make dir */
				FS_FIDOUT("New Directory");
				break;
			case 151: /* root volume */
				STROUT(hf_afs_fs_volname);
				break;
			case 153: /* get time */
				BIGDATEOUT(hf_afs_fs_timestamp);
				break;
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		UINTOUT(hf_afs_fs_errcode);
	}
}

static void
dissect_fs_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	/* skip opcode */
	SKIP(sizeof(guint32));

	switch ( opcode )
	{
		case 130: /* Fetch data */
			FS_FIDOUT("Source");
			UINTOUT(hf_afs_fs_offset);
			UINTOUT(hf_afs_fs_length);
			break;
		case 131: /* Fetch ACL */
		case 132: /* Fetch Status */
		case 135: /* Store Status */
		case 143: /* Old Set Lock */
		case 144: /* Old Extend Lock */
		case 145: /* Old Release Lock */
		case 156: /* Set Lock */
		case 157: /* Extend Lock */
		case 158: /* Release Lock */
			FS_FIDOUT("Target");
			break;
		case 133: /* Store Data */
			FS_FIDOUT("Destination");
			SKIP(6*sizeof(guint32));
			UINTOUT(hf_afs_fs_offset);
			UINTOUT(hf_afs_fs_length);
			UINTOUT(hf_afs_fs_flength);
			break;
		case 134: /* Store ACL */
			FS_FIDOUT("Target");
			dissect_acl(pd,curoffset,fd,tree);
			/* print acl */
			break;
		case 136: /* Remove File */
		case 137: /* Create File */
		case 141: /* Make dir */
		case 142: /* Remove dir */
			FS_FIDOUT("Target");
			STROUT(hf_afs_fs_name);
			break;
		case 138: /* Rename file */
			FS_FIDOUT("Old");
			STROUT(hf_afs_fs_oldname);
			FS_FIDOUT("New");
			STROUT(hf_afs_fs_newname);
			break;
		case 139: /* Symlink */
			FS_FIDOUT("File");
			STROUT(hf_afs_fs_symlink_name);
			STROUT(hf_afs_fs_symlink_content);
			break;
		case 140: /* Link */
			FS_FIDOUT("Link From (Old File)");
			STROUT(hf_afs_fs_name);
			FS_FIDOUT("Link To (New File)");
			break;
		case 148: /* Get vol info */
			STROUT(hf_afs_fs_volname);
			break;
		case 149: /* Get vol stats */
		case 150: /* Set vol stats */
			UINTOUT(hf_afs_fs_volid);
			break;
		case 154: /* new get vol info */
			STROUT(hf_afs_fs_volname);
			break;
		case 155: /* bulk stat */
		{
			unsigned int j,i;
			TRUNC(1);

			j = pntohl(&pd[curoffset]);
			curoffset += 1;
			for (i=0; i<j; i++)
			{
				FS_FIDOUT("Target");
			}
			break;
		}
	}
}

/*
 * BOS Helpers
 */
static void
dissect_bos_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 85: /* get instance info */
				STROUT(hf_afs_bos_type);
				break;
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		UINTOUT(hf_afs_bos_errcode);
	}
}

static void
dissect_bos_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	/* skip opcode */
	SKIP(sizeof(guint32));

	switch ( opcode )
	{
		case 80: /* create b node */
			STROUT(hf_afs_bos_type);
			STROUT(hf_afs_bos_instance);
			break;
		case 81: /* delete b node */
		case 83: /* get status */
		case 85: /* get instance info */
		case 87: /* add super user */
		case 88: /* delete super user */
		case 93: /* set cell name */
		case 96: /* add cell host */
		case 97: /* delete cell host */
		case 104: /* restart */
		case 106: /* uninstall */
		case 108: /* exec */
		case 112: /* get log */
		case 114: /* get instance strings */
			STROUT(hf_afs_bos_content);
			break;
		case 82: /* set status */
		case 98: /* set t status */
			STROUT(hf_afs_bos_content);
			UINTOUT(hf_afs_bos_status);
			break;
		case 86: /* get instance parm */
			STROUT(hf_afs_bos_instance);
			UINTOUT(hf_afs_bos_num);
			break;
		case 84: /* enumerate instance */
		case 89: /* list super users */
		case 90: /* list keys */
		case 91: /* add key */
		case 92: /* delete key */
		case 95: /* set cell host */
			UINTOUT(hf_afs_bos_num);
			break;
		case 105: /* install */
			STROUT(hf_afs_bos_content);
			UINTOUT(hf_afs_bos_size);
			UINTOUT(hf_afs_bos_flags);
			UINTOUT(hf_afs_bos_date);
			break;
	}
}

/*
 * VOL Helpers
 */
static void
dissect_vol_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 121:
				/* should loop here maybe */
				UINTOUT(hf_afs_vol_count);
				VECOUT(hf_afs_vol_name, 32); /* not sure on  */
				break;
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		UINTOUT(hf_afs_vol_errcode);
	}
}

static void
dissect_vol_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	/* skip opcode */
	SKIP(sizeof(guint32));

	switch ( opcode )
	{
		case 121: /* list one vol */
			UINTOUT(hf_afs_vol_count);
			UINTOUT(hf_afs_vol_id);
			break;
	}
}

/*
 * KAUTH Helpers
 */
static void
dissect_kauth_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		UINTOUT(hf_afs_kauth_errcode);
	}
}

static void
dissect_kauth_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	/* skip opcode */
	SKIP(sizeof(guint32));

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
			STROUT(hf_afs_kauth_princ);
			STROUT(hf_afs_kauth_realm);
			RAWOUT(hf_afs_kauth_data);
			break;
		case 3: /* getticket-old */
		case 23: /* getticket */
			UINTOUT(hf_afs_kauth_kvno);
			STROUT(hf_afs_kauth_domain);
			STROUT(hf_afs_kauth_data);
			STROUT(hf_afs_kauth_princ);
			STROUT(hf_afs_kauth_realm);
			break;
		case 4: /* set pass */
			STROUT(hf_afs_kauth_princ);
			STROUT(hf_afs_kauth_realm);
			UINTOUT(hf_afs_kauth_kvno);
			break;
		case 12: /* get pass */
			STROUT(hf_afs_kauth_name);
			break;
	}
}

/*
 * CB Helpers
 */
static void
dissect_cb_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		UINTOUT(hf_afs_cb_errcode);
	}
}

static void
dissect_cb_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	/* skip opcode */
	SKIP(sizeof(guint32));

	switch ( opcode )
	{
		case 204: /* callback */
		{
			unsigned int i,j;

			TRUNC(4);
			j = GETINT();

			for (i=0; i<j; i++)
			{
				CB_FIDOUT("Target");
			}

			TRUNC(4);
			j = GETINT();
			for (i=0; i<j; i++)
			{
				CB_CALLBACKOUT();
			}
		}
	}
}

/*
 * PROT Helpers
 */
static void
dissect_prot_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 504: /* name to id */
				{
					unsigned int i, j;

					TRUNC(4);
					j = GETINT();
					UINTOUT(hf_afs_prot_count);

					for (i=0; i<j; i++)
					{
						UINTOUT(hf_afs_prot_id);
					}
				}
				break;
			case 505: /* id to name */
				{
					unsigned int i, j;

					TRUNC(4);
					j = GETINT();
					UINTOUT(hf_afs_prot_count);

					for (i=0; i<j; i++)
					{
						VECOUT(hf_afs_prot_name, PRNAMEMAX);
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

					TRUNC(4);
					j = GETINT();
					UINTOUT(hf_afs_prot_count);

					for (i=0; i<j; i++)
					{
						UINTOUT(hf_afs_prot_id);
					}
				}
				break;
			case 510: /* list max */
				UINTOUT(hf_afs_prot_maxuid);
				UINTOUT(hf_afs_prot_maxgid);
				break;
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		UINTOUT(hf_afs_prot_errcode);
	}
}

static void
dissect_prot_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	/* skip opcode */
	SKIP(sizeof(guint32));

	switch ( opcode )
	{
		case 500: /* new user */
			STROUT(hf_afs_prot_name);
			UINTOUT(hf_afs_prot_id);
			UINTOUT(hf_afs_prot_oldid);
			break;
		case 501: /* where is it */
		case 506: /* delete */
		case 508: /* get cps */
		case 512: /* list entry */
		case 514: /* list elements */
		case 517: /* list owned */
		case 519: /* get host cps */
			UINTOUT(hf_afs_prot_id);
			break;
		case 502: /* dump entry */
			UINTOUT(hf_afs_prot_pos);
			break;
		case 503: /* add to group */
		case 507: /* remove from group */
		case 515: /* is a member of? */
			UINTOUT(hf_afs_prot_uid);
			UINTOUT(hf_afs_prot_gid);
			break;
		case 504: /* name to id */
			{
				unsigned int i, j;

				TRUNC(4);
				j = GETINT();
				UINTOUT(hf_afs_prot_count);

				for (i=0; i<j; i++)
				{
					VECOUT(hf_afs_prot_name,PRNAMEMAX);
				}
			}
			break;
		case 505: /* id to name */
			{
				unsigned int i, j;

				TRUNC(4);
				j = GETINT();
				UINTOUT(hf_afs_prot_count);

				for (i=0; i<j; i++)
				{
					UINTOUT(hf_afs_prot_id);
				}
			}
			break;
		case 509: /* new entry */
			STROUT(hf_afs_prot_name);
			UINTOUT(hf_afs_prot_flag);
			UINTOUT(hf_afs_prot_oldid);
			break;
		case 511: /* set max */
			UINTOUT(hf_afs_prot_id);
			UINTOUT(hf_afs_prot_flag);
			break;
		case 513: /* change entry */
			UINTOUT(hf_afs_prot_id);
			STROUT(hf_afs_prot_name);
			UINTOUT(hf_afs_prot_oldid);
			UINTOUT(hf_afs_prot_newid);
			break;
		case 520: /* update entry */
			UINTOUT(hf_afs_prot_id);
			STROUT(hf_afs_prot_name);
			break;
	}
}

/*
 * VLDB Helpers
 */
static void
dissect_vldb_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 510: /* list entry */
				UINTOUT(hf_afs_vldb_count);
				UINTOUT(hf_afs_vldb_nextindex);
				break;
			case 503: /* get entry by id */
			case 504: /* get entry by name */
				{
					int nservers,i,j;
					VECOUT(hf_afs_vldb_name, VLNAMEMAX);
					TRUNC(4);
					nservers = GETINT();
					UINTOUT(hf_afs_vldb_numservers);
					for (i=0; i<8; i++)
					{
						if ( i<nservers )
						{
							IPOUT(hf_afs_vldb_server);
						}
						else
						{
							SKIP(4);
						}
					}
					for (i=0; i<8; i++)
					{
						char part[8];
						TRUNC(4);
						j = GETINT();
						strcpy(part, "/vicepa");
						if ( i<nservers && j<=25 )
						{
							part[6] = 'a' + (char) j;
							proto_tree_add_string(tree, hf_afs_vldb_partition, NullTVB,
								curoffset, 4, part);
						}
						SKIP(4);
					}
					SKIP(8 * sizeof(guint32));
					UINTOUT(hf_afs_vldb_rwvol);
					UINTOUT(hf_afs_vldb_rovol);
					UINTOUT(hf_afs_vldb_bkvol);
				}
				break;
			case 505: /* get new volume id */
				UINTOUT(hf_afs_vldb_id);
				break;
			case 521: /* list entry */
			case 529: /* list entry U */
				UINTOUT(hf_afs_vldb_count);
				UINTOUT(hf_afs_vldb_nextindex);
				break;
			case 518: /* get entry by id n */
			case 519: /* get entry by name N */
				{
					int nservers,i,j;
					VECOUT(hf_afs_vldb_name, VLNAMEMAX);
					TRUNC(4);
					nservers = GETINT();
					UINTOUT(hf_afs_vldb_numservers);
					for (i=0; i<13; i++)
					{
						if ( i<nservers )
						{
							IPOUT(hf_afs_vldb_server);
						}
						else
						{
							SKIP(4);
						}
					}
					for (i=0; i<13; i++)
					{
						char part[8];
						TRUNC(4);
						j = GETINT();
						strcpy(part, "/vicepa");
						if ( i<nservers && j<=25 )
						{
							part[6] = 'a' + (char) j;
							proto_tree_add_string(tree, hf_afs_vldb_partition, NullTVB,
								curoffset, 4, part);
						}
						SKIP(4);
					}
					SKIP(13 * sizeof(guint32));
					UINTOUT(hf_afs_vldb_rwvol);
					UINTOUT(hf_afs_vldb_rovol);
					UINTOUT(hf_afs_vldb_bkvol);
				}
				break;
			case 526: /* get entry by id u */
			case 527: /* get entry by name u */
				{
					int nservers,i,j;
					VECOUT(hf_afs_vldb_name, VLNAMEMAX);
					TRUNC(4);
					nservers = GETINT();
					UINTOUT(hf_afs_vldb_numservers);
					for (i=0; i<13; i++)
					{
						if ( i<nservers )
						{
							BYTESOUT(hf_afs_vldb_serveruuid, 11*sizeof(guint32));
						}
						else
						{
							SKIP(11*sizeof(guint32));
						}
					}
					for (i=0; i<13; i++)
					{
						char part[8];
						TRUNC(4);
						j = GETINT();
						strcpy(part, "/vicepa");
						if ( i<nservers && j<=25 )
						{
							part[6] = 'a' + (char) j;
							proto_tree_add_string(tree, hf_afs_vldb_partition, NullTVB,
								curoffset, 4, part);
						}
						SKIP(4);
					}
					SKIP(13 * sizeof(guint32));
					UINTOUT(hf_afs_vldb_rwvol);
					UINTOUT(hf_afs_vldb_rovol);
					UINTOUT(hf_afs_vldb_bkvol);
				}
				break;
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		UINTOUT(hf_afs_vldb_errcode);
	}
}

static void
dissect_vldb_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	/* skip opcode */
	SKIP(sizeof(guint32));

	switch ( opcode )
	{
		case 501: /* create new volume */
		case 517: /* create entry N */
			VECOUT(hf_afs_vldb_name, VLNAMEMAX);
			break;
		case 502: /* delete entry */
		case 503: /* get entry by id */
		case 507: /* update entry */
		case 508: /* set lock */
		case 509: /* release lock */
		case 518: /* get entry by id */
			UINTOUT(hf_afs_vldb_id);
			UINTOUT(hf_afs_vldb_type);
			break;
		case 504: /* get entry by name */
		case 519: /* get entry by name N */
		case 524: /* update entry by name */
		case 527: /* get entry by name U */
			STROUT(hf_afs_vldb_name);
			break;
		case 505: /* get new vol id */
			UINTOUT(hf_afs_vldb_bump);
			break;
		case 506: /* replace entry */
		case 520: /* replace entry N */
			UINTOUT(hf_afs_vldb_id);
			UINTOUT(hf_afs_vldb_type);
			VECOUT(hf_afs_vldb_name, VLNAMEMAX);
			break;
		case 510: /* list entry */
		case 521: /* list entry N */
			UINTOUT(hf_afs_vldb_index);
			break;
	}
}

/*
 * UBIK Helpers
 */
static void
dissect_ubik_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
			case 10000: /* beacon */
				proto_tree_add_boolean(tree,hf_afs_ubik_votetype, NullTVB,0,0,0);
				break;
			case 20004: /* get version */
				UBIK_VERSIONOUT("DB Version");
				break;
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		switch ( opcode )
		{
			case 10000:
				proto_tree_add_boolean(tree,hf_afs_ubik_votetype, NullTVB,0,0,1);
				DATEOUT(hf_afs_ubik_voteend);
				break;
			default:
				UINTOUT(hf_afs_ubik_errcode);
				break;
		}
	}
}

static void
dissect_ubik_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	/* skip opcode */
	SKIP(sizeof(guint32));

	switch ( opcode )
	{
		case 10000: /* beacon */
			UINTOUT(hf_afs_ubik_syncsite);
			DATEOUT(hf_afs_ubik_votestart);
			UBIK_VERSIONOUT("DB Version");
			UBIK_VERSIONOUT("TID");
			break;
		case 10003: /* get sync site */
			IPOUT(hf_afs_ubik_site);
			break;
		case 20000: /* begin */
		case 20001: /* commit */
		case 20007: /* abort */
		case 20008: /* release locks */
		case 20010: /* writev */
			UBIK_VERSIONOUT("TID");
			break;
		case 20002: /* lock */
			UBIK_VERSIONOUT("TID");
			UINTOUT(hf_afs_ubik_file);
			UINTOUT(hf_afs_ubik_pos);
			UINTOUT(hf_afs_ubik_length);
			UINTOUT(hf_afs_ubik_locktype);
			break;
		case 20003: /* write */
			UBIK_VERSIONOUT("TID");
			UINTOUT(hf_afs_ubik_file);
			UINTOUT(hf_afs_ubik_pos);
			break;
		case 20005: /* get file */
			UINTOUT(hf_afs_ubik_file);
			break;
		case 20006: /* send file */
			UINTOUT(hf_afs_ubik_file);
			UINTOUT(hf_afs_ubik_length);
			UBIK_VERSIONOUT("DB Version");
			break;
		case 20009: /* truncate */
			UBIK_VERSIONOUT("TID");
			UINTOUT(hf_afs_ubik_file);
			UINTOUT(hf_afs_ubik_length);
			break;
		case 20012: /* set version */
			UBIK_VERSIONOUT("TID");
			UBIK_VERSIONOUT("Old DB Version");
			UBIK_VERSIONOUT("New DB Version");
			break;
	}
}

/*
 * BACKUP Helpers
 */
static void
dissect_backup_reply(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	if ( rxh->type == RX_PACKET_TYPE_DATA )
	{
		switch ( opcode )
		{
		}
	}
	else if ( rxh->type == RX_PACKET_TYPE_ABORT )
	{
		UINTOUT(hf_afs_backup_errcode);
	}
}

static void
dissect_backup_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, int opcode)
{
	struct rx_header *rxh;
	unsigned char *data;
	int doffset, curoffset;

	rxh = (struct rx_header *) &pd[offset];
	data = (char *)rxh + sizeof(struct rx_header);
	doffset = offset + sizeof(struct rx_header);
	curoffset = doffset;

	/* skip opcode */
	SKIP(sizeof(guint32));

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

		{ &hf_afs_fs, {
			"File Server", "afs.fs", FT_BOOLEAN, BASE_NONE,
			0, 0, "File Server" }},
		{ &hf_afs_cb, {
			"Callback", "afs.cb", FT_BOOLEAN, BASE_NONE,
			0, 0, "Callback" }},
		{ &hf_afs_prot, {
			"Protection", "afs.prot", FT_BOOLEAN, BASE_NONE,
			0, 0, "Protection" }},
		{ &hf_afs_vldb, {
			"VLDB", "afs.vldb", FT_BOOLEAN, BASE_NONE,
			0, 0, "VLDB" }},
		{ &hf_afs_kauth, {
			"Kauth", "afs.kauth", FT_BOOLEAN, BASE_NONE,
			0, 0, "Kauth" }},
		{ &hf_afs_vol, {
			"Volume Server", "afs.vol", FT_BOOLEAN, BASE_NONE,
			0, 0, "Volume Server" }},
		{ &hf_afs_error, {
			"Error", "afs.error", FT_BOOLEAN, BASE_NONE,
			0, 0, "Error" }},
		{ &hf_afs_bos, {
			"BOS", "afs.bos", FT_BOOLEAN, BASE_NONE,
			0, 0, "BOS" }},
		{ &hf_afs_update, {
			"Update", "afs.update", FT_BOOLEAN, BASE_NONE,
			0, 0, "Update" }},
		{ &hf_afs_rmtsys, {
			"Rmtsys", "afs.rmtsys", FT_BOOLEAN, BASE_NONE,
			0, 0, "Rmtsys" }},
		{ &hf_afs_ubik, {
			"Ubik", "afs.ubik", FT_BOOLEAN, BASE_NONE,
			0, 0, "Ubik" }},
		{ &hf_afs_backup, {
			"Backup", "afs.backup", FT_BOOLEAN, BASE_NONE,
			0, 0, "Backup" }},

		{ &hf_afs_fs_opcode, {
			"Operation", "afs.fs.opcode", FT_UINT32, BASE_DEC,
			VALS(fs_req), 0, "Operation" }},
		{ &hf_afs_cb_opcode, {
			"Operation", "afs.cb.opcode", FT_UINT32, BASE_DEC,
			VALS(cb_req), 0, "Operation" }},
		{ &hf_afs_prot_opcode, {
			"Operation", "afs.prot.opcode", FT_UINT32, BASE_DEC,
			VALS(prot_req), 0, "Operation" }},
		{ &hf_afs_vldb_opcode, {
			"Operation", "afs.vldb.opcode", FT_UINT32, BASE_DEC,
			VALS(vldb_req), 0, "Operation" }},
		{ &hf_afs_kauth_opcode, {
			"Operation", "afs.kauth.opcode", FT_UINT32, BASE_DEC,
			VALS(kauth_req), 0, "Operation" }},
		{ &hf_afs_vol_opcode, {
			"Operation", "afs.vol.opcode", FT_UINT32, BASE_DEC,
			VALS(vol_req), 0, "Operation" }},
		{ &hf_afs_bos_opcode, {
			"Operation", "afs.bos.opcode", FT_UINT32, BASE_DEC,
			VALS(bos_req), 0, "Operation" }},
		{ &hf_afs_update_opcode, {
			"Operation", "afs.update.opcode", FT_UINT32, BASE_DEC,
			0, 0, "Operation" }},
		{ &hf_afs_rmtsys_opcode, {
			"Operation", "afs.rmtsys.opcode", FT_UINT32, BASE_DEC,
			0, 0, "Operation" }},
		{ &hf_afs_error_opcode, {
			"Operation", "afs.error.opcode", FT_UINT32, BASE_DEC,
			0, 0, "Operation" }},
		{ &hf_afs_backup_opcode, {
			"Operation", "afs.backup.opcode", FT_UINT32, BASE_DEC,
			0, 0, "Operation" }},
		{ &hf_afs_ubik_opcode, {
			"Operation", "afs.ubik.opcode", FT_UINT32, BASE_DEC,
			VALS(ubik_req), 0, "Operation" }},


		/* File Server Fields */
		{ &hf_afs_fs_fid_volume, {
			"FileID (Volume)", "afs.fs.fid.volume", FT_UINT32, BASE_DEC,
			0, 0, "File ID (Volume)" }},
		{ &hf_afs_fs_fid_vnode, {
			"FileID (VNode)", "afs.fs.fid.vnode", FT_UINT32, BASE_DEC,
			0, 0, "File ID (VNode)" }},
		{ &hf_afs_fs_fid_uniqifier, {
			"FileID (Uniqifier)", "afs.fs.fid.uniq", FT_UINT32, BASE_DEC,
			0, 0, "File ID (Uniqifier)" }},
		{ &hf_afs_fs_offset, {
			"Offset", "afs.fs.offset", FT_UINT32, BASE_DEC,
			0, 0, "Offset" }},
		{ &hf_afs_fs_length, {
			"Length", "afs.fs.length", FT_UINT32, BASE_DEC,
			0, 0, "Length" }},
		{ &hf_afs_fs_flength, {
			"FLength", "afs.fs.flength", FT_UINT32, BASE_DEC,
			0, 0, "FLength" }},
		{ &hf_afs_fs_errcode, {
			"Error Code", "afs.fs.errcode", FT_UINT32, BASE_DEC,
			VALS(afs_errors), 0, "Error Code" }},
		{ &hf_afs_fs_data, {
			"Data", "afs.fs.data", FT_BYTES, BASE_HEX,
			0, 0, "Data" }},
		{ &hf_afs_fs_oldname, {
			"Old Name", "afs.fs.oldname", FT_STRING, BASE_HEX,
			0, 0, "Old Name" }},
		{ &hf_afs_fs_newname, {
			"New Name", "afs.fs.newname", FT_STRING, BASE_HEX,
			0, 0, "New Name" }},
		{ &hf_afs_fs_name, {
			"Name", "afs.fs.name", FT_STRING, BASE_HEX,
			0, 0, "Name" }},
		{ &hf_afs_fs_symlink_name, {
			"Symlink Name", "afs.fs.symlink.name", FT_STRING, BASE_HEX,
			0, 0, "Symlink Name" }},
		{ &hf_afs_fs_symlink_content, {
			"Symlink Content", "afs.fs.symlink.content", FT_STRING, BASE_HEX,
			0, 0, "Symlink Content" }},
		{ &hf_afs_fs_volid, {
			"Volume ID", "afs.fs.volid", FT_UINT32, BASE_DEC,
			0, 0, "Volume ID" }},
		{ &hf_afs_fs_volname, {
			"Volume Name", "afs.fs.volname", FT_STRING, BASE_HEX,
			0, 0, "Volume Name" }},
		{ &hf_afs_fs_timestamp, {
			"Timestamp", "afs.fs.timestamp", FT_ABSOLUTE_TIME, BASE_DEC,
			0, 0, "Timestamp" }},

		{ &hf_afs_fs_acl_count_positive, {
			"ACL Count (Positive)", "afs.fs.acl.count.positive", FT_UINT32, BASE_DEC,
			0, 0, "Number of Positive ACLs" }},
		{ &hf_afs_fs_acl_count_negative, {
			"ACL Count (Negative)", "afs.fs.acl.count.negative", FT_UINT32, BASE_DEC,
			0, 0, "Number of Negative ACLs" }},
		{ &hf_afs_fs_acl_datasize, {
			"ACL Size", "afs.fs.acl.datasize", FT_UINT32, BASE_DEC,
			0, 0, "ACL Data Size" }},
		{ &hf_afs_fs_acl_entity, {
			"Entity (User/Group)", "afs.fs.acl.entity", FT_STRING, BASE_HEX,
			0, 0, "ACL Entity (User/Group)" }},
		{ &hf_afs_fs_acl_r, {
			"_R_ead", "afs.fs.acl.r", FT_UINT8, BASE_BIN,
			0, PRSFS_READ, "Read" }},
		{ &hf_afs_fs_acl_l, {
			"_L_ookup", "afs.fs.acl.l", FT_UINT8, BASE_BIN,
			0, PRSFS_LOOKUP, "Lookup" }},
		{ &hf_afs_fs_acl_i, {
			"_I_nsert", "afs.fs.acl.i", FT_UINT8, BASE_BIN,
			0, PRSFS_INSERT, "Insert" }},
		{ &hf_afs_fs_acl_d, {
			"_D_elete", "afs.fs.acl.d", FT_UINT8, BASE_BIN,
			0, PRSFS_DELETE, "Delete" }},
		{ &hf_afs_fs_acl_w, {
			"_W_rite", "afs.fs.acl.w", FT_UINT8, BASE_BIN,
			0, PRSFS_WRITE, "Write" }},
		{ &hf_afs_fs_acl_k, {
			"_L_ock", "afs.fs.acl.k", FT_UINT8, BASE_BIN,
			0, PRSFS_LOCK, "Lock" }},
		{ &hf_afs_fs_acl_a, {
			"_A_dminister", "afs.fs.acl.a", FT_UINT8, BASE_BIN,
			0, PRSFS_ADMINISTER, "Administer" }},

		{ &hf_afs_fs_callback_version, {
			"Version", "afs.fs.callback.version", FT_UINT32, BASE_DEC,
			0, 0, "Version" }},
		{ &hf_afs_fs_callback_expires, {
			"Expires", "afs.fs.callback.expires", FT_ABSOLUTE_TIME, BASE_DEC,
			0, 0, "Expires" }},
		{ &hf_afs_fs_callback_type, {
			"Type", "afs.fs.callback.type", FT_UINT32, BASE_DEC,
			VALS(cb_types), 0, "Type" }},

		/* BOS Server Fields */
		{ &hf_afs_bos_errcode, {
			"Error Code", "afs.bos.errcode", FT_UINT32, BASE_DEC,
			VALS(afs_errors), 0, "Error Code" }},
		{ &hf_afs_bos_type, {
			"Type", "afs.bos.type", FT_STRING, BASE_HEX,
			0, 0, "Type" }},
		{ &hf_afs_bos_content, {
			"Content", "afs.bos.content", FT_STRING, BASE_HEX,
			0, 0, "Content" }},
		{ &hf_afs_bos_instance, {
			"Instance", "afs.bos.instance", FT_STRING, BASE_HEX,
			0, 0, "Instance" }},
		{ &hf_afs_bos_status, {
			"Status", "afs.bos.status", FT_INT32, BASE_DEC,
			0, 0, "Status" }},
		{ &hf_afs_bos_num, {
			"Number", "afs.bos.number", FT_UINT32, BASE_DEC,
			0, 0, "Number" }},
		{ &hf_afs_bos_size, {
			"Size", "afs.bos.size", FT_UINT32, BASE_DEC,
			0, 0, "Size" }},
		{ &hf_afs_bos_flags, {
			"Flags", "afs.bos.flags", FT_UINT32, BASE_DEC,
			0, 0, "Flags" }},
		{ &hf_afs_bos_date, {
			"Date", "afs.bos.date", FT_UINT32, BASE_DEC,
			0, 0, "Date" }},

		/* KAUTH Server Fields */
		{ &hf_afs_kauth_errcode, {
			"Error Code", "afs.kauth.errcode", FT_UINT32, BASE_DEC,
			VALS(afs_errors), 0, "Error Code" }},
		{ &hf_afs_kauth_princ, {
			"Principal", "afs.kauth.princ", FT_STRING, BASE_HEX,
			0, 0, "Principal" }},
		{ &hf_afs_kauth_realm, {
			"Realm", "afs.kauth.realm", FT_STRING, BASE_HEX,
			0, 0, "Realm" }},
		{ &hf_afs_kauth_domain, {
			"Domain", "afs.kauth.domain", FT_STRING, BASE_HEX,
			0, 0, "Domain" }},
		{ &hf_afs_kauth_name, {
			"Name", "afs.kauth.name", FT_STRING, BASE_HEX,
			0, 0, "Name" }},
		{ &hf_afs_kauth_data, {
			"Data", "afs.kauth.data", FT_BYTES, BASE_HEX,
			0, 0, "Data" }},
		{ &hf_afs_kauth_kvno, {
			"Key Version Number", "afs.kauth.kvno", FT_UINT32, BASE_DEC,
			0, 0, "Key Version Number" }},

		/* VOL Server Fields */
		{ &hf_afs_vol_errcode, {
			"Error Code", "afs.vol.errcode", FT_UINT32, BASE_DEC,
			VALS(afs_errors), 0, "Error Code" }},
		{ &hf_afs_vol_id, {
			"Volume ID", "afs.vol.id", FT_UINT32, BASE_DEC,
			0, 0, "Volume ID" }},
		{ &hf_afs_vol_count, {
			"Volume Count", "afs.vol.count", FT_UINT32, BASE_DEC,
			0, 0, "Volume Count" }},
		{ &hf_afs_vol_name, {
			"Volume Name", "afs.vol.name", FT_STRING, BASE_HEX,
			0, 0, "Volume Name" }},

		/* VLDB Server Fields */
		{ &hf_afs_vldb_errcode, {
			"Error Code", "afs.vldb.errcode", FT_UINT32, BASE_DEC,
			VALS(afs_errors), 0, "Error Code" }},
		{ &hf_afs_vldb_type, {
			"Volume Type", "afs.vldb.type", FT_UINT32, BASE_DEC,
			VALS(volume_types), 0, "Volume Type" }},
		{ &hf_afs_vldb_id, {
			"Volume ID", "afs.vldb.id", FT_UINT32, BASE_DEC,
			0, 0, "Volume ID" }},
		{ &hf_afs_vldb_bump, {
			"Bumped Volume ID", "afs.vldb.bump", FT_UINT32, BASE_DEC,
			0, 0, "Bumped Volume ID" }},
		{ &hf_afs_vldb_index, {
			"Volume Index", "afs.vldb.index", FT_UINT32, BASE_DEC,
			0, 0, "Volume Index" }},
		{ &hf_afs_vldb_count, {
			"Volume Count", "afs.vldb.count", FT_UINT32, BASE_DEC,
			0, 0, "Volume Count" }},
		{ &hf_afs_vldb_numservers, {
			"Number of Servers", "afs.vldb.numservers", FT_UINT32, BASE_DEC,
			0, 0, "Number of Servers" }},
		{ &hf_afs_vldb_nextindex, {
			"Next Volume Index", "afs.vldb.nextindex", FT_UINT32, BASE_DEC,
			0, 0, "Next Volume Index" }},
		{ &hf_afs_vldb_rovol, {
			"Read-Only Volume ID", "afs.vldb.rovol", FT_UINT32, BASE_DEC,
			0, 0, "Read-Only Volume ID" }},
		{ &hf_afs_vldb_rwvol, {
			"Read-Write Volume ID", "afs.vldb.rwvol", FT_UINT32, BASE_DEC,
			0, 0, "Read-Only Volume ID" }},
		{ &hf_afs_vldb_bkvol, {
			"Backup Volume ID", "afs.vldb.bkvol", FT_UINT32, BASE_DEC,
			0, 0, "Read-Only Volume ID" }},
		{ &hf_afs_vldb_name, {
			"Volume Name", "afs.vldb.name", FT_STRING, BASE_HEX,
			0, 0, "Volume Name" }},
		{ &hf_afs_vldb_partition, {
			"Partition", "afs.vldb.partition", FT_STRING, BASE_HEX,
			0, 0, "Partition" }},
		{ &hf_afs_vldb_server, {
			"Server", "afs.vldb.server", FT_IPv4, BASE_HEX,
			0, 0, "Server" }},
		{ &hf_afs_vldb_serveruuid, {
			"Server UUID", "afs.vldb.serveruuid", FT_BYTES, BASE_HEX,
			0, 0, "Server UUID" }},

		/* BACKUP Server Fields */
		{ &hf_afs_backup_errcode, {
			"Error Code", "afs.backup.errcode", FT_UINT32, BASE_DEC,
			VALS(afs_errors), 0, "Error Code" }},

		/* CB Server Fields */
		{ &hf_afs_cb_errcode, {
			"Error Code", "afs.cb.errcode", FT_UINT32, BASE_DEC,
			VALS(afs_errors), 0, "Error Code" }},
		{ &hf_afs_cb_callback_version, {
			"Version", "afs.cb.callback.version", FT_UINT32, BASE_DEC,
			0, 0, "Version" }},
		{ &hf_afs_cb_callback_expires, {
			"Expires", "afs.cb.callback.expires", FT_ABSOLUTE_TIME, BASE_DEC,
			0, 0, "Expires" }},
		{ &hf_afs_cb_callback_type, {
			"Type", "afs.cb.callback.type", FT_UINT32, BASE_DEC,
			VALS(cb_types), 0, "Type" }},
		{ &hf_afs_cb_fid_volume, {
			"FileID (Volume)", "afs.cb.fid.volume", FT_UINT32, BASE_DEC,
			0, 0, "File ID (Volume)" }},
		{ &hf_afs_cb_fid_vnode, {
			"FileID (VNode)", "afs.cb.fid.vnode", FT_UINT32, BASE_DEC,
			0, 0, "File ID (VNode)" }},
		{ &hf_afs_cb_fid_uniqifier, {
			"FileID (Uniqifier)", "afs.cb.fid.uniq", FT_UINT32, BASE_DEC,
			0, 0, "File ID (Uniqifier)" }},

		/* PROT Server Fields */
		{ &hf_afs_prot_errcode, {
			"Error Code", "afs.prot.errcode", FT_UINT32, BASE_DEC,
			VALS(afs_errors), 0, "Error Code" }},
		{ &hf_afs_prot_name, {
			"Name", "afs.prot.name", FT_STRING, BASE_HEX,
			0, 0, "Name" }},
		{ &hf_afs_prot_id, {
			"ID", "afs.prot.id", FT_UINT32, BASE_DEC,
			0, 0, "ID" }},
		{ &hf_afs_prot_oldid, {
			"Old ID", "afs.prot.oldid", FT_UINT32, BASE_DEC,
			0, 0, "Old ID" }},
		{ &hf_afs_prot_newid, {
			"New ID", "afs.prot.newid", FT_UINT32, BASE_DEC,
			0, 0, "New ID" }},
		{ &hf_afs_prot_gid, {
			"Group ID", "afs.prot.gid", FT_UINT32, BASE_DEC,
			0, 0, "Group ID" }},
		{ &hf_afs_prot_uid, {
			"User ID", "afs.prot.uid", FT_UINT32, BASE_DEC,
			0, 0, "User ID" }},
		{ &hf_afs_prot_count, {
			"Count", "afs.prot.count", FT_UINT32, BASE_DEC,
			0, 0, "Count" }},
		{ &hf_afs_prot_maxgid, {
			"Maximum Group ID", "afs.prot.maxgid", FT_UINT32, BASE_DEC,
			0, 0, "Maximum Group ID" }},
		{ &hf_afs_prot_maxuid, {
			"Maximum User ID", "afs.prot.maxuid", FT_UINT32, BASE_DEC,
			0, 0, "Maximum User ID" }},
		{ &hf_afs_prot_pos, {
			"Position", "afs.prot.pos", FT_UINT32, BASE_DEC,
			0, 0, "Position" }},
		{ &hf_afs_prot_flag, {
			"Flag", "afs.prot.flag", FT_UINT32, BASE_HEX,
			0, 0, "Flag" }},

		/* UBIK Fields */
		{ &hf_afs_ubik_errcode, {
			"Error Code", "afs.ubik.errcode", FT_UINT32, BASE_DEC,
			VALS(afs_errors), 0, "Error Code" }},
		{ &hf_afs_ubik_version_epoch, {
			"Epoch", "afs.ubik.version.epoch", FT_ABSOLUTE_TIME, BASE_DEC,
			0, 0, "Epoch" }},
		{ &hf_afs_ubik_votestart, {
			"Vote Started", "afs.ubik.votestart", FT_ABSOLUTE_TIME, BASE_DEC,
			0, 0, "Vote Started" }},
		{ &hf_afs_ubik_voteend, {
			"Vote Ends", "afs.ubik.voteend", FT_ABSOLUTE_TIME, BASE_DEC,
			0, 0, "Vote Ends" }},
		{ &hf_afs_ubik_version_counter, {
			"Counter", "afs.ubik.version.counter", FT_UINT32, BASE_DEC,
			0, 0, "Counter" }},
		{ &hf_afs_ubik_file, {
			"File", "afs.ubik.file", FT_UINT32, BASE_DEC,
			0, 0, "File" }},
		{ &hf_afs_ubik_pos, {
			"Position", "afs.ubik.position", FT_UINT32, BASE_DEC,
			0, 0, "Position" }},
		{ &hf_afs_ubik_length, {
			"Length", "afs.ubik.length", FT_UINT32, BASE_DEC,
			0, 0, "Length" }},
		{ &hf_afs_ubik_locktype, {
			"Lock Type", "afs.ubik.locktype", FT_UINT32, BASE_DEC,
			VALS(ubik_lock_types), 0, "Lock Type" }},
		{ &hf_afs_ubik_votetype, {
			"Vote Type", "afs.ubik.votetype", FT_BOOLEAN, BASE_HEX,
			0, 0, "Vote Type" }},
		{ &hf_afs_ubik_syncsite, {
			"Syncsite", "afs.ubik.syncsite", FT_BOOLEAN, BASE_HEX,
			0, 0, "Syncsite" }},
		{ &hf_afs_ubik_site, {
			"Site", "afs.ubik.site", FT_IPv4, BASE_HEX,
			0, 0, "Site" }},

	};
	static gint *ett[] = {
		&ett_afs,
		&ett_afs_op,
		&ett_afs_acl,
		&ett_afs_fid,
		&ett_afs_callback,
		&ett_afs_ubikver,
	};

	proto_afs = proto_register_protocol("Andrew File System (AFS)", "afs");
	proto_register_field_array(proto_afs, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_init_routine(&afs_init_protocol);
}
