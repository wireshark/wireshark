/* packet-afs-defs.h
 * Routines for AFS packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 * Based on routines from tcpdump patches by
 *   Ken Hornstein <kenh@cmf.nrl.navy.mil>
 * Portions based on information retrieved from the RX definitions
 *   in Arla, the free AFS client at http://www.stacken.kth.se/project/arla/
 * Portions based on information/specs retrieved from the OpenAFS sources at
 *   www.openafs.org, Copyright IBM. 
 *
 * $Id: packet-afs-defs.h,v 1.10 2002/02/03 18:12:04 nneul Exp $
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
	{ 0,		NULL },
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
