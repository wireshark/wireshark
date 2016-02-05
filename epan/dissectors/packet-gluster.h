/* packet-gluster.h
 * Header for gluster dissection
 * Copyright 2012, Niels de Vos <ndevos@redhat.com>
 * With contributions from:
 *    Shreedhara LG <shreedharlg@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *
 * References to source files point in general to the glusterfs sources.
 * There is currently no RFC or other document where the protocol is
 * completely described. The glusterfs sources can be found at:
 * - http://git.gluster.com/?p=glusterfs.git
 * - https://github.com/gluster/glusterfs
 *
 * The coding-style is roughly the same as the one use in the Linux kernel,
 * see http://www.kernel.org/doc/Documentation/CodingStyle.
 */

#ifndef __PACKET_GLUSTER_H__
#define __PACKET_GLUSTER_H__

#define GLUSTER_PORT		24007

/* most of this comes from rpc/rpc-lib/src/protocol-common.h
 * Some versions are commented with a user-visible version, others are not.
 * Some programs were introduced starting version 2.
 *
 * Older versions were removed from the sources.
 * One patch that did this is at http://review.gluster.com/610
 */
#define GLUSTERD1_MGMT_PROGRAM	1298433
/* only available in version 1 */

#define GLUSTERFS_PROGRAM	4867634 /* same as GD_BRICK_PROGRAM */
/* only available in version 1 (replaced by GD_BRICK_PROGRAM) */

/* rpc/rpc-lib/src/xdr-common.h */
#define GLUSTER_DUMP_PROGRAM	123451501
/* only available in version 1 */

#define GLUSTER_HNDSK_PROGRAM	14398633
/* only available in version 1 (0.0.1) */

#define GLUSTER_PMAP_PROGRAM	34123456
/* only available in version 1 */

#define GLUSTER_CBK_PROGRAM	52743234
/* only available in version 1 (0.0.1) */

#define GLUSTER3_1_FOP_PROGRAM	1298437
/* available in version 310 (3.1.0) */

#define GD_MGMT_PROGRAM		1238433
/* available in version 1, 2 and 3 */

#define GD_FRIEND_PROGRAM	1238437
/* only available in version 2 (0.0.2) */

#define GLUSTER_CLI_PROGRAM	1238463
/* available in version 1 (0.0.1) and 2 (0.0.2) */

#define GD_BRICK_PROGRAM	4867634
/* only available in version 2 (supersedes GLUSTERFS_PROGRAM) */

/* GD_MGMT_PROGRAM */
enum gf_mgmt_procnum {
	GD_MGMT_NULL = 0,
	GD_MGMT_PROBE_QUERY,
	GD_MGMT_FRIEND_ADD,
	GD_MGMT_CLUSTER_LOCK,
	GD_MGMT_CLUSTER_UNLOCK,
	GD_MGMT_STAGE_OP,
	GD_MGMT_COMMIT_OP,
	GD_MGMT_FRIEND_REMOVE,
	GD_MGMT_FRIEND_UPDATE,
	GD_MGMT_CLI_PROBE,
	GD_MGMT_CLI_DEPROBE,
	GD_MGMT_CLI_LIST_FRIENDS,
	GD_MGMT_CLI_CREATE_VOLUME,
	GD_MGMT_CLI_GET_VOLUME,
	GD_MGMT_CLI_DELETE_VOLUME,
	GD_MGMT_CLI_START_VOLUME,
	GD_MGMT_CLI_STOP_VOLUME,
	GD_MGMT_CLI_RENAME_VOLUME,
	GD_MGMT_CLI_DEFRAG_VOLUME,
	GD_MGMT_CLI_SET_VOLUME,
	GD_MGMT_CLI_ADD_BRICK,
	GD_MGMT_CLI_REMOVE_BRICK,
	GD_MGMT_CLI_REPLACE_BRICK,
	GD_MGMT_CLI_LOG_FILENAME,
	GD_MGMT_CLI_LOG_LOCATE,
	GD_MGMT_CLI_LOG_ROTATE,
	GD_MGMT_CLI_SYNC_VOLUME,
	GD_MGMT_CLI_RESET_VOLUME,
	GD_MGMT_CLI_FSM_LOG,
	GD_MGMT_CLI_GSYNC_SET,
	GD_MGMT_CLI_PROFILE_VOLUME,
	GD_MGMT_BRICK_OP,
	GD_MGMT_CLI_LOG_LEVEL,
	GD_MGMT_CLI_STATUS_VOLUME,
	GD_MGMT_MAXVALUE
};

/* GLUSTER_CLI_PROGRAM */
enum gluster_cli_procnum {
	GLUSTER_CLI_NULL = 0,
	GLUSTER_CLI_PROBE,
	GLUSTER_CLI_DEPROBE,
	GLUSTER_CLI_LIST_FRIENDS,
	GLUSTER_CLI_CREATE_VOLUME,
	GLUSTER_CLI_GET_VOLUME,
	GLUSTER_CLI_GET_NEXT_VOLUME,
	GLUSTER_CLI_DELETE_VOLUME,
	GLUSTER_CLI_START_VOLUME,
	GLUSTER_CLI_STOP_VOLUME,
	GLUSTER_CLI_RENAME_VOLUME,
	GLUSTER_CLI_DEFRAG_VOLUME,
	GLUSTER_CLI_SET_VOLUME,
	GLUSTER_CLI_ADD_BRICK,
	GLUSTER_CLI_REMOVE_BRICK,
	GLUSTER_CLI_REPLACE_BRICK,
	GLUSTER_CLI_LOG_FILENAME,
	GLUSTER_CLI_LOG_LOCATE,
	GLUSTER_CLI_LOG_ROTATE,
	GLUSTER_CLI_GETSPEC,
	GLUSTER_CLI_PMAP_PORTBYBRICK,
	GLUSTER_CLI_SYNC_VOLUME,
	GLUSTER_CLI_RESET_VOLUME,
	GLUSTER_CLI_FSM_LOG,
	GLUSTER_CLI_GSYNC_SET,
	GLUSTER_CLI_PROFILE_VOLUME,
	GLUSTER_CLI_QUOTA,
	GLUSTER_CLI_TOP_VOLUME,
	GLUSTER_CLI_GETWD,
	GLUSTER_CLI_LOG_LEVEL,
	GLUSTER_CLI_STATUS_VOLUME,
	GLUSTER_CLI_MOUNT,
	GLUSTER_CLI_UMOUNT,
	GLUSTER_CLI_HEAL_VOLUME,
	GLUSTER_CLI_STATEDUMP_VOLUME,
	GLUSTER_CLI_MAXVALUE
};

/* GLUSTER_CLI_PROGRAM 2 */
enum gluster_cli_2_procnum {
	GLUSTER_CLI_2_NULL = 0,    /* 0 */
	GLUSTER_CLI_2_PROBE,
	GLUSTER_CLI_2_DEPROBE,
	GLUSTER_CLI_2_LIST_FRIENDS,
	GLUSTER_CLI_2_CREATE_VOLUME,
	GLUSTER_CLI_2_GET_VOLUME,
	GLUSTER_CLI_2_GET_NEXT_VOLUME,
	GLUSTER_CLI_2_DELETE_VOLUME,
	GLUSTER_CLI_2_START_VOLUME,
	GLUSTER_CLI_2_STOP_VOLUME,
	GLUSTER_CLI_2_RENAME_VOLUME,
	GLUSTER_CLI_2_DEFRAG_VOLUME,
	GLUSTER_CLI_2_SET_VOLUME,
	GLUSTER_CLI_2_ADD_BRICK,
	GLUSTER_CLI_2_REMOVE_BRICK,
	GLUSTER_CLI_2_REPLACE_BRICK,
	GLUSTER_CLI_2_LOG_ROTATE,
	GLUSTER_CLI_2_GETSPEC,
	GLUSTER_CLI_2_PMAP_PORTBYBRICK,
	GLUSTER_CLI_2_SYNC_VOLUME,
	GLUSTER_CLI_2_RESET_VOLUME,
	GLUSTER_CLI_2_FSM_LOG,
	GLUSTER_CLI_2_GSYNC_SET,
	GLUSTER_CLI_2_PROFILE_VOLUME,
	GLUSTER_CLI_2_QUOTA,
	GLUSTER_CLI_2_TOP_VOLUME,
	GLUSTER_CLI_2_GETWD,
	GLUSTER_CLI_2_STATUS_VOLUME,
	GLUSTER_CLI_2_STATUS_ALL,
	GLUSTER_CLI_2_MOUNT,
	GLUSTER_CLI_2_UMOUNT,
	GLUSTER_CLI_2_HEAL_VOLUME,
	GLUSTER_CLI_2_STATEDUMP_VOLUME,
	GLUSTER_CLI_2_LIST_VOLUME,
	GLUSTER_CLI_2_CLRLOCKS_VOLUME,
	GLUSTER_CLI_2_MAXVALUE
};


/* GLUSTER_DUMP_PROGRAM */
enum gluster_prog_dump_procs {
	GF_DUMP_NULL = 0,
	GF_DUMP_DUMP,
	GF_DUMP_MAXVALUE
};

/* GLUSTERD1_MGMT_PROGRAM */
enum glusterd_mgmt_procnum {
	GLUSTERD_MGMT_NULL = 0,
	GLUSTERD_MGMT_PROBE_QUERY,
	GLUSTERD_MGMT_FRIEND_ADD,
	GLUSTERD_MGMT_CLUSTER_LOCK,
	GLUSTERD_MGMT_CLUSTER_UNLOCK,
	GLUSTERD_MGMT_STAGE_OP,
	GLUSTERD_MGMT_COMMIT_OP,
	GLUSTERD_MGMT_FRIEND_REMOVE,
	GLUSTERD_MGMT_FRIEND_UPDATE,
	GLUSTERD_MGMT_MAXVALUE
};

/* GLUSTERD1_MGMT_PROGRAM  for version 2*/
enum glusterd_mgmt_2_procnum {
	GLUSTERD_MGMT_2_NULL = 0,    /* 0 */
	GLUSTERD_MGMT_2_CLUSTER_LOCK,
	GLUSTERD_MGMT_2_CLUSTER_UNLOCK,
	GLUSTERD_MGMT_2_STAGE_OP,
	GLUSTERD_MGMT_2_COMMIT_OP,
	GLUSTERD_MGMT_2_MAXVALUE
};

/* GLUSTERD1_MGMT_PROGRAM  for version 3 */
enum glusterd_mgmt_3_procnum {
	GLUSTERD_MGMT_3_NULL = 0,
	GLUSTERD_MGMT_3_LOCK,
	GLUSTERD_MGMT_3_PRE_VALIDATE,
	GLUSTERD_MGMT_3_BRICK_OP,
	GLUSTERD_MGMT_3_COMMIT,
	GLUSTERD_MGMT_3_POST_VALIDATE,
	GLUSTERD_MGMT_3_UNLOCK,
	GLUSTERD_MGMT_3_MAXVALUE
};

/* GLUSTERFS_PROGRAM */
enum gf_brick_procnum {
	GF_BRICK_NULL = 0,
	GF_BRICK_TERMINATE,
	GF_BRICK_XLATOR_INFO,
	GF_BRICK_XLATOR_HEAL,
	GF_BRICK_MAXVALUE
};

/* GLUSTER_HNDSK_PROGRAM  for nersion 1 and 2*/
enum gluster_prog_hndsk_procs {
	GF_HNDSK_NULL = 0,
	GF_HNDSK_SETVOLUME,
	GF_HNDSK_GETSPEC,
	GF_HNDSK_PING,
	GF_HNDSK_SET_LK_VER,
	GF_HNDSK_EVENT_NOTIFY,
	GF_HNDSK_MAXVALUE
};

/* GLUSTER_PMAP_PROGRAM */
enum gf_pmap_procnum {
	GF_PMAP_NULL = 0,
	GF_PMAP_PORTBYBRICK,
	GF_PMAP_BRICKBYPORT,
	GF_PMAP_SIGNUP,
	GF_PMAP_SIGNIN,
	GF_PMAP_SIGNOUT,
	GF_PMAP_MAXVALUE
};

/* GD_BRICK_PROGRAM */
enum glusterd_brick_procnum {
	GLUSTERD_BRICK_NULL = 0,
	GLUSTERD_BRICK_TERMINATE,
	GLUSTERD_BRICK_XLATOR_INFO,
	GLUSTERD_BRICK_XLATOR_HEAL,
	GLUSTERD_BRICK_OP,
	GLUSTERD_BRICK_MAXVALUE
};

/* "rpc/rpc-lib/src/protocol-common.h" line 174 of 228 */
enum glusterd_brick_2_procnum {
	GLUSTERD_2_BRICK_NULL,    /* 0 */
	GLUSTERD_2_BRICK_TERMINATE,
	GLUSTERD_2_BRICK_XLATOR_INFO,
	GLUSTERD_2_BRICK_XLATOR_OP,
	GLUSTERD_2_BRICK_STATUS,
	GLUSTERD_2_BRICK_OP,
	GLUSTERD_2_BRICK_XLATOR_DEFRAG,
	GLUSTERD_2_NODE_PROFILE,
	GLUSTERD_2_NODE_STATUS,
	GLUSTERD_2_BRICK_MAXVALUE
};


/* GLUSTER_CBK_PROGRAM */
enum gf_cbk_procnum {
	GF_CBK_NULL = 0,
	GF_CBK_FETCHSPEC,
	GF_CBK_INO_FLUSH,
	GF_CBK_EVENT_NOTIFY,
	GF_CBK_GET_SNAPS,
	GF_CBK_CACHE_INVALIDATION,
	GF_CBK_MAXVALUE
};

/* GD_FRIEND_PROGRAM  defined in "rpc/rpc-lib/src/protocol-common.h" */
enum glusterd_friend_procnum {
	GLUSTERD_FRIEND_NULL,    /* 0 */
	GLUSTERD_PROBE_QUERY,
	GLUSTERD_FRIEND_ADD,
	GLUSTERD_FRIEND_REMOVE,
	GLUSTERD_FRIEND_UPDATE,
	GLUSTERD_FRIEND_MAXVALUE
};

enum gf_fop_procnum {
	GFS3_OP_NULL = 0,
	GFS3_OP_STAT,
	GFS3_OP_READLINK,
	GFS3_OP_MKNOD,
	GFS3_OP_MKDIR,
	GFS3_OP_UNLINK,
	GFS3_OP_RMDIR,
	GFS3_OP_SYMLINK,
	GFS3_OP_RENAME,
	GFS3_OP_LINK,
	GFS3_OP_TRUNCATE,
	GFS3_OP_OPEN,
	GFS3_OP_READ,
	GFS3_OP_WRITE,
	GFS3_OP_STATFS,
	GFS3_OP_FLUSH,
	GFS3_OP_FSYNC,
	GFS3_OP_SETXATTR,
	GFS3_OP_GETXATTR,
	GFS3_OP_REMOVEXATTR,
	GFS3_OP_OPENDIR,
	GFS3_OP_FSYNCDIR,
	GFS3_OP_ACCESS,
	GFS3_OP_CREATE,
	GFS3_OP_FTRUNCATE,
	GFS3_OP_FSTAT,
	GFS3_OP_LK,
	GFS3_OP_LOOKUP,
	GFS3_OP_READDIR,
	GFS3_OP_INODELK,
	GFS3_OP_FINODELK,
	GFS3_OP_ENTRYLK,
	GFS3_OP_FENTRYLK,
	GFS3_OP_XATTROP,
	GFS3_OP_FXATTROP,
	GFS3_OP_FGETXATTR,
	GFS3_OP_FSETXATTR,
	GFS3_OP_RCHECKSUM,
	GFS3_OP_SETATTR,
	GFS3_OP_FSETATTR,
	GFS3_OP_READDIRP,
	GFS3_OP_RELEASE,
	GFS3_OP_RELEASEDIR,
	GFS3_OP_FREMOVEXATTR,
	GFS3_OP_FALLOCATE,
	GFS3_OP_DISCARD,
	GFS3_OP_ZEROFILL,
	GFS3_OP_IPC,
	GFS3_OP_SEEK,
	GFS3_OP_MAXVALUE
};

/* dir-entry types from libglusterfs/src/compat.h */
enum gluster_entry_types {
	GLUSTER_DT_UNKNOWN = 0,
	GLUSTER_DT_FIFO = 1,
	GLUSTER_DT_CHR = 2,
	GLUSTER_DT_DIR = 4,
	GLUSTER_DT_BLK = 6,
	GLUSTER_DT_REG = 8,
	GLUSTER_DT_LNK = 10,
	GLUSTER_DT_SOCK = 12,
	GLUSTER_DT_WHT = 14
};


/* LOCKING operators come from libglusterfs/src/glusterfs.h */

/* based on original enum glusterfs_lk_cmds_t */
enum gluster_lk_cmds {
	GF_LK_GETLK = 0,
	GF_LK_SETLK,
	GF_LK_SETLKW,
	GF_LK_RESLK_LCK,
	GF_LK_RESLK_LCKW,
	GF_LK_RESLK_UNLCK,
	GF_LK_GETLK_FD
};

/* based on original enum glusterfs_lk_types_t */
enum gluster_lk_types {
	GF_LK_F_RDLCK = 0,
	GF_LK_F_WRLCK,
	GF_LK_F_UNLCK,
	GF_LK_EOL
};

enum gluster_lk_whence {
	GF_LK_SEEK_SET = 0,
	GF_LK_SEEK_CUR,
	GF_LK_SEEK_END
};

enum gluster_seek_whence {
	GF_SEEK_DATA = 0,
	GF_SEEK_HOLE
};

/* based on enum glusterd_op_ from xlators/mgmt/glusterd/src/glusterd.h */
enum glusterd_ops {
	GD_OP_NONE = 0,
	GD_OP_CREATE_VOLUME,
	GD_OP_START_BRICK,
	GD_OP_STOP_BRICK,
	GD_OP_DELETE_VOLUME,
	GD_OP_START_VOLUME,
	GD_OP_STOP_VOLUME,
	GD_OP_DEFRAG_VOLUME,
	GD_OP_ADD_BRICK,
	GD_OP_REMOVE_BRICK,
	GD_OP_REPLACE_BRICK,
	GD_OP_SET_VOLUME,
	GD_OP_RESET_VOLUME,
	GD_OP_SYNC_VOLUME,
	GD_OP_LOG_ROTATE,
	GD_OP_GSYNC_SET,
	GD_OP_PROFILE_VOLUME,
	GD_OP_QUOTA,
	GD_OP_STATUS_VOLUME,
	GD_OP_REBALANCE,
	GD_OP_HEAL_VOLUME,
	GD_OP_STATEDUMP_VOLUME,
	GD_OP_LIST_VOLUME,
	GD_OP_CLEARLOCKS_VOLUME,
	GD_OP_DEFRAG_BRICK_VOLUME,
	GD_OP_COPY_FILE,
	GD_OP_SYS_EXEC,
	GD_OP_GSYNC_CREATE,
	GD_OP_SNAP,
	GD_OP_MAX
};

/* based on enum gf_upcall_event_ from libglusterfs/src/upcall-utils.h */
enum gf_upcall_event {
	GF_UPCALL_EVENT_NULL,
	GF_UPCALL_CACHE_INVALIDATION,
};

extern int
gluster_rpc_dissect_dict(proto_tree *tree, tvbuff_t *tvb, int hfindex,
								int offset);

extern int
gluster_dissect_common_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo, proto_tree *tree, void* data _U_);
extern int
glusterfs_gfs3_3_op_common_reply(tvbuff_t *tvb,
				packet_info *pinfo, proto_tree *tree, void* data _U_);

extern int
glusterfs_rpc_dissect_gf_iatt(proto_tree *tree, tvbuff_t *tvb, int hfindex,
								int offset);
#endif /* __PACKET_GLUSTER_H__ */
