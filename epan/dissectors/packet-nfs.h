/* packet-nfs.h (c) 1999 Uwe Girlich */
/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_NFS_H__
#define __PACKET_NFS_H__

#include "packet-rpc.h"

#define NFS_PROGRAM 100003

#define FHSIZE 32

/* verifier */
#define NFS3_COOKIEVERFSIZE 8
#define NFS3_CREATEVERFSIZE 8
#define NFS3_WRITEVERFSIZE  8

/* for ftype3 */
#define NF3REG  1
#define NF3DIR  2
#define NF3BLK  3
#define NF3CHR  4
#define NF3LNK  5
#define NF3SOCK 6
#define NF3FIFO 7

/*
 * NFSv4 error codes used in code, as opposed to UI
 */
#define NFS4_OK                0
#define NFS4ERR_DENIED     10010
#define NFS4ERR_CLID_INUSE 10017

/*
 * NFSv4 file types
 */
#define NF4REG       1
#define NF4DIR       2
#define NF4BLK       3
#define NF4CHR       4
#define NF4LNK       5
#define NF4SOCK      6
#define NF4FIFO      7
#define NF4ATTRDIR   8
#define NF4NAMEDATTR 9

/*
 * Since NFSv4 "operations" are handled differently than previous NFS
 * versions, these tokens are necessary.
 */
#define NFS4_OP_ACCESS                       3
#define NFS4_OP_CLOSE                        4
#define NFS4_OP_COMMIT                       5
#define NFS4_OP_CREATE                       6
#define NFS4_OP_DELEGPURGE                   7
#define NFS4_OP_DELEGRETURN                  8
#define NFS4_OP_GETATTR                      9
#define NFS4_OP_GETFH                       10
#define NFS4_OP_LINK                        11
#define NFS4_OP_LOCK                        12
#define NFS4_OP_LOCKT                       13
#define NFS4_OP_LOCKU                       14
#define NFS4_OP_LOOKUP                      15
#define NFS4_OP_LOOKUPP                     16
#define NFS4_OP_NVERIFY                     17
#define NFS4_OP_OPEN                        18
#define NFS4_OP_OPENATTR                    19
#define NFS4_OP_OPEN_CONFIRM                20
#define NFS4_OP_OPEN_DOWNGRADE              21
#define NFS4_OP_PUTFH                       22
#define NFS4_OP_PUTPUBFH                    23
#define NFS4_OP_PUTROOTFH                   24
#define NFS4_OP_READ                        25
#define NFS4_OP_READDIR                     26
#define NFS4_OP_READLINK                    27
#define NFS4_OP_REMOVE                      28
#define NFS4_OP_RENAME                      29
#define NFS4_OP_RENEW                       30
#define NFS4_OP_RESTOREFH                   31
#define NFS4_OP_SAVEFH                      32
#define NFS4_OP_SECINFO                     33
#define NFS4_OP_SETATTR                     34
#define NFS4_OP_SETCLIENTID                 35
#define NFS4_OP_SETCLIENTID_CONFIRM         36
#define NFS4_OP_VERIFY                      37
#define NFS4_OP_WRITE                       38
#define NFS4_OP_RELEASE_LOCKOWNER           39
/* Minor version 1 */
#define NFS4_OP_BACKCHANNEL_CTL             40
#define NFS4_OP_BIND_CONN_TO_SESSION        41
#define NFS4_OP_EXCHANGE_ID                 42
#define NFS4_OP_CREATE_SESSION              43
#define NFS4_OP_DESTROY_SESSION             44
#define NFS4_OP_FREE_STATEID                45
#define NFS4_OP_GET_DIR_DELEGATION          46
#define NFS4_OP_GETDEVINFO                  47
#define NFS4_OP_GETDEVLIST                  48
#define NFS4_OP_LAYOUTCOMMIT                49
#define NFS4_OP_LAYOUTGET                   50
#define NFS4_OP_LAYOUTRETURN                51
#define NFS4_OP_SECINFO_NO_NAME             52
#define NFS4_OP_SEQUENCE                    53
#define NFS4_OP_SET_SSV                     54
#define NFS4_OP_TEST_STATEID                55
#define NFS4_OP_WANT_DELEGATION             56
#define NFS4_OP_DESTROY_CLIENTID            57
#define NFS4_OP_RECLAIM_COMPLETE            58

#define NFS4_OP_ILLEGAL                  10044

/*
 * NFSv41 callback ops
 */
#define NFS4_OP_CB_GETATTR                   3
#define NFS4_OP_CB_RECALL                    4
#define NFS4_OP_CB_LAYOUTRECALL              5
#define NFS4_OP_CB_NOTIFY                    6
#define NFS4_OP_CB_PUSH_DELEG                7
#define NFS4_OP_CB_RECALL_ANY                8
#define NFS4_OP_CB_RECALLABLE_OBJ_AVAIL      9
#define NFS4_OP_CB_RECALL_SLOT              10
#define NFS4_OP_CB_SEQUENCE                 11
#define NFS4_OP_CB_WANTS_CANCELLED          12
#define NFS4_OP_CB_NOTIFY_LOCK              13
#define NFS4_OP_CB_NOTIFY_DEVICEID          14
#define NFS4_OP_CB_ILLEGAL               10044

/* for write */
#define UNSTABLE  0
#define DATA_SYNC 1
#define FILE_SYNC 2

/* for create */
#define UNCHECKED 0
#define GUARDED   1
#define EXCLUSIVE 2

/* for create4 */
#define UNCHECKED4   0
#define GUARDED4     1
#define EXCLUSIVE4   2
#define EXCLUSIVE4_1 3

/* for access mask */
#define NFS_ACCESS_MASK_READ        0x01
#define NFS_ACCESS_MASK_LOOKUP      0x02
#define NFS_ACCESS_MASK_MODIFY      0x04
#define NFS_ACCESS_MASK_EXTEND      0x08
#define NFS_ACCESS_MASK_DELETE      0x10
#define NFS_ACCESS_MASK_EXECUTE     0x20

/* pNFS layout types */
#define LAYOUT4_NFSV4_1_FILES  1
#define LAYOUT4_OSD2_OBJECTS   2
#define LAYOUT4_BLOCK_VOLUME   3

extern gboolean nfs_file_name_snooping;
extern void nfs_name_snoop_add_name(int xid, tvbuff_t *tvb, int name_offset, int name_len,
	                                int parent_offset, int parent_len, const char *name);
extern gboolean nfs_fhandle_reqrep_matching;
extern int dissect_fhandle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
                           const char *name, guint32 *hash, rpc_call_info_value *civ);
extern void dissect_fhandle_hidden(packet_info *pinfo, proto_tree *tree, int frame);
extern int dissect_nfs3_fh(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
                           const char *name, guint32 *hash, rpc_call_info_value *civ);
extern int dissect_nfs3_post_op_attr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
	                                 const char* name);
extern int dissect_nfs2_fattr(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name);
extern proto_tree* display_access_items(tvbuff_t* tvb, int offset, packet_info* pinfo,
	                                    proto_tree* tree, guint32 amask, char mtype, int version,
										GString* optext, const char* label);
extern int dissect_access_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree* tree,
                                int version, GString *optext, rpc_call_info_value *civ);
extern int hf_nfs_status;

#endif /* packet-nfs.h */

