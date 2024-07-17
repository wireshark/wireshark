/* packet-nfs.h (c) 1999 Uwe Girlich */
/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_NFS_H__
#define __PACKET_NFS_H__

#include "packet-rpc.h"

#define NFS_PROGRAM 100003
#define NFS_CB_PROGRAM 0x40000000

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
#define NFS4_OK                      0
#define NFS4ERR_DENIED	         10010
#define NFS4ERR_CLID_INUSE       10017
#define NFS4ERR_OFFLOAD_NO_REQS  10094

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
/* Minor version 2 */
#define NFS4_OP_ALLOCATE                    59
#define NFS4_OP_COPY                        60
#define NFS4_OP_COPY_NOTIFY                 61
#define NFS4_OP_DEALLOCATE                  62
#define NFS4_OP_IO_ADVISE                   63
#define NFS4_OP_LAYOUTERROR                 64
#define NFS4_OP_LAYOUTSTATS                 65
#define NFS4_OP_OFFLOAD_CANCEL              66
#define NFS4_OP_OFFLOAD_STATUS              67
#define NFS4_OP_READ_PLUS                   68
#define NFS4_OP_SEEK                        69
#define NFS4_OP_WRITE_SAME                  70
#define NFS4_OP_CLONE                       71
#define NFS4_OP_GETXATTR                    72
#define NFS4_OP_SETXATTR                    73
#define NFS4_OP_LISTXATTRS                  74
#define NFS4_OP_REMOVEXATTR                 75
#define NFS4_LAST_OP                        75
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
#define NFS4_OP_CB_OFFLOAD                  15
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
#define NFS_ACCESS_MASK_READ        0x001
#define NFS_ACCESS_MASK_LOOKUP      0x002
#define NFS_ACCESS_MASK_MODIFY      0x004
#define NFS_ACCESS_MASK_EXTEND      0x008
#define NFS_ACCESS_MASK_DELETE      0x010
#define NFS_ACCESS_MASK_EXECUTE     0x020
#define NFS_ACCESS_MASK_XATTR_READ  0x040
#define NFS_ACCESS_MASK_XATTR_WRITE 0x080
#define NFS_ACCESS_MASK_XATTR_LIST  0x100

/* pNFS layout types */
#define LAYOUT4_NO_LAYOUT_TYPE            0
#define LAYOUT4_NFSV4_1_FILES             1
#define LAYOUT4_OSD2_OBJECTS              2
#define LAYOUT4_BLOCK_VOLUME              3
#define LAYOUT4_FLEX_FILES                4
#define LAYOUT4_SCSI                      5

#define NFL4_UFLG_MASK                   0x0000003F
#define NFL4_UFLG_DENSE                  0x00000001
#define NFL4_UFLG_COMMIT_THRU_MDS        0x00000002
#define NFL4_UFLG_STRIPE_UNIT_SIZE_MASK  0xFFFFFFC0

/* GET_DIR_DELEGATION non-fatal status */
#define GDD4_OK		0
#define GDD4_UNAVAIL	1

/* NFSv4.2 */

/* netloc types */
#define NL4_NAME    1
#define NL4_URL     2
#define NL4_NETADDR 3

extern bool nfs_file_name_snooping;
extern void nfs_name_snoop_add_name(int xid, tvbuff_t *tvb, int name_offset, int name_len,
	                                int parent_offset, int parent_len, const char *name);
extern bool nfs_fhandle_reqrep_matching;
extern int dissect_fhandle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
                           const char *name, uint32_t *hash, rpc_call_info_value *civ);
extern void dissect_fhandle_hidden(packet_info *pinfo, proto_tree *tree, int frame);
extern int dissect_nfs3_fh(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
                           const char *name, uint32_t *hash, rpc_call_info_value *civ);
extern int dissect_nfs3_post_op_attr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
	                                 const char* name);
extern int dissect_nfs2_fattr(tvbuff_t *tvb, int offset, proto_tree *tree, const char* name);
extern proto_tree* display_access_items(tvbuff_t* tvb, int offset, packet_info* pinfo,
	                                    proto_tree* tree, uint32_t amask, char mtype, int version,
										wmem_strbuf_t* optext, const char* label);
extern int dissect_access_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree* tree,
                                int version, wmem_strbuf_t *optext, rpc_call_info_value *civ);
extern int hf_nfs_status;

#endif /* packet-nfs.h */

