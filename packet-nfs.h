/* packet-nfs.h (c) 1999 Uwe Girlich */
/* $Id: packet-nfs.h,v 1.7 2000/12/01 00:38:18 guy Exp $ */

#ifndef __PACKET_NFS_H__
#define __PACKET_NFS_H__

#include "packet-rpc.h"

#define NFS_PROGRAM 100003

#define FHSIZE 32

/* verifier */
#define NFS3_COOKIEVERFSIZE 8
#define NFS3_CREATEVERFSIZE 8
#define NFS3_WRITEVERFSIZE 8

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
#define NFS4_OK 0
#define NFS4ERR_DENIED 10010
#define NFS4ERR_CLID_INUSE 10017

/*
 * NFSv4 file types
 */
#define NF4REG			1
#define NF4DIR			2
#define NF4BLK			3
#define NF4CHR			4
#define NF4LNK			5
#define NF4SOCK		6
#define NF4FIFO		7
#define NF4ATTRDIR	8
#define NF4NAMEDATTR	9

/*
 * Since NFSv4 "operations" are handled differently than previous NFS
 * versions, these tokens are necessary.
 */
#define NFS4_OP_ACCESS						3
#define NFS4_OP_CLOSE						4
#define NFS4_OP_COMMIT						5
#define NFS4_OP_CREATE						6
#define NFS4_OP_DELEGPURGE					7
#define NFS4_OP_DELEGRETURN				8
#define NFS4_OP_GETATTR						9
#define NFS4_OP_GETFH						10
#define NFS4_OP_LINK							11
#define NFS4_OP_LOCK							12
#define NFS4_OP_LOCKT						13
#define NFS4_OP_LOCKU						14
#define NFS4_OP_LOOKUP						15
#define NFS4_OP_LOOKUPP						16
#define NFS4_OP_NVERIFY						17
#define NFS4_OP_OPEN							18
#define NFS4_OP_OPENATTR					19
#define NFS4_OP_OPEN_CONFIRM				20
#define NFS4_OP_OPEN_DOWNGRADE			21
#define NFS4_OP_PUTFH						22
#define NFS4_OP_PUTPUBFH					23
#define NFS4_OP_PUTROOTFH					24
#define NFS4_OP_READ							25
#define NFS4_OP_READDIR						26
#define NFS4_OP_READLINK					27
#define NFS4_OP_REMOVE						28
#define NFS4_OP_RENAME						29
#define NFS4_OP_RENEW						30
#define NFS4_OP_RESTOREFH					31
#define NFS4_OP_SAVEFH						32
#define NFS4_OP_SECINFO						33
#define NFS4_OP_SETATTR						34
#define NFS4_OP_SETCLIENTID				35
#define NFS4_OP_SETCLIENTID_CONFIRM		36
#define NFS4_OP_VERIFY						37
#define NFS4_OP_WRITE						38

/* for write */
#define UNSTABLE 0
#define DATA_SYNC 1
#define FILE_SYNC 2

/* for create */
#define UNCHECKED 0
#define GUARDED 1
#define EXCLUSIVE 2


/* the RPC mount protocol needs both function to decode a MNT reply */
int dissect_fhandle(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name);
int dissect_nfs_fh3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name);

#endif /* packet-nfs.h */

