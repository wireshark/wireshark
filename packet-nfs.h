/* packet-nfs.h (c) 1999 Uwe Girlich */
/* $Id: packet-nfs.h,v 1.6 2000/01/18 11:54:07 girlich Exp $ */

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

