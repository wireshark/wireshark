/* packet-nfs.h (c) 1999 Uwe Girlich */
/* $Id: packet-nfs.h,v 1.4 1999/12/14 11:48:03 girlich Exp $ */

#ifndef __PACKET_NFS_H__
#define __PACKET_NFS_H__

#include "packet-rpc.h"

#define NFS_PROGRAM 100003

#define FHSIZE 32

/* verifier */
#define NFS3_CREATEVERFSIZE 8
#define NFS3_WRITEVERFSIZE 8

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

