/* packet-nfs.h (c) 1999 Uwe Girlich */
/* $Id: packet-nfs.h,v 1.3 1999/12/09 10:08:05 girlich Exp $ */

#ifndef __PACKET_NFS_H__
#define __PACKET_NFS_H__

#include "packet-rpc.h"

#define NFS_PROGRAM 100003

#define FHSIZE 32

#define UNCHECKED 0
#define GUARDED 1
#define EXCLUSIVE 2

/* the RPC mount protocol needs both function to decode a MNT reply */
int dissect_fhandle(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name);
int dissect_nfs_fh3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name);

#endif /* packet-nfs.h */

