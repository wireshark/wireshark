/* packet-nfs.h (c) 1999 Uwe Girlich */
/* $Id: packet-nfs.h,v 1.2 1999/11/15 14:17:18 nneul Exp $ */

#ifndef __PACKET_NFS_H__
#define __PACKET_NFS_H__

#include "packet-rpc.h"

#define NFS_PROGRAM 100003

#define FHSIZE 32

/* the RPC mount protocol needs both function to decode a MNT reply */
int dissect_fhandle(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name);
int dissect_nfs_fh3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, char* name);

#endif /* packet-nfs.h */

