/* packet-nfs.h (c) 1999 Uwe Girlich */
/* $Id: packet-nfs.h,v 1.1 1999/10/29 01:11:23 guy Exp $ */

#ifndef __PACKET_NFS_H__
#define __PACKET_NFS_H__

#include "packet-rpc.h"

#define NFS_PROGRAM 100003

#define FHSIZE 32

/* the RPC mount protocol needs both function to decode a MNT reply */
int dissect_fh2(const u_char *pd, int offset, frame_data *fd, proto_tree *tree);
int dissect_fh3(const u_char *pd, int offset, frame_data *fd, proto_tree *tree);

#endif /* packet-nfs.h */

