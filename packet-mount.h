/* packet-mount.h */
/* $Id: packet-mount.h,v 1.3 1999/11/20 06:17:00 guy Exp $ */

#ifndef PACKET_MOUNT_H
#define PACKET_MOUNT_H

#define MOUNT_PROGRAM  100005

#define MOUNTPROC_NULL		0
#define MOUNTPROC_MNT		1
#define MOUNTPROC_DUMP		2
#define MOUNTPROC_UMNT		3
#define MOUNTPROC_UMNTALL	4
#define MOUNTPROC_EXPORT	5
#define MOUNTPROC_EXPORTALL	6
#define MOUNTPROC_PATHCONF	7

#endif
