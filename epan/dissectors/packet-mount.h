/* packet-mount.h */
/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

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

#define SGI_MOUNT_PROGRAM	391004
#define MOUNTPROC_EXPORTLIST	99
#define MOUNTPROC_STATVFS	100
#endif
