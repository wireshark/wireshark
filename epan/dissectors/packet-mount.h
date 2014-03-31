/* packet-mount.h */
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
