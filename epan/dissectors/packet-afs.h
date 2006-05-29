/* packet-afs.h
 * Definitions for packet disassembly structures and routines
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef PACKET_AFS_H
#define PACKET_AFS_H

#define AFS_PORT_FS	7000
#define AFS_PORT_CB	7001
#define AFS_PORT_PROT	7002
#define AFS_PORT_VLDB	7003
#define AFS_PORT_KAUTH	7004
#define AFS_PORT_VOL	7005
#define AFS_PORT_ERROR	7006		/* Doesn't seem to be used */
#define AFS_PORT_BOS	7007
#define AFS_PORT_UPDATE	7008
#define AFS_PORT_RMTSYS	7009
#define AFS_PORT_BACKUP 7021

#ifndef AFSNAMEMAX
#define AFSNAMEMAX 256
#endif

#ifndef AFSOPAQUEMAX
#define AFSOPAQUEMAX 1024
#endif

#define PRNAMEMAX 64
#define VLNAMEMAX 65
#define KANAMEMAX 64
#define BOSNAMEMAX 256

#define	PRSFS_READ		1 /* Read files */
#define	PRSFS_WRITE		2 /* Write files */
#define	PRSFS_INSERT		4 /* Insert files into a directory */
#define	PRSFS_LOOKUP		8 /* Lookup files into a directory */
#define	PRSFS_DELETE		16 /* Delete files */
#define	PRSFS_LOCK		32 /* Lock files */
#define	PRSFS_ADMINISTER	64 /* Change ACL's */

#define CB_TYPE_EXCLUSIVE 1
#define CB_TYPE_SHARED 2
#define CB_TYPE_DROPPED 3

#define OPCODE_LOW 		0
#define OPCODE_HIGH     66000 /* arbitrary, is just a fuzzy check for encrypted traffic */
#define VOTE_LOW        10000
#define VOTE_HIGH       10007
#define DISK_LOW        20000
#define DISK_HIGH       20013

#define FILE_TYPE_FILE 1
#define FILE_TYPE_DIR 2
#define FILE_TYPE_LINK 3

struct afs_header {
	guint32 opcode;
};

struct afs_volsync {
     guint32 spare1;
     guint32 spare2;
     guint32 spare3;
     guint32 spare4;
     guint32 spare5;
     guint32 spare6;
};

struct afs_status {
     guint32 InterfaceVersion;
     guint32 FileType;
     guint32 LinkCount;
     guint32 Length;
     guint32 DataVersion;
     guint32 Author;
     guint32 Owner;
     guint32 CallerAccess;
     guint32 AnonymousAccess;
     guint32 UnixModeBits;
     guint32 ParentVnode;
     guint32 ParentUnique;
     guint32 SegSize;
     guint32 ClientModTime;
     guint32 ServerModTime;
     guint32 Group;
     guint32 SyncCount;
     guint32 spare1;
     guint32 spare2;
     guint32 spare3;
     guint32 spare4;
};

struct afs_volumeinfo {
    guint32  Vid;
    guint32  Type;
    guint32  Type0;
    guint32  Type1;
    guint32  Type2;
    guint32  Type3;
    guint32  Type4;
    guint32  ServerCount;
    guint32  Server0;
    guint32  Server1;
    guint32  Server2;
    guint32  Server3;
    guint32  Server4;
    guint32  Server5;
    guint32  Server6;
    guint32  Server7;
    guint16 Part0;
    guint16 Part1;
    guint16 Part2;
    guint16 Part3;
    guint16 Part4;
    guint16 Part5;
    guint16 Part6;
    guint16 Part7;
};


#endif
