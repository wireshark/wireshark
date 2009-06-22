/* packet-fmp_notify.h
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

#ifndef PACKET_FMP_NOTIFY_H
#define PACKET_FMP_NOTIFY_H

#define FMP_NOTIFY_PROG 	1001912
#define FMP_NOTIFY_VERSION_2 	2

/*
 * FMP/NOTIFY Procedures
 */
#define FMP_NOTIFY_DownGrade		1
#define FMP_NOTIFY_RevokeList		2
#define FMP_NOTIFY_RevokeAll 		3
#define FMP_NOTIFY_FileSetEof 		4
#define FMP_NOTIFY_RequestDone 		5
#define FMP_NOTIFY_volFreeze 		6
#define FMP_NOTIFY_revokeHandleList	7

typedef enum {
	FMP_LIST_USER_QUOTA_EXCEEDED = 0,
	FMP_LIST_GROUP_QUOTA_EXCEEDED = 1,
	FMP_LIST_SERVER_RESOURCE_LOW = 2
} revokeHandleListReason;
int dissect_fmp_notify_status(tvbuff_t *, int, proto_tree *, int *);
int dissect_fmp_extentList(tvbuff_t *, int, packet_info *, proto_tree *);

#endif
