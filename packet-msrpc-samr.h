/* packet-msrpc-samr.h
 * Routines for SMB \\PIPE\\samr packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-msrpc-samr.h,v 1.1 2001/11/12 08:58:43 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_MSRPC_SAMR_H
#define __PACKET_MSRPC_SAMR_H

/* Functions available on the SAMR pipe.  From Samba, include/rpc_samr.h */

#define SAMR_CONNECT_ANON      0x00
#define SAMR_CLOSE_HND         0x01
#define SAMR_UNKNOWN_2         0x02
#define SAMR_QUERY_SEC_OBJECT  0x03
#define SAMR_UNKNOWN_4         0x04
#define SAMR_LOOKUP_DOMAIN     0x05
#define SAMR_ENUM_DOMAINS      0x06
#define SAMR_OPEN_DOMAIN       0x07
#define SAMR_QUERY_DOMAIN_INFO 0x08
#define SAMR_CREATE_DOM_GROUP  0x0a
#define SAMR_ENUM_DOM_GROUPS   0x0b
#define SAMR_ENUM_DOM_USERS    0x0d
#define SAMR_CREATE_DOM_ALIAS  0x0e
#define SAMR_ENUM_DOM_ALIASES  0x0f
#define SAMR_QUERY_USERALIASES 0x10
#define SAMR_LOOKUP_NAMES      0x11
#define SAMR_LOOKUP_RIDS       0x12
#define SAMR_OPEN_GROUP        0x13
#define SAMR_QUERY_GROUPINFO   0x14
#define SAMR_SET_GROUPINFO     0x15
#define SAMR_ADD_GROUPMEM      0x16
#define SAMR_DELETE_DOM_GROUP  0x17
#define SAMR_DEL_GROUPMEM      0x18
#define SAMR_QUERY_GROUPMEM    0x19
#define SAMR_UNKNOWN_1A        0x1a
#define SAMR_OPEN_ALIAS        0x1b
#define SAMR_QUERY_ALIASINFO   0x1c
#define SAMR_SET_ALIASINFO     0x1d
#define SAMR_DELETE_DOM_ALIAS  0x1e
#define SAMR_ADD_ALIASMEM      0x1f
#define SAMR_DEL_ALIASMEM      0x20
#define SAMR_QUERY_ALIASMEM    0x21
#define SAMR_OPEN_USER         0x22
#define SAMR_DELETE_DOM_USER   0x23
#define SAMR_QUERY_USERINFO    0x24
#define SAMR_SET_USERINFO2     0x25
#define SAMR_QUERY_USERGROUPS  0x27
#define SAMR_QUERY_DISPINFO    0x28
#define SAMR_UNKNOWN_29        0x29
#define SAMR_UNKNOWN_2a        0x2a
#define SAMR_UNKNOWN_2b        0x2b
#define SAMR_GET_USRDOM_PWINFO 0x2c
#define SAMR_UNKNOWN_2D        0x2d
#define SAMR_UNKNOWN_2e        0x2e
#define SAMR_UNKNOWN_2f        0x2f
#define SAMR_QUERY_DISPINFO3   0x30
#define SAMR_UNKNOWN_31        0x31
#define SAMR_CREATE_USER       0x32
#define SAMR_QUERY_DISPINFO4   0x33
#define SAMR_ADDMULTI_ALIASMEM 0x34
#define SAMR_UNKNOWN_35        0x35
#define SAMR_UNKNOWN_36        0x36
#define SAMR_CHGPASSWD_USER    0x37
#define SAMR_GET_DOM_PWINFO    0x38
#define SAMR_CONNECT           0x39
#define SAMR_SET_USERINFO      0x3A

#endif /* packet-msrpc-samr.h */
