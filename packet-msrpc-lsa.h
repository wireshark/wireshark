/* packet-msrpc-lsa.h
 * Routines for SMB \\PIPE\\lsarpc packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-msrpc-lsa.h,v 1.1 2001/11/12 08:58:43 guy Exp $
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

#ifndef __PACKET_MSRPC_LSA_H
#define __PACKET_MSRPC_LSA_H

/* Functions available on the LSA pipe.  From Samba, include/rpc_lsa.h */

#define LSA_CLOSE              0x00
#define LSA_DELETE             0x01
#define LSA_ENUM_PRIVS         0x02
#define LSA_QUERYSECOBJ        0x03
#define LSA_SETSECOBJ          0x04
#define LSA_CHANGEPASSWORD     0x05
#define LSA_OPENPOLICY         0x06
#define LSA_QUERYINFOPOLICY    0x07
#define LSA_SETINFOPOLICY      0x08
#define LSA_CLEARAUDITLOG      0x09
#define LSA_CREATEACCOUNT      0x0a
#define LSA_ENUM_ACCOUNTS      0x0b
#define LSA_CREATETRUSTDOM     0x0c
#define LSA_ENUMTRUSTDOM       0x0d
#define LSA_LOOKUPNAMES        0x0e
#define LSA_LOOKUPSIDS         0x0f
#define LSA_CREATESECRET       0x10
#define LSA_OPENACCOUNT	       0x11
#define LSA_ENUMPRIVSACCOUNT   0x12
#define LSA_ADDPRIVS           0x13
#define LSA_REMOVEPRIVS        0x14
#define LSA_GETQUOTAS          0x15
#define LSA_SETQUOTAS          0x16
#define LSA_GETSYSTEMACCOUNT   0x17
#define LSA_SETSYSTEMACCOUNT   0x18
#define LSA_OPENTRUSTDOM       0x19
#define LSA_QUERYTRUSTDOM      0x1a
#define LSA_SETINFOTRUSTDOM    0x1b
#define LSA_OPENSECRET         0x1c
#define LSA_SETSECRET          0x1d
#define LSA_QUERYSECRET        0x1e
#define LSA_LOOKUPPRIVVALUE    0x1f
#define LSA_LOOKUPPRIVNAME     0x20
#define LSA_PRIV_GET_DISPNAME  0x21
#define LSA_DELETEOBJECT       0x22
#define LSA_ENUMACCTWITHRIGHT  0x23
#define LSA_ENUMACCTRIGHTS     0x24
#define LSA_ADDACCTRIGHTS      0x25
#define LSA_REMOVEACCTRIGHTS   0x26
#define LSA_QUERYTRUSTDOMINFO  0x27
#define LSA_SETTRUSTDOMINFO    0x28
#define LSA_DELETETRUSTDOM     0x29
#define LSA_STOREPRIVDATA      0x2a
#define LSA_RETRPRIVDATA       0x2b
#define LSA_OPENPOLICY2        0x2c
#define LSA_UNK_GET_CONNUSER   0x2d

#endif /* packet-msrpc-lsa.h */
