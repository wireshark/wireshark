/* packet-tns.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef PACKET_TNS_H
#define PACKET_TNS_H

/* Packet Types */
#define TNS_TYPE_CONNECT        1
#define TNS_TYPE_ACCEPT         2
#define TNS_TYPE_ACK            3
#define TNS_TYPE_REFUSE         4
#define TNS_TYPE_REDIRECT       5
#define TNS_TYPE_DATA           6
#define TNS_TYPE_NULL           7
#define TNS_TYPE_ABORT          9
#define TNS_TYPE_RESEND         11
#define TNS_TYPE_MARKER         12
#define TNS_TYPE_ATTENTION      13
#define TNS_TYPE_CONTROL        14
#define TNS_TYPE_MAX            19

/* Data Packet Functions */
#define SQLNET_SET_PROTOCOL     1
#define SQLNET_SET_DATATYPES    2
#define SQLNET_USER_OCI_FUNC    3
#define SQLNET_RETURN_STATUS    4
#define SQLNET_ACCESS_USR_ADDR  5
#define SQLNET_ROW_TRANSF_HDR   6
#define SQLNET_ROW_TRANSF_DATA  7
#define SQLNET_RETURN_OPI_PARAM 8
#define SQLNET_FUNCCOMPLETE     9
#define SQLNET_NERROR_RET_DEF   10
#define SQLNET_IOVEC_4FAST_UPI  11
#define SQLNET_LONG_4FAST_UPI   12
#define SQLNET_INVOKE_USER_CB   13
#define SQLNET_LOB_FILE_DF      14
#define SQLNET_WARNING          15
#define SQLNET_DESCRIBE_INFO    16
#define SQLNET_PIGGYBACK_FUNC   17
#define SQLNET_SIG_4UCS         18
#define SQLNET_FLUSH_BIND_DATA  19
#define SQLNET_SNS              0xdeadbeef
#define SQLNET_XTRN_PROCSERV_R1 32
#define SQLNET_XTRN_PROCSERV_R2 68

#endif
