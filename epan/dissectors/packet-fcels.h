/* packet-fcels.h
 * Fibre Channel Extended Link Services Definitions (ddutt@cisco.com)
 * Copyright 2001, Dinesh G Dutt <ddutt@cisco.com>
 *
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

#ifndef __PACKET_FCELS_H_
#define __PACKET_FCELS_H_

#define FC_ELS_LSRJT         0x01
#define FC_ELS_ACC           0x02
#define FC_ELS_PLOGI         0x03
#define FC_ELS_FLOGI	     0x04
#define FC_ELS_LOGOUT        0x05
#define FC_ELS_ABTX          0x06
#define FC_ELS_RSI           0x0A
#define FC_ELS_RTV           0x0E
#define FC_ELS_RLS           0x0F
#define FC_ELS_ECHO          0x10
#define FC_ELS_TEST          0x11
#define FC_ELS_RRQ           0x12
#define FC_ELS_REC           0x13
#define FC_ELS_SRR           0x14
#define FC_ELS_PRLI          0x20
#define FC_ELS_PRLO          0x21
#define FC_ELS_TPRLO         0x24
#define FC_ELS_PDISC         0x50
#define FC_ELS_FDISC         0x51
#define FC_ELS_ADISC         0x52
#define FC_ELS_FARP_REQ      0x54
#define FC_ELS_FARP_RPLY     0x55
#define FC_ELS_RPS           0x56
#define FC_ELS_RPL           0x57
#define FC_ELS_FAN           0x60
#define FC_ELS_RSCN          0x61
#define FC_ELS_SCR           0x62
#define FC_ELS_RNFT          0x63
#define FC_ELS_LINIT         0x70
#define FC_ELS_LSTS          0x72
#define FC_ELS_RNID          0x78
#define FC_ELS_RLIR          0x79
#define FC_ELS_LIRR          0x7A
#define FC_ELS_SRL           0x7B
#define FC_ELS_RPSC          0x7D
#define FC_ELS_LKA           0x80
#define FC_ELS_AUTH          0x90
#define FC_ELS_CBIND         0xE0
#define FC_ELS_UNBIND        0xE4

extern value_string_ext fc_els_proto_val_ext;

#endif
