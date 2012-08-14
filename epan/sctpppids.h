/* sctpppids.h
 * Declarations of SCTP payload protocol IDs.
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __SCTPPPIDS_H__
#define __SCTPPPIDS_H__

/*
 * SCTP payload protocol IDs.
 * Based on http://www.iana.org/assignments/sctp-parameters
 * as of October 28th, 2009
 */
#define NOT_SPECIFIED_PROTOCOL_ID        0
#define IUA_PAYLOAD_PROTOCOL_ID          1
#define M2UA_PAYLOAD_PROTOCOL_ID         2
#define M3UA_PAYLOAD_PROTOCOL_ID         3
#define SUA_PAYLOAD_PROTOCOL_ID          4
#define M2PA_PAYLOAD_PROTOCOL_ID         5
#define V5UA_PAYLOAD_PROTOCOL_ID         6
#define H248_PAYLOAD_PROTOCOL_ID         7
#define BICC_PAYLOAD_PROTOCOL_ID         8
#define TALI_PAYLOAD_PROTOCOL_ID         9
#define DUA_PAYLOAD_PROTOCOL_ID         10
#define ASAP_PAYLOAD_PROTOCOL_ID        11
#define ENRP_PAYLOAD_PROTOCOL_ID        12
#define H323_PAYLOAD_PROTOCOL_ID        13
#define QIPC_PAYLOAD_PROTOCOL_ID        14
#define SIMCO_PAYLOAD_PROTOCOL_ID       15
#define DDP_SEG_CHUNK_PROTOCOL_ID       16
#define DDP_STREAM_SES_CTRL_PROTOCOL_ID 17
#define S1AP_PAYLOAD_PROTOCOL_ID        18
#define RUA_PAYLOAD_PROTOCOL_ID         19
#define HNBAP_PAYLOAD_PROTOCOL_ID       20
#define FORCES_HP_PAYLOAD_PROTOCOL_ID   21
#define FORCES_MP_PAYLOAD_PROTOCOL_ID   22
#define FORCES_LP_PAYLOAD_PROTOCOL_ID   23
#define SBC_AP_PAYLOAD_PROTOCOL_ID      24
#define NBAP_PAYLOAD_PROTOCOL_ID		25
/* Unassigned 26 */
#define X2AP_PAYLOAD_PROTOCOL_ID        27
#define IRCP_PAYLOAD_PROTOCOL_ID        28
#define DIAMETER_PROTOCOL_ID            46
#define DIAMETER_DTLS_PROTOCOL_ID       47
#define R14P_BER_PROTOCOL_ID            48
#define M2TP_PAYLOAD_PROTOCOL_ID        99    /* s-link */
#endif /* sctpppids.h */
