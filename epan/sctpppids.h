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
 */
#define NOT_SPECIFIED_PROTOCOL_ID  0
#define IUA_PAYLOAD_PROTOCOL_ID    1
#define M2UA_PAYLOAD_PROTOCOL_ID   2
#define M3UA_PAYLOAD_PROTOCOL_ID   3
#define SUA_PAYLOAD_PROTOCOL_ID    4
#define M2PA_PAYLOAD_PROTOCOL_ID   5
#define V5UA_PAYLOAD_PROTOCOL_ID   6
#define H248_PAYLOAD_PROTOCOL_ID   7
#define BICC_PAYLOAD_PROTOCOL_ID   8
#define TALI_PAYLOAD_PROTOCOL_ID   9
#define DUA_PAYLOAD_PROTOCOL_ID   10
#define ASAP_PAYLOAD_PROTOCOL_ID  11
#define ENRP_PAYLOAD_PROTOCOL_ID  12
#define H323_PAYLOAD_PROTOCOL_ID  13
#define QIPC_PAYLOAD_PROTOCOL_ID  14
#define SIMCO_PAYLOAD_PROTOCOL_ID 15
#define M2TP_PAYLOAD_PROTOCOL_ID  99    /* s-link */

#endif /* sctpppids.h */
