/* packet-vines.h
 * Definitions for packet disassembly structures and routines
 *
 * $Id$
 *
 * Don Lafontaine <lafont02@cn.ca>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 * Joerg Mayer <jmayer@loplof.de>
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

/* Information about VINES can be found in
 *
 * VINES Protocol Definition
 * Order Number: DA254-00
 * Banyan Systems incorporated
 * February 1990
 * Part Number: 092093-000
 *
 * Some information can also be found in
 *
 *	http://www.cisco.com/univercd/cc/td/doc/cisintwk/ito_doc/vines.htm
 *
 * and at
 *
 *	http://www.synapse.de/ban/HTML/P_VINES/Eng/P_vines.html
 *
 * The document at
 *
 *	http://www.watersprings.org/pub/id/draft-ietf-rmonmib-rmonprot-v2-00.txt
 *
 * lists a bunch of values of protocol identifier fields for various
 * protocols.  It speaks of the Vines Fragmentation Protocol,
 * the "Vines Token Ring Protocol" which appears to be the same as the
 * "Vines LLC" protocol here, the Vines echo protocol, Vines IP, and
 * protocols running atop Vines IP.
 *
 * The LLC values it describes are:
 *
 *	0xbc	(SAP_VINES2) Vines Token Ring a/k/a Vines LLC
 *
 * It doesn't mention 0xba (SAP_VINES1).
 *
 * The Vines Token Ring/Vines LLC protocol identifier values it
 * describes are:
 *
 *	0xba	Vines IP
 *	0xbb	Vines Echo
 *
 * The Ethernet type values it describes are:
 *
 *	0x0bad	(ETHERTYPE_VINES) Vines IP
 *	0x0baf	Vines Echo
 */

#ifndef __PACKETVINES_H__
#define __PACKETVINES_H__

#include <epan/to_str.h>

#define VINES_ADDR_LEN	6

/* VINES IP structs and definitions */

enum {
  VIP_PROTO_IPC = 1,	 /* Interprocess Communications Protocol (IPC) */
  VIP_PROTO_SPP = 2,	/* Sequenced Packet Protcol (SPP) */
  VIP_PROTO_ARP = 4,	/* Address Resolution Protocol (ARP) */
  VIP_PROTO_RTP = 5,	/* Routing Update Protocol (RTP) / SRTP (Sequenced RTP) */
  VIP_PROTO_ICP = 6	/* Internet Control Protocol (ICP) */
};

typedef struct _e_vip {
  guint16 vip_chksum;
  guint16 vip_pktlen;
  guint8  vip_tctl;	/* Transport Control */
  guint8  vip_proto;
  guint8  vip_dst[VINES_ADDR_LEN];
  guint8  vip_src[VINES_ADDR_LEN];
} e_vip;

/* VINES SPP and IPC structs and definitions */

enum {
  PKTTYPE_DGRAM = 0,	/* Unreliable datagram */
  PKTTYPE_DATA = 1,	/* User Data */
  PKTTYPE_ERR = 2,	/* Error */
  PKTTYPE_DISC = 3,	/* Diconnect Request */
  PKTTYPE_PROBE = 4,	/* Probe (retransmit) */
  PKTTYPE_ACK = 5	/* Acknowledgement */
};

typedef struct _e_vspp {
  guint16 vspp_sport;
  guint16 vspp_dport;
  guint8  vspp_pkttype;
  guint8  vspp_control;
  guint16 vspp_lclid;	/* Local Connection ID */
  guint16 vspp_rmtid;	/* Remote Connection ID */
  guint16 vspp_seqno;	/* Sequence Number */
  guint16 vspp_ack;	/* Acknowledgement Number */
  guint16 vspp_win;
} e_vspp;

typedef struct _e_vipc {
  guint16 vipc_sport;
  guint16 vipc_dport;
  guint8  vipc_pkttype;
  guint8  vipc_control;
  guint16 vipc_lclid;	/* Local Connection ID */
  guint16 vipc_rmtid;	/* Remote Connection ID */
  guint16 vipc_seqno;	/* Sequence Number */
  guint16 vipc_ack;	/* Acknowledgement Number */
  guint16 vipc_err_len;
} e_vipc;

void capture_vines(packet_counts *);

#endif /* packet-vines.h */
