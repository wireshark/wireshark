/* packet-vines.h
 * Definitions for packet disassembly structures and routines
 *
 * $Id: packet-vines.h,v 1.3 1999/10/22 08:30:04 guy Exp $
 *
 * Don Lafontaine <lafont02@cn.ca>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 * Joerg Mayer <jmayer@telemation.de>
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

/* Information about VINES can be found in
 *
 * VINES Protocol Definition
 * Order Number: DA254-00
 * Banyan Systems incorporated
 * February 1990
 * Part Number: 092093-000
 */

#ifndef __PACKETVINES_H__
#define __PACKETVINES_H__

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
  guint32 vip_dnet;
  guint16 vip_dsub;
  guint32 vip_snet;
  guint16 vip_ssub;
} e_vip;

/* VINES SPP structs and definitions */

enum {
  VSPP_PKTTYPE_DATA = 1,	/* User Data */
  VSPP_PKTTYPE_DISC = 3,	/* Diconnect Request */
  VSPP_PKTTYPE_PROBE = 4,	/* Probe (retransmit) */
  VSPP_PKTTYPE_ACK = 5		/* Acknowledgement */
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

/* VINES SMB structs and definitions */

typedef struct _e_vsmb {
  guint32 vsmb_tag;
  guint8  vsmb_func;
  guint8  vsmb_d1;
  guint32 vsmb_d2;
  guint32 vsmb_d3;
  guint16 vsmb_d4;
  guint32 vsmb_d5;
  guint32 vsmb_d6;
  guint16 vsmb_treeid; 
  guint16 vsmb_pid;
  guint16 vsmb_uid;
  guint16 vsmb_mid; 
  guint8  vsmb_wcnt;
  guint16 vsmb_pbytes;
  guint16 vsmb_dbytes;
  guint16 vsmb_maxpbytes;
  guint16 vsmb_maxdbytes;
  guint16 vsmb_setupw;
  guint16 vsmb_tflags;
  guint32 vsmb_ttw;
} e_vsmb;

/*
 * Routine to take a Vines address and generate a string.
 */
extern gchar *vines_addr_to_str(const guint8 *addrp);

#endif /* packet-vines.h */
