/* packet-vines.h
 * Definitions for packet disassembly structures and routines
 *
 * $Id: packet-vines.h,v 1.1 1998/09/17 02:37:46 gerald Exp $
 *
 * Don Lafontaine <lafont02@cn.ca>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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


#ifndef __PACKETVINES_H__
#define __PACKETVINES_H__

/* VINES IP structs and definitions */

typedef struct _e_vip {
  guint16 vip_sum;
  guint16 vip_len;
  guint8  vip_tos;
  guint8  vip_proto;    /* 2 = VSPP */
  guint32 vip_dnet;
  guint16 vip_dsub;
  guint32 vip_snet;
  guint16 vip_ssub;

} e_vip;

/* VINES SPP structs and definitions */

typedef struct _e_vspp {
  guint16 vspp_sport;
  guint16 vspp_dport;
  guint8  vspp_pkttype; /* 5=ack 1=data */
  guint8  vspp_tos;  /* Unused with type 5 packets */
  guint16 vspp_lclid;
  guint16 vspp_rmtid;
  guint16 vspp_seq; 
  guint16 vspp_ack;
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

#endif /* packet-vines.h */
