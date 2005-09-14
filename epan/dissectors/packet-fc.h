/* packet-fc.h
 * Basic Fibre Channel Header definitions
 * Copyright 2002 Dinesh G Dutt (ddutt@cisco.com)
 *
 * $Id$
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

#ifndef __PACKET_FC_H_
#define __PACKET_FC_H_

/* R_CTL upper bits creates a classification tree */
#define FC_RCTL_DEV_DATA       0x00
#define FC_RCTL_ELS            0x20
#define FC_RCTL_LINK_DATA      0x30
#define FC_RCTL_VIDEO          0x40
#define FC_RCTL_BLS            0x80
#define FC_RCTL_LINK_CTL       0xC0
/* XXX - is 0xF0 Extended Routing?  It is in the FC-FS draft on the T11
   Web site. */

#define FC_TYPE_CMNSVC         0x0  /* Used in PRLI Svc Param Page */

/* TYPE definitions for Basic or Extended Link_Data */
#define FC_TYPE_ELS            0x1

/* TYPE definitions for FC-4 */
#define FC_TYPE_LLCSNAP        0x4
#define FC_TYPE_IP             0x5
#define FC_TYPE_SCSI           0x8
#define FC_TYPE_SB_TO_CU       0x1B
#define FC_TYPE_SB_FROM_CU     0x1C
#define FC_TYPE_FCCT           0x20
#define FC_TYPE_SWILS          0x22
#define FC_TYPE_AL             0x23
#define FC_TYPE_SNMP           0x24
#define FC_TYPE_VENDOR         0xFF


/*
 * the following allows TAP code access to the messages
 * without having to duplicate it. With MSVC and a 
 * libethereal.dll, we need a special declaration.
 */
ETH_VAR_IMPORT const value_string fc_fc4_val[];

/* DF_CTL bits */
#define FC_DFCTL_DH         0x03   /* Device_Header type bits: */
#define FC_DFCTL_DH_NONE    0x00   /* No Device_Header */
#define FC_DFCTL_DH_16_BYTE 0x01   /* 16 Byte Device_Header */
#define FC_DFCTL_DH_32_BYTE 0x02   /* 32 Byte Device_Header */
#define FC_DFCTL_DH_64_BYTE 0x03   /* 64 Byte Device_Header */
#define FC_DFCTL_AH         0x10   /* Association_Header bit */
#define FC_DFCTL_NH         0x20   /* Association_Header bit */
#define FC_DFCTL_SH         0x40   /* reserved for security header */

/* Derived Frame types (used for ULP demux) */
#define FC_FTYPE_UNDEF         0x0
#define FC_FTYPE_SWILS         0x1
#define FC_FTYPE_IP            0x2
#define FC_FTYPE_SCSI          0x3
#define FC_FTYPE_BLS           0x4
#define FC_FTYPE_ELS           0x5
#define FC_FTYPE_FCCT          0x7
#define FC_FTYPE_LINKDATA      0x8
#define FC_FTYPE_VDO           0x9
#define FC_FTYPE_LINKCTL       0xA
#define FC_FTYPE_SWILS_RSP     0xB
#define FC_FTYPE_SBCCS         0xC
#define FC_FTYPE_OHMS          0xD

/* Well-known Address Definitions (in Network order) */
#define FC_WKA_MULTICAST       0xFFFFF5
#define FC_WKA_CLKSYNC         0xFFFFF6
#define FC_WKA_KEYDIST         0xFFFFF7
#define FC_WKA_ALIAS           0xFFFFF8
#define FC_WKA_QOSF            0xFFFFF9
#define FC_WKA_MGMT            0xFFFFFA
#define FC_WKA_TIME            0xFFFFFB
#define FC_WKA_DNS             0xFFFFFC
#define FC_WKA_FABRIC_CTRLR    0xFFFFFD
#define FC_WKA_FPORT           0xFFFFFE
#define FC_WKA_BCAST           0xFFFFFF

/* Well-known Address Definitions (in little endian) */

/* Information Categories for Link Data & Link Control Frames */
#define FC_IU_UNCATEGORIZED     0x0
#define FC_IU_SOLICITED_DATA    0x1
#define FC_IU_UNSOLICITED_CTL   0x2
#define FC_IU_SOLICITED_CTL     0x3
#define FC_IU_UNSOLICITED_DATA  0x4
#define FC_IU_DATA_DESCRIPTOR   0x5
#define FC_IU_UNSOLICITED_CMD   0x6
#define FC_IU_CMD_STATUS        0x7

/* FC_CTL bits */
#define FC_FCTL_EXCHANGE_RESPONDER	0x800000
#define FC_FCTL_SEQ_RECIPIENT		0x400000
#define FC_FCTL_EXCHANGE_FIRST		0x200000
#define FC_FCTL_EXCHANGE_LAST		0x100000
#define FC_FCTL_SEQ_LAST		0x080000
#define FC_FCTL_PRIORITY		0x020000
#define FC_FCTL_TRANSFER_SEQ_INITIATIVE	0x010000
#define FC_FCTL_LAST_DATA_FRAME_MASK	0x00c000
#define FC_FCTL_ACK_0_1_MASK		0x003000
#define FC_FCTL_REXMITTED_SEQ		0x000200
#define FC_FCTL_ABTS_MASK		0x000030
#define FC_FCTL_REL_OFFSET		0x000008

/* structure and functions to keep track of first/last exchange
   frames and time deltas 
*/
typedef struct _fc_exchange_data {
    address s_id;
    address d_id;
    guint16 oxid;
    guint32 first_exchange_frame;
    guint32 last_exchange_frame;
    nstime_t fc_time;
} fc_exchange_data;

/* FC header structure */
typedef struct _fc_hdr {
    address s_id;
    address d_id;
    guint32 fctl;
    guint8 type;
    guint16 seqcnt;
    guint16 oxid;
    guint16 rxid;
    guint8 r_ctl;
    guint8 cs_ctl;
    fc_exchange_data *fced;
} fc_hdr;

#endif /* __PACKET_FC_H_ */
