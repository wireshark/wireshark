/* packet-fc.h
 * Basic Fibre Channel Header definitions
 * Copyright 2002 Dinesh G Dutt (ddutt@cisco.com)
 *
 * $Id: packet-fc.h,v 1.1 2002/12/08 02:32:17 gerald Exp $
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

/* TYPE (FC-4) Definitions */

#define FC_TYPE_SCSI           0x8
#define FC_TYPE_IP             0x5
#define FC_TYPE_LLCSNAP        0x4
#define FC_TYPE_ELS            0x1
#define FC_TYPE_FCCT           0x20
#define FC_TYPE_SWILS          0x22
#define FC_TYPE_AL             0x23
#define FC_TYPE_SNMP           0x24
#define FC_TYPE_CMNSVC         0x0  /* Used in PRLI Svc Param Page */

static const value_string fc_fc4_val[] = {
    {FC_TYPE_SCSI    , "FCP"},
    {FC_TYPE_IP      , "IP/FC"},
    {FC_TYPE_LLCSNAP , "LLC_SNAP"},
    {FC_TYPE_ELS     , "Ext Link Svc"},
    {FC_TYPE_FCCT    , "FC_CT"},
    {FC_TYPE_SWILS   , "SW_ILS"},
    {FC_TYPE_AL      , "AL"},
    {FC_TYPE_SNMP    , "SNMP"},
    {0, NULL},
};

static const value_string fc_prli_fc4_val[] = {
    {FC_TYPE_SCSI    , "FCP"},
    {FC_TYPE_IP      , "IP/FC"},
    {FC_TYPE_LLCSNAP , "LLC_SNAP"},
    {FC_TYPE_ELS     , "Ext Link Svc"},
    {FC_TYPE_FCCT    , "FC_CT"},
    {FC_TYPE_SWILS   , "SW_ILS"},
    {FC_TYPE_AL      , "AL"},
    {FC_TYPE_SNMP    , "SNMP"},
    {FC_TYPE_CMNSVC  , "Common to all FC-4 Types"},
    {0, NULL},
};

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

static const value_string fc_ftype_vals [] = {
    {FC_FTYPE_UNDEF ,    "Unknown frame"},
    {FC_FTYPE_SWILS,     "SW_ILS"},
    {FC_FTYPE_IP ,       "IP/FC"},
    {FC_FTYPE_SCSI ,     "FCP"},
    {FC_FTYPE_BLS ,      "Basic Link Svc"},
    {FC_FTYPE_ELS ,      "ELS"},
    {FC_FTYPE_FCCT ,     "FC_CT"},
    {FC_FTYPE_LINKDATA,  "Link Data"},
    {FC_FTYPE_VDO,       "Video Data"},
    {FC_FTYPE_LINKCTL,   "Link Ctl"},
    {0, NULL},
};

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

static const value_string fc_wka_vals[] = {
    {FC_WKA_MULTICAST,    "Multicast Server"},
    {FC_WKA_CLKSYNC,      "Clock Sync Server"},
    {FC_WKA_KEYDIST,      "Key Distribution Server"},
    {FC_WKA_ALIAS,        "Alias Server"},
    {FC_WKA_QOSF,         "QoS Facilitator"},
    {FC_WKA_MGMT,         "Management Server"},
    {FC_WKA_TIME,         "Time Server"},
    {FC_WKA_DNS,          "Directory Server"},
    {FC_WKA_FABRIC_CTRLR, "Fabric Ctlr"},
    {FC_WKA_FPORT,        "F_Port Server"},
    {FC_WKA_BCAST,        "Broadcast ID"},
    {0, NULL},
};

/* Information Categories for Link Data & Link Control Frames */
#define FC_IU_UNCATEGORIZED     0x0
#define FC_IU_SOLICITED_DATA    0x1
#define FC_IU_UNSOLICITED_CTL   0x2
#define FC_IU_SOLICITED_CTL     0x3
#define FC_IU_UNSOLICITED_DATA  0x4
#define FC_IU_DATA_DESCRIPTOR   0x5
#define FC_IU_UNSOLICITED_CMD   0x6
#define FC_IU_CMD_STATUS        0x7

static const value_string fc_iu_val[] = {
    {FC_IU_UNCATEGORIZED   , "Uncategorized Data"},
    {FC_IU_SOLICITED_DATA  , "Solicited Data"},
    {FC_IU_UNSOLICITED_CTL , "Unsolicited Control"},
    {FC_IU_SOLICITED_CTL   , "Solicited Control"},
    {FC_IU_UNSOLICITED_DATA, "Solicited Data"},
    {FC_IU_DATA_DESCRIPTOR , "Data Descriptor"},
    {FC_IU_UNSOLICITED_CMD , "Unsolicited Command"},
    {FC_IU_CMD_STATUS      , "Command Status"},
    {0, NULL},
};

#endif
