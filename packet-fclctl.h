/* packet-fclctl.h
 * Fibre Channel Link Control definitions
 * Copyright 2001 Dinesh G Dutt (ddutt@cisco.com)
 *
 * $Id: packet-fclctl.h,v 1.1 2002/12/08 02:32:17 gerald Exp $
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

#ifndef __PACKET_FCLCTL_H_
#define __PACKET_FCLCTL_H_

#define FC_LCTL_ACK1      0x00
#define FC_LCTL_ACK0      0x01
#define FC_LCTL_PRJT      0x02
#define FC_LCTL_FRJT      0x03
#define FC_LCTL_PBSY      0x04
#define FC_LCTL_FBSYL     0x05
#define FC_LCTL_FBSYB     0x06
#define FC_LCTL_LCR       0x07
#define FC_LCTL_NTY       0x08
#define FC_LCTL_END       0x09

static const value_string fc_lctl_proto_val[] = {
    {FC_LCTL_ACK1  , "ACK1"},
    {FC_LCTL_ACK0  , "ACK0"},
    {FC_LCTL_PRJT  , "P_RJT"},
    {FC_LCTL_FRJT  , "F_RJT"},
    {FC_LCTL_PBSY  , "P_BSY"},
    {FC_LCTL_FBSYL , "F_BSY (Data frame)"},
    {FC_LCTL_FBSYB , "F_BSY (Link Ctl)"},
    {FC_LCTL_LCR   , "LCR"},
    {FC_LCTL_NTY   , "NTY"},
    {FC_LCTL_END   , "END"},
    {0, NULL},
};

#define FC_LCTL_FBSY_FBSY  0x01
#define FC_LCTL_FBSY_NBSY  0x03

static const value_string fc_lctl_fbsy_val[] = {
    {FC_LCTL_FBSY_FBSY, "Fabric Busy"},
    {FC_LCTL_FBSY_NBSY, "N_Port Busy"},
    {0, NULL}
};

#define FC_LCTL_PBSY_ACODE_SEQBSY 0x01
#define FC_LCTL_PBSY_ACODE_C2BSY  0x02

static const value_string fc_lctl_pbsy_acode_val[] = {
    {FC_LCTL_PBSY_ACODE_SEQBSY, "Sequence Marked Busy"},
    {FC_LCTL_PBSY_ACODE_C2BSY, "Class 2 Frame Busy"},
    {0, NULL},
};

#define FC_LCTL_PBSY_PORTBSY      0x01
#define FC_LCTL_PBSY_RSRCBSY      0x03
#define FC_LCTL_PBSY_MCASTBSY     0x07 
#define FC_LCTL_PBSY_VENDBSY      0xFF

static const value_string fc_lctl_pbsy_rjt_val[] = {
    {FC_LCTL_PBSY_PORTBSY , "Physical N_Port Busy"},
    {FC_LCTL_PBSY_RSRCBSY , "N_Port Resource Busy"},
    {FC_LCTL_PBSY_MCASTBSY, "Partial Multicast Busy"},
    {FC_LCTL_PBSY_VENDBSY , "Vendor unique Busy"},
    {0, NULL},
};

#define FC_LCTL_RJT_ACODE_RETRY   0x01
#define FC_LCTL_RJT_ACODE_NORETRY 0x02

static const value_string fc_lctl_rjt_acode_val[] = {
    {FC_LCTL_RJT_ACODE_RETRY, "Retryable Error"},
    {FC_LCTL_RJT_ACODE_NORETRY, "Non-retryable Error"},
    {0, NULL},
};

#define FC_LCTL_RJT_INVDID                 0x01
#define FC_LCTL_RJT_INVSID                 0x02
#define FC_LCTL_RJT_NPORT_NOTAVAIL_T       0x03
#define FC_LCTL_RJT_NPORT_NOTAVAIL_P       0x04
#define FC_LCTL_RJT_CLASS_NOTSUPP          0x05
#define FC_LCTL_RJT_DELIM_USERR            0x06
#define FC_LCTL_RJT_TYPE_NOTSUPP           0x07
#define FC_LCTL_RJT_INV_LCTL               0x08
#define FC_LCTL_RJT_INV_RCTL               0x09
#define FC_LCTL_RJT_INV_FCTL               0x0A
#define FC_LCTL_RJT_INV_OXID               0x0B
#define FC_LCTL_RJT_INV_RXID               0x0C
#define FC_LCTL_RJT_INV_SEQID              0x0D
#define FC_LCTL_RJT_INV_DFCTL              0x0E
#define FC_LCTL_RJT_INV_SEQCNT             0x0F
#define FC_LCTL_RJT_INV_PARAM              0x10
#define FC_LCTL_RJT_EXCHG_ERR              0x11
#define FC_LCTL_RJT_PROTO_ERR              0x12
#define FC_LCTL_RJT_INV_LEN                0x13
#define FC_LCTL_RJT_UNEXP_ACK              0x14
#define FC_LCTL_RJT_CLS_NOTSUPP            0x15
#define FC_LCTL_RJT_LOGI_REQD              0x16
#define FC_LCTL_RJT_TOOMANY_SEQ            0x17
#define FC_LCTL_RJT_EXCHG_NOTESTD          0x18 
#define FC_LCTL_RJT_RSVD                   0x19
#define FC_LCTL_RJT_FPATH_NOTAVAIL         0x1A
#define FC_LCTL_RJT_INV_VCID               0x1B 
#define FC_LCTL_RJT_INV_CSCTL              0x1C
#define FC_LCTL_RJT_OORSRC                 0x1D
#define FC_LCTL_RJT_INV_CLASS              0x1F
#define FC_LCTL_RJT_PRMPT_RJT              0x20
#define FC_LCTL_RJT_PRMPT_DIS              0x21 
#define FC_LCTL_RJT_MCAST_ERR              0x22
#define FC_LCTL_RJT_MCAST_TERM             0x23
#define FC_LCTL_RJT_PRLI_REQD              0x24
#define FC_LCTL_RJT_VEND_ERR               0xFF

static const value_string fc_lctl_rjt_val[] = {
    {FC_LCTL_RJT_INVSID             , "Invalid S_ID"},
    {FC_LCTL_RJT_INVDID             , "Invalid D_ID"},
    {FC_LCTL_RJT_NPORT_NOTAVAIL_T   , "N_Port Not Avail (Temporary)"},
    {FC_LCTL_RJT_NPORT_NOTAVAIL_P   , "N_Port Not Avail (Permanent)"},
    {FC_LCTL_RJT_CLASS_NOTSUPP      , "Class Not Supported"},
    {FC_LCTL_RJT_DELIM_USERR        , "Delimiter Usage Error"},
    {FC_LCTL_RJT_TYPE_NOTSUPP       , "Type Not Supported"},
    {FC_LCTL_RJT_INV_LCTL           , "Invalid Link Ctl Frame"},
    {FC_LCTL_RJT_INV_RCTL           , "Invalid R_CTL"},
    {FC_LCTL_RJT_INV_FCTL           , "Invalid F_CTL"},
    {FC_LCTL_RJT_INV_OXID           , "Invalid OX_ID"},
    {FC_LCTL_RJT_INV_RXID           , "Invalid RX_ID"},
    {FC_LCTL_RJT_INV_SEQID          , "Invalid SEQID"},
    {FC_LCTL_RJT_INV_DFCTL          , "Invalid DF_CTL"},
    {FC_LCTL_RJT_INV_SEQCNT         , "Invalid SEQCNT"},
    {FC_LCTL_RJT_INV_PARAM          , "Invalid Parameter"},
    {FC_LCTL_RJT_EXCHG_ERR          , "Exchange Error"},
    {FC_LCTL_RJT_PROTO_ERR          , "Protocol Error"},
    {FC_LCTL_RJT_INV_LEN            , "Incorrect Length"},
    {FC_LCTL_RJT_UNEXP_ACK          , "Unexpected ACK"},
    {FC_LCTL_RJT_CLS_NOTSUPP        , "Class Not Supported by Entity at 0xFFFFFE"},
    {FC_LCTL_RJT_LOGI_REQD          , "Login Required"},
    {FC_LCTL_RJT_TOOMANY_SEQ        , "Excessive Sequences Attempted"},
    {FC_LCTL_RJT_EXCHG_NOTESTD      , "Exchange Not Established"},
    {FC_LCTL_RJT_RSVD               , "Reserved"},
    {FC_LCTL_RJT_FPATH_NOTAVAIL     , "Fabric Path Not Available"},
    {FC_LCTL_RJT_INV_VCID           , "Invalid VC_ID"},
    {FC_LCTL_RJT_INV_CSCTL          , "Invalid CS_CTL"},
    {FC_LCTL_RJT_OORSRC             , "Insufficient Resources of VC (Class 4)"},
    {FC_LCTL_RJT_INV_CLASS          , "Invalid Class of Service"},
    {FC_LCTL_RJT_PRMPT_RJT          , "Preemption Request Rejected"},
    {FC_LCTL_RJT_PRMPT_DIS          , "Preemption Not Enabled"},
    {FC_LCTL_RJT_MCAST_ERR          , "Multicast Error"},
    {FC_LCTL_RJT_MCAST_TERM         , "Multicast Error Terminate"},
    {FC_LCTL_RJT_PRLI_REQD          , "PRLI Required"},
    {FC_LCTL_RJT_VEND_ERR           , "Vendor Unique Error"},
    {0, NULL},
};

/* Function definitions */
gchar *fclctl_get_typestr (guint8 linkctl_type, guint8 type);
gchar *fclctl_get_paramstr (guint32 linkctl_type, guint32 param);
#endif
