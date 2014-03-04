/* packet-fclctl.c
 * Routines for FC Link Control Frames
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

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/wmem/wmem.h>
#include <epan/etypes.h>
#include <epan/conversation.h>
#include "packet-fc.h"
#include "packet-fclctl.h"

const value_string fc_lctl_proto_val[] = {
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

static const value_string fc_lctl_fbsy_val[] = {
    {FC_LCTL_FBSY_FBSY, "Fabric Busy"},
    {FC_LCTL_FBSY_NBSY, "N_Port Busy"},
    {0, NULL}
};

static const value_string fc_lctl_pbsy_acode_val[] = {
    {FC_LCTL_PBSY_ACODE_SEQBSY, "Sequence Marked Busy"},
    {FC_LCTL_PBSY_ACODE_C2BSY, "Class 2 Frame Busy"},
    {0, NULL},
};

static const value_string fc_lctl_pbsy_rjt_val[] = {
    {FC_LCTL_PBSY_PORTBSY , "Physical N_Port Busy"},
    {FC_LCTL_PBSY_RSRCBSY , "N_Port Resource Busy"},
    {FC_LCTL_PBSY_MCASTBSY, "Partial Multicast Busy"},
    {FC_LCTL_PBSY_VENDBSY , "Vendor unique Busy"},
    {0, NULL},
};

static const value_string fc_lctl_rjt_acode_val[] = {
    {FC_LCTL_RJT_ACODE_RETRY, "Retryable Error"},
    {FC_LCTL_RJT_ACODE_NORETRY, "Non-retryable Error"},
    {0, NULL},
};

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

const gchar *
fclctl_get_typestr (guint8 linkctl_type, guint8 type)
{
    if ((linkctl_type == FC_LCTL_FBSYB) ||
        (linkctl_type == FC_LCTL_FBSYL)) {
        return (val_to_str ((type & 0xF0), fc_lctl_fbsy_val, "0x%x"));
    }
    return "";
}

const gchar *
fclctl_get_paramstr (guint32 linkctl_type, guint32 param)
{
    if (linkctl_type == FC_LCTL_PBSY) {
      return wmem_strdup_printf(wmem_packet_scope(), "%s, %s",
                 val_to_str (((param & 0xFF000000) >> 24), fc_lctl_pbsy_acode_val, "0x%x"),
		 val_to_str (((param & 0x00FF0000) >> 16), fc_lctl_pbsy_rjt_val, "0x%x"));
    }
    if ((linkctl_type == FC_LCTL_FRJT) ||
             (linkctl_type == FC_LCTL_PRJT)) {
      return wmem_strdup_printf(wmem_packet_scope(), "%s, %s",
                 val_to_str (((param & 0xFF000000) >> 24), fc_lctl_rjt_acode_val, "0x%x"),
                 val_to_str (((param & 0x00FF0000) >> 16), fc_lctl_rjt_val, "%x"));
    }
    return "";
}
