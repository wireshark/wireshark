/* packet-fc.c
 * Routines for Fibre Channel Decoding (FC Header, Link Ctl & Basic Link Svc) 
 * Copyright 2001, Dinesh G Dutt <ddutt@cisco.com>
 *
 * $Id: packet-fc.c,v 1.3 2003/01/28 23:56:38 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include "prefs.h"
#include "reassemble.h"
#include "etypes.h"
#include "packet-fc.h"
#include "packet-fclctl.h"
#include "packet-fcbls.h"

#define FC_HEADER_SIZE         24
#define FC_RCTL_EISL           0x50

/* Size of various fields in FC header in bytes */
#define FC_RCTL_SIZE           1
#define FC_DID_SIZE            3
#define FC_CSCTL_SIZE          1
#define FC_SID_SIZE            3
#define FC_TYPE_SIZE           1
#define FC_FCTL_SIZE           3
#define FC_SEQID_SIZE          1
#define FC_DFCTL_SIZE          1
#define FC_SEQCNT_SIZE         2
#define FC_OXID_SIZE           2
#define FC_RXID_SIZE           2
#define FC_PARAM_SIZE          4

/* Initialize the protocol and registered fields */
static int proto_fc = -1;
static int hf_fc_rctl = -1;
static int hf_fc_did = -1;
static int hf_fc_csctl = -1;
static int hf_fc_sid = -1;
static int hf_fc_type = -1;
static int hf_fc_fctl = -1;
static int hf_fc_seqid = -1;
static int hf_fc_dfctl = -1;
static int hf_fc_seqcnt = -1;
static int hf_fc_oxid = -1;
static int hf_fc_rxid = -1;
static int hf_fc_param = -1;
static int hf_fc_ftype = -1;    /* Derived field, non-existent in FC hdr */
static int hf_fc_exchg_orig = -1;
static int hf_fc_exchg_resp = -1;
static int hf_fc_reassembled = -1;

/* Network_Header fields */
static int hf_fc_nh_da = -1;
static int hf_fc_nh_sa = -1;

/* For Basic Link Svc */
static int hf_fc_bls_seqid_vld = -1;
static int hf_fc_bls_lastvld_seqid = -1;
static int hf_fc_bls_oxid = -1;
static int hf_fc_bls_rxid = -1;
static int hf_fc_bls_lowseqcnt = -1;
static int hf_fc_bls_hiseqcnt = -1;
static int hf_fc_bls_rjtcode = -1;
static int hf_fc_bls_rjtdetail = -1;
static int hf_fc_bls_vendor = -1;


/* Initialize the subtree pointers */
static gint ett_fc = -1;
static gint ett_fcbls = -1;

static dissector_table_t fcftype_dissector_table;
static dissector_handle_t data_handle;

/* Reassembly stuff */
static gboolean fc_reassemble = TRUE;
static guint32  fc_max_frame_size = 1024;
static GHashTable *fc_fragment_table = NULL;

const value_string fc_fc4_val[] = {
    {FC_TYPE_ELS     , "Ext Link Svc"},
    {FC_TYPE_LLCSNAP , "LLC_SNAP"},
    {FC_TYPE_IP      , "IP/FC"},
    {FC_TYPE_SCSI    , "FCP"},
    {FC_TYPE_FCCT    , "FC_CT"},
    {FC_TYPE_SWILS   , "SW_ILS"},
    {FC_TYPE_AL      , "AL"},
    {FC_TYPE_SNMP    , "SNMP"},
    {0, NULL},
};

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

static void fc_defragment_init(void)
{
  fragment_table_init(&fc_fragment_table);
}


static gchar *
fctl_to_str (const guint8 *fctl, gchar *str, gboolean is_ack)
{
    int stroff = 0;
    guint8 tmp = 0;

    if (str == NULL)
        return (str);
    
    if (fctl[0] & 0x80) {
        strcpy (str, "Exchange Responder, ");
        stroff += 20;
    }
    else {
        strcpy (str, "Exchange Originator, ");
        stroff += 21;
    }

    if (fctl[0] & 0x40) {
        strcpy (&str[stroff], "Seq Recipient, ");
        stroff += 15;
    }
    else {
        strcpy (&str[stroff], "Seq Initiator, ");
        stroff += 15;
    }

    if (fctl[0] & 0x20) {
        strcpy (&str[stroff], "Exchg First, ");
        stroff += 13;
    }

    if (fctl[0] & 0x10) {
        strcpy (&str[stroff], "Exchg Last, ");
        stroff += 12;
    }

    if (fctl[0] & 0x8) {
        strcpy (&str[stroff], "Seq Last, ");
        stroff += 10;
    }

    if (fctl[0] & 0x2) {
        strcpy (&str[stroff], "Priority, ");
        stroff += 10;
    }
    else {
        strcpy (&str[stroff], "CS_CTL, ");
        stroff += 8;
    }

    if (fctl[0] & 0x1) {
        strcpy (&str[stroff], "Transfer Seq Initiative, ");
        stroff += 25;
    }

    if (fctl[1] & 0x30) {
        strcpy (&str[stroff], "ACK_0 Reqd, ");
        stroff += 12;
    }
    else if (fctl[1] & 0x10) {
        strcpy (&str[stroff], "ACK_1 Reqd, ");
        stroff += 12;
    }

    if (fctl[1] & 0x2) {
        strcpy (&str[stroff], "Rexmitted Seq, ");
        stroff += 15;
    }

    tmp = fctl[2] & 0xC0;
    switch (tmp) {
    case 0:
        strcpy (&str[stroff], "Last Data Frame - No Info, ");
        stroff += 27;
        break;
    case 1:
        strcpy (&str[stroff], "Last Data Frame - Seq Imm, ");
        stroff += 27;
        break;
    case 2:
        strcpy (&str[stroff], "Last Data Frame - Seq Soon, ");
        stroff += 28;
        break;
    case 3:
        strcpy (&str[stroff], "Last Data Frame - Seq Delyd, ");
        stroff += 29;
        break;
    }

    tmp = fctl[2] & 0x30;
    switch (tmp) {
    case 0:
        if (is_ack) {
            strcpy (&str[stroff], "ABTS - Cont, ");
            stroff += 13;
        }
        else {
            strcpy (&str[stroff], "ABTS - Abort/MS, ");
            stroff += 17;
        }
        break;
    case 0x10:
        if (is_ack) {
            strcpy (&str[stroff], "ABTS - Abort, ");
            stroff += 14;
        }
        else {
            strcpy (&str[stroff], "ABTS - Abort/SS, ");
            stroff += 17;
        }
        break;
    case 0x20:
        if (is_ack) {
            strcpy (&str[stroff], "ABTS - Stop, ");
            stroff += 13;
        }
        else {
            strcpy (&str[stroff], "ABTS - Process/IB, ");
            stroff += 19;
        }
        break;
    case 0x30:
        if (is_ack) {
            strcpy (&str[stroff], "ABTS - Imm Seq Retx, ");
            stroff += 21;
        }
        else {
            strcpy (&str[stroff], "ABTS - Discard/MS/Imm Retx, ");
            stroff += 28;
        }
        break;
    }

    if (fctl[2] & 0x8) {
        strcpy (&str[stroff], "Rel Offset = 1");
        stroff += 14;
    }

    return (str);
}

/* BA_ACC & BA_RJT are decoded in this file itself instead of a traditional
 * dedicated file and dissector format because the dissector would require some
 * fields of the FC_HDR such as param in some cases, type in some others, the
 * lower 4 bits of r_ctl in some other cases etc. So, we decode BLS & Link Ctl
 * in this file itself.
 */
static void
dissect_fc_ba_acc (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *acc_tree;
    int offset = 0;

    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "BLS");

    if (check_col(pinfo->cinfo, COL_INFO)) 
        col_set_str(pinfo->cinfo, COL_INFO, "BA_ACC");

    if (tree) {
        ti = proto_tree_add_text (tree, tvb, 0, tvb_length (tvb), "Basic Link Svc");
        acc_tree = proto_item_add_subtree (ti, ett_fcbls);

        proto_tree_add_item (acc_tree, hf_fc_bls_seqid_vld, tvb, offset++, 1, FALSE);
        proto_tree_add_item (acc_tree, hf_fc_bls_lastvld_seqid, tvb, offset++, 1, FALSE);
        offset += 2; /* Skip reserved field */
        proto_tree_add_item (acc_tree, hf_fc_bls_oxid, tvb, offset, 2, FALSE);
        offset += 2;
        proto_tree_add_item (acc_tree, hf_fc_bls_rxid, tvb, offset, 2, FALSE);
        offset += 2;
        proto_tree_add_item (acc_tree, hf_fc_bls_lowseqcnt, tvb, offset, 2, FALSE);
        offset += 2;
        proto_tree_add_item (acc_tree, hf_fc_bls_hiseqcnt, tvb, offset, 2, FALSE);
    }
}

static void
dissect_fc_ba_rjt (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *rjt_tree;
    int offset = 0;

    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "BLS");

    if (check_col(pinfo->cinfo, COL_INFO)) 
        col_set_str(pinfo->cinfo, COL_INFO, "BA_RJT");

    if (tree) {
        ti = proto_tree_add_text (tree, tvb, 0, tvb_length (tvb), "Basic Link Svc");
        rjt_tree = proto_item_add_subtree (ti, ett_fcbls);

        proto_tree_add_item (rjt_tree, hf_fc_bls_rjtcode, tvb, offset+1, 1, FALSE);
        proto_tree_add_item (rjt_tree, hf_fc_bls_rjtdetail, tvb, offset+2, 1, FALSE);
        proto_tree_add_item (rjt_tree, hf_fc_bls_vendor, tvb, offset+3, 1, FALSE);
    }
}

static guint8
fc_get_ftype (guint8 r_ctl, guint8 type)
{
    /* A simple attempt to determine the upper level protocol based on the
     * r_ctl & type fields.
     */
    switch (r_ctl & 0xF0) {
    case FC_RCTL_DEV_DATA:
        switch (type) {
        case FC_TYPE_SWILS:
            if ((r_ctl == 0x2) || (r_ctl == 0x3))
                return FC_FTYPE_SWILS;
            else
                return FC_FTYPE_UNDEF;
        case FC_TYPE_IP:
            return FC_FTYPE_IP;
        case FC_TYPE_SCSI:
            return FC_FTYPE_SCSI;
        case FC_TYPE_FCCT:
            return FC_FTYPE_FCCT;
        default:
            return FC_FTYPE_UNDEF;
        }
        break;
    case FC_RCTL_ELS:
        if (((r_ctl & 0x0F) == 0x2) || ((r_ctl & 0x0F) == 0x3))
            return FC_FTYPE_ELS;
        else
            return FC_FTYPE_UNDEF;
        break;
    case FC_RCTL_LINK_DATA:
        return FC_FTYPE_LINKDATA;
        break;
    case FC_RCTL_VIDEO:
        return FC_FTYPE_VDO;
        break;
    case FC_RCTL_BLS:
        if (type == 0)
            return FC_FTYPE_BLS;
        else
            return FC_FTYPE_UNDEF;
        break;
    case FC_RCTL_LINK_CTL:
        return FC_FTYPE_LINKCTL;
        break;
    default:
        return FC_FTYPE_UNDEF;
        break;
    }
}
/* Code to actually dissect the packets */
static void
dissect_fc (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *fc_tree = NULL;
    tvbuff_t *next_tvb;
    int offset = 0, next_offset;
    gboolean is_lastframe_inseq;
    gboolean is_exchg_resp = 0;
    fragment_data *fcfrag_head;
    guint32 frag_id;
    guint32 frag_size;
    guint8 r_ctl, type, df_ctl;
    
    gchar str[256];
    guint32 param;
    guint16 seqcnt;
    guint8 ftype;
    gboolean is_ack;
    
    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "FC");

    r_ctl = tvb_get_guint8 (tvb, offset);

    /* If the R_CTL is the EISL field, skip the first 8 bytes to retrieve the
     * real FC header. EISL is Cisco-proprietary and is not decoded.
     */
    if (r_ctl == FC_RCTL_EISL) {
        offset += 8;
        r_ctl = tvb_get_guint8 (tvb, offset);
    }
    
    type  = tvb_get_guint8 (tvb, offset+8);
    seqcnt = tvb_get_ntohs (tvb, offset+14);
    param = tvb_get_ntohl (tvb, offset+20);

    SET_ADDRESS (&pinfo->dst, AT_FC, 3, tvb_get_ptr (tvb, 1, 3));
    SET_ADDRESS (&pinfo->src, AT_FC, 3, tvb_get_ptr (tvb, 5, 3));
    pinfo->oxid = tvb_get_ntohs (tvb, offset+16);
    pinfo->rxid = tvb_get_ntohs (tvb, offset+18);
    pinfo->ptype = PT_EXCHG;
    pinfo->r_ctl = r_ctl;

    is_ack = ((r_ctl == 0xC0) || (r_ctl == 0xC1));

    ftype = fc_get_ftype (r_ctl, type);
    
    if (check_col (pinfo->cinfo, COL_INFO)) {
        col_add_str (pinfo->cinfo, COL_INFO, match_strval (ftype, fc_ftype_vals));

        if (ftype == FC_FTYPE_LINKCTL)
            col_append_fstr (pinfo->cinfo, COL_INFO, ", %s",
                             match_strval ((r_ctl & 0x0F),
                                           fc_lctl_proto_val));
    }
    
    /* In the interest of speed, if "tree" is NULL, don't do any work not
       necessary to generate protocol tree items. */
    if (tree) {
        ti = proto_tree_add_protocol_format (tree, proto_fc, tvb, offset,
                                             FC_HEADER_SIZE, "Fibre Channel");
        fc_tree = proto_item_add_subtree (ti, ett_fc);

        if (ftype == FC_FTYPE_LINKCTL) {
            /* the lower 4 bits of R_CTL indicate the type of link ctl frame */
            proto_tree_add_uint_format (fc_tree, hf_fc_rctl, tvb, offset,
                                        FC_RCTL_SIZE, r_ctl,
                                        "R_CTL: 0x%x(%s)",
                                        r_ctl,
                                        val_to_str ((r_ctl & 0x0F),
                                                    fc_lctl_proto_val, "0x%x")); 
        }
        else if (ftype == FC_FTYPE_BLS) {
            /* the lower 4 bits of R_CTL indicate the type of BLS frame */
            proto_tree_add_uint_format (fc_tree, hf_fc_rctl, tvb, offset,
                                        FC_RCTL_SIZE, r_ctl,
                                        "R_CTL: 0x%x(%s)",
                                        r_ctl,
                                        val_to_str ((r_ctl & 0x0F),
                                                    fc_bls_proto_val, "0x%x")); 
        }
        else {
            proto_tree_add_item (fc_tree, hf_fc_rctl, tvb, offset, 1, FALSE);
        }
        
        proto_tree_add_uint_hidden (fc_tree, hf_fc_ftype, tvb, offset, 1,
                                    ftype); 
        proto_tree_add_string (fc_tree, hf_fc_did, tvb, offset+1, 3,
                               fc_to_str ((guint8 *)tvb_get_ptr (tvb,
                                                                 offset+1, 3)));
        proto_tree_add_item (fc_tree, hf_fc_csctl, tvb, offset+4, 1, FALSE);

        proto_tree_add_string (fc_tree, hf_fc_sid, tvb, offset+5, 3,
                               fc_to_str ((guint8 *)tvb_get_ptr (tvb,
                                                                 offset+5, 3)));
        
        if (ftype == FC_FTYPE_LINKCTL) {
            if (((r_ctl & 0x0F) == FC_LCTL_FBSYB) ||
                ((r_ctl & 0x0F) == FC_LCTL_FBSYL)) {
                /* for F_BSY frames, the upper 4 bits of the type field specify the
                 * reason for the BSY.
                 */
                proto_tree_add_uint_format (fc_tree, hf_fc_type, tvb,
                                            offset+8, FC_TYPE_SIZE,
                                            type, "Type: 0x%x(%s)", type, 
                                            fclctl_get_typestr (r_ctl & 0x0F,
                                                                type));
            }
            else {
                proto_tree_add_item (fc_tree, hf_fc_type, tvb, offset+8, 1, FALSE);
            }
        }
        else {
            proto_tree_add_item (fc_tree, hf_fc_type, tvb, offset+8, 1, FALSE);
        }

        proto_tree_add_uint_format (fc_tree, hf_fc_fctl, tvb, offset+9,
                                    3, tvb_get_ntoh24 (tvb, offset+9),
                                    "F_CTL: 0x%x (%s)",
                                    tvb_get_ntoh24 (tvb, offset+9),
                                    fctl_to_str (tvb_get_ptr (tvb, offset+9, 3),
                                                 str, is_ack));

        /* Bit 23 if set => this frame is from the exchange originator */
        if (tvb_get_guint8 (tvb, offset+9) & 0x80) {
            proto_tree_add_boolean_hidden (fc_tree, hf_fc_exchg_orig, tvb,
                                           offset+9, 1, 0);
            proto_tree_add_boolean_hidden (fc_tree, hf_fc_exchg_resp, tvb,
                                           offset+9, 1, 1);
        }
        else {
            proto_tree_add_boolean_hidden (fc_tree, hf_fc_exchg_orig, tvb,
                                           offset+9, 1, 1);
            proto_tree_add_boolean_hidden (fc_tree, hf_fc_exchg_resp, tvb,
                                           offset+9, 1, 0);
        }
        
        proto_tree_add_item (fc_tree, hf_fc_seqid, tvb, offset+12, 1, FALSE);
    }
    df_ctl = tvb_get_guint8(tvb, offset+13);
    if (tree) {
        proto_tree_add_uint (fc_tree, hf_fc_dfctl, tvb, offset+13, 1, df_ctl);
        proto_tree_add_item (fc_tree, hf_fc_seqcnt, tvb, offset+14, 2, FALSE);
        proto_tree_add_item (fc_tree, hf_fc_oxid, tvb, offset+16, 2, FALSE);
        proto_tree_add_item (fc_tree, hf_fc_rxid, tvb, offset+18, 2, FALSE);

        if (ftype == FC_FTYPE_LINKCTL) {
            if (((r_ctl & 0x0F) == FC_LCTL_FRJT) ||
                ((r_ctl & 0x0F) == FC_LCTL_PRJT) ||
                ((r_ctl & 0x0F) == FC_LCTL_PBSY)) {
                /* In all these cases of Link Ctl frame, the parameter field
                 * encodes the detailed error message
                 */
                proto_tree_add_uint_format (fc_tree, hf_fc_param, tvb,
                                            offset+20, 4, param,
                                            "Parameter: 0x%x(%s)", param,
                                            fclctl_get_paramstr ((r_ctl & 0x0F),
                                                                 param));
            }
            else {
                proto_tree_add_item (fc_tree, hf_fc_param, tvb, offset+20, 4, FALSE);
            }
        }
        else if (ftype == FC_FTYPE_BLS) {
            if ((r_ctl & 0x0F) == FC_BLS_ABTS) {
                proto_tree_add_uint_format (fc_tree, hf_fc_param, tvb,
                                            offset+20, 4, param, 
                                            "Parameter: 0x%x(%s)", param,
                                            ((param & 0x0F) == 1 ? "Abort Sequence" :
                                             "Abort Exchange"));
            }
            else {
                proto_tree_add_item (fc_tree, hf_fc_param, tvb, offset+20,
                                     4, FALSE);
            }
        }
        else {
            proto_tree_add_item (fc_tree, hf_fc_param, tvb, offset+20, 4, FALSE);
        }
    }

    /* Skip the Frame_Header */
    next_offset = offset + FC_HEADER_SIZE;

    /* Network_Header present? */
    if (df_ctl & FC_DFCTL_NH) {
        /* Yes - dissect it. */
        if (tree) {
            proto_tree_add_string (fc_tree, hf_fc_nh_da, tvb, next_offset, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset, 8)));
            proto_tree_add_string (fc_tree, hf_fc_nh_sa, tvb, offset+8, 8,
                                   fcwwn_to_str (tvb_get_ptr (tvb, offset+8, 8)));
        }
        next_offset += 16;
    }

    /* XXX - handle Association_Header and Device_Header here */

    if (ftype == FC_FTYPE_LINKCTL) {
        /* ACK_1 frames and other LINK_CTL frames echo the last seq bit if the
         * packet they're ack'ing did not have it set. So, we'll incorrectly
         * flag them as being fragmented when they're not. This fixes the
         * problem
         */
        is_lastframe_inseq = TRUE;
    }
    else {
        is_lastframe_inseq = tvb_get_guint8 (tvb, offset+9) & 0x08;
        is_exchg_resp = ((tvb_get_guint8 (tvb, offset+20) & 0x80) == 0x80);
    }

    frag_size = tvb_reported_length (tvb)-FC_HEADER_SIZE;

    if (!is_lastframe_inseq) {
        /* Show this only as a fragmented FC frame */
        if (check_col (pinfo->cinfo, COL_INFO)) {
            col_append_str (pinfo->cinfo, COL_INFO, " (Fragmented)");
        }
    }

    /* If this is a fragment, attempt to check if fully reassembled frame is
     * present, if we're configured to reassemble.
     */
    if ((ftype != FC_FTYPE_LINKCTL) && (ftype != FC_FTYPE_BLS) &&
        seqcnt && fc_reassemble) {
        /* Add this to the list of fragments */
        frag_id = (pinfo->oxid << 16) | is_exchg_resp;

        /* We assume that all frames are of the same max size */
        fcfrag_head = fragment_add (tvb, FC_HEADER_SIZE, pinfo, frag_id,
                                    fc_fragment_table,
                                    seqcnt * fc_max_frame_size,
                                    frag_size,
                                    TRUE);
        
        if (fcfrag_head) {
            next_tvb = tvb_new_real_data (fcfrag_head->data,
                                          fcfrag_head->datalen,
                                          fcfrag_head->datalen);
            tvb_set_child_real_data_tvbuff(tvb, next_tvb);
            
            /* Add the defragmented data to the data source list. */
            add_new_data_source(pinfo, next_tvb, "Reassembled FC");
            
            if (tree) {
                proto_tree_add_boolean_hidden (fc_tree, hf_fc_reassembled,
                                               tvb, offset+9, 1, 1);
            }
        }
        else {
            if (tree) {
                proto_tree_add_boolean_hidden (fc_tree, hf_fc_reassembled,
                                               tvb, offset+9, 1, 0);
            }
            next_tvb = tvb_new_subset (tvb, next_offset, -1, -1);
            call_dissector (data_handle, next_tvb, pinfo, tree);
            return;
        }
    }
    else {
        if (tree) {
            proto_tree_add_boolean_hidden (fc_tree, hf_fc_reassembled,
                                           tvb, offset+9, 1, 0);
        }
        next_tvb = tvb_new_subset (tvb, next_offset, -1, -1);
    }

    if ((ftype != FC_FTYPE_LINKCTL) && (ftype != FC_FTYPE_BLS)) {
        if (!dissector_try_port (fcftype_dissector_table, ftype, next_tvb,
                                 pinfo, tree)) {
            call_dissector (data_handle, next_tvb, pinfo, tree);
        }
    }
    else if (ftype == FC_FTYPE_BLS) {
        if ((r_ctl & 0x0F) == FC_BLS_BAACC) {
            dissect_fc_ba_acc (next_tvb, pinfo, tree);
        }
        else if ((r_ctl & 0x0F) == FC_BLS_BARJT) {
            dissect_fc_ba_rjt (next_tvb, pinfo, tree);
        }
    }
}


/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_fc(void)
{                 

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_fc_rctl,
          { "R_CTL", "fc.r_ctl", FT_UINT8, BASE_HEX, NULL, 0x0,
            "R_CTL", HFILL }},
        { &hf_fc_ftype,
          {"Frame type", "fc.ftype", FT_UINT8, BASE_HEX, VALS(fc_ftype_vals),
           0x0, "Derived Type", HFILL}},
        { &hf_fc_did,
          { "Dest Addr", "fc.d_id", FT_STRING, BASE_HEX, NULL, 0x0,
            "Destination Address", HFILL}},
        { &hf_fc_csctl,
          {"CS_CTL", "fc.cs_ctl", FT_UINT8, BASE_HEX, NULL, 0x0,
           "CS_CTL", HFILL}},
        { &hf_fc_sid,
          {"Src Addr", "fc.s_id", FT_STRING, BASE_HEX, NULL, 0x0,
           "Source Address", HFILL}},
        { &hf_fc_type,
          {"Type", "fc.type", FT_UINT8, BASE_HEX, VALS (fc_fc4_val), 0x0,
           "", HFILL}},
        { &hf_fc_fctl,
          {"F_CTL", "fc.f_ctl", FT_UINT24, BASE_HEX, NULL, 0x0, "", HFILL}},
        { &hf_fc_seqid,
          {"SEQ_ID", "fc.seq_id", FT_UINT8, BASE_HEX, NULL, 0x0,
           "Sequence ID", HFILL}},
        { &hf_fc_dfctl,
          {"DF_CTL", "fc.df_ctl", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL}},
        { &hf_fc_seqcnt,
          {"SEQ_CNT", "fc.seq_cnt", FT_UINT16, BASE_DEC, NULL, 0x0,
           "Sequence Count", HFILL}},
        { &hf_fc_oxid,
          {"OX_ID", "fc.ox_id", FT_UINT16, BASE_HEX, NULL, 0x0, "Originator ID",
           HFILL}},
        { &hf_fc_rxid,
          {"RX_ID", "fc.rx_id", FT_UINT16, BASE_HEX, NULL, 0x0, "Receiver ID",
           HFILL}},
        { &hf_fc_param,
          {"Parameter", "fc.parameter", FT_UINT32, BASE_HEX, NULL, 0x0, "Parameter",
           HFILL}},

        { &hf_fc_exchg_orig,
          {"Exchange Originator", "fc.xchg_orig", FT_BOOLEAN, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fc_exchg_resp,
          {"Exchange Responder", "fc.xchg_resp", FT_BOOLEAN, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fc_reassembled,
          {"Reassembled Frame", "fc.reassembled", FT_BOOLEAN, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fc_nh_da,
          {"Network DA", "fc.nethdr.da", FT_STRING, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fc_nh_sa,
          {"Network SA", "fc.nethdr.sa", FT_STRING, BASE_HEX, NULL,
           0x0, "", HFILL}},

        /* Basic Link Svc field definitions */
        { &hf_fc_bls_seqid_vld,
          {"SEQID Valid", "fc.bls_seqidvld", FT_UINT8, BASE_HEX,
           VALS (fc_bls_seqid_val), 0x0, "", HFILL}},
        { &hf_fc_bls_lastvld_seqid,
          {"Last Valid SEQID", "fc.bls_lastseqid", FT_UINT8, BASE_HEX, NULL,
           0x0, "", HFILL}},
        { &hf_fc_bls_oxid,
          {"OXID", "fc.bls_oxid", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL}},
        { &hf_fc_bls_rxid,
          {"RXID", "fc.bls_rxid", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL}},
        { &hf_fc_bls_lowseqcnt,
          {"Low SEQCNT", "fc.bls_lseqcnt", FT_UINT16, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_fc_bls_hiseqcnt,
          {"High SEQCNT", "fc.bls_hseqcnt", FT_UINT16, BASE_HEX, NULL, 0x0, "",
           HFILL}},
        { &hf_fc_bls_rjtcode,
          {"Reason", "fc.bls_reason", FT_UINT8, BASE_HEX, VALS(fc_bls_barjt_val),
           0x0, "", HFILL}},
        { &hf_fc_bls_rjtdetail,
          {"Reason Explanantion", "fc.bls_rjtdetail", FT_UINT8, BASE_HEX,
           VALS (fc_bls_barjt_det_val), 0x0, "", HFILL}},
        { &hf_fc_bls_vendor,
          {"Vendor Unique Reason", "fc.bls_vnduniq", FT_UINT8, BASE_HEX, NULL,
           0x0, "", HFILL}},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_fc,
        &ett_fcbls,
    };

    module_t *fc_module;

    /* Register the protocol name and description */
    proto_fc = proto_register_protocol ("Fibre Channel", "FC", "fc");
    register_dissector ("fc", dissect_fc, proto_fc);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_fc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    fcftype_dissector_table = register_dissector_table ("fc.ftype",
                                                        "FC Frame Type",
                                                        FT_UINT8, BASE_HEX);

    /* Register preferences */
    fc_module = prefs_register_protocol (proto_fc, NULL);
    prefs_register_bool_preference (fc_module,
                                    "reassemble",
                                    "Reassemble multi-frame sequences",
                                    "If enabled, reassembly of multi-frame "
                                    "sequences is done",
                                    &fc_reassemble);
    prefs_register_uint_preference (fc_module,
                                    "max_frame_size", "Max FC Frame Size",
                                    "This is the size of non-last frames in a "
                                    "multi-frame sequence", 10,
                                    &fc_max_frame_size);
    
    register_init_routine(fc_defragment_init);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_fc (void)
{
    dissector_handle_t fc_handle;

    fc_handle = create_dissector_handle (dissect_fc, proto_fc);

    data_handle = find_dissector("data");
}
