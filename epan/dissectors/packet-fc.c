/* packet-fc.c
 * Routines for Fibre Channel Decoding (FC Header, Link Ctl & Basic Link Svc)
 * Copyright 2001, Dinesh G Dutt <ddutt@cisco.com>
 *   Copyright 2003  Ronnie Sahlberg, exchange first/last matching and
 *                                    tap listener and misc updates
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
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/to_str.h>
#include <wiretap/wtap.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/etypes.h>
#include "packet-fc.h"
#include "packet-fclctl.h"
#include "packet-fcbls.h"
#include <epan/tap.h>
#include <epan/wmem/wmem.h>
#include <epan/crc32-tvb.h>
#include <epan/expert.h>

void proto_register_fc(void);
void proto_reg_handoff_fc(void);

#define FC_HEADER_SIZE         24
#define FC_RCTL_VFT            0x50
#define MDSHDR_TRAILER_SIZE    6

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
static int hf_fc_time = -1;
static int hf_fc_exchange_first_frame = -1;
static int hf_fc_exchange_last_frame = -1;
static int hf_fc_rctl = -1;
static int hf_fc_did = -1;
static int hf_fc_csctl = -1;
static int hf_fc_sid = -1;
static int hf_fc_id = -1;
static int hf_fc_type = -1;
static int hf_fc_fctl = -1;
static int hf_fc_fctl_exchange_responder = -1;
static int hf_fc_fctl_seq_recipient = -1;
static int hf_fc_fctl_exchange_first = -1;
static int hf_fc_fctl_exchange_last = -1;
static int hf_fc_fctl_seq_last = -1;
static int hf_fc_fctl_priority = -1;
static int hf_fc_fctl_transfer_seq_initiative = -1;
static int hf_fc_fctl_rexmitted_seq = -1;
static int hf_fc_fctl_rel_offset = -1;
static int hf_fc_fctl_abts_ack = -1;
/* static int hf_fc_fctl_abts_not_ack = -1; */
static int hf_fc_fctl_last_data_frame = -1;
static int hf_fc_fctl_ack_0_1 = -1;
static int hf_fc_seqid = -1;
static int hf_fc_dfctl = -1;
static int hf_fc_seqcnt = -1;
static int hf_fc_oxid = -1;
static int hf_fc_rxid = -1;
static int hf_fc_param = -1;
static int hf_fc_ftype = -1;    /* Derived field, non-existent in FC hdr */
static int hf_fc_reassembled = -1;
static int hf_fc_relative_offset = -1;

/* VFT fields */
static int hf_fc_vft = -1;
static int hf_fc_vft_rctl = -1;
static int hf_fc_vft_ver = -1;
static int hf_fc_vft_type = -1;
static int hf_fc_vft_pri = -1;
static int hf_fc_vft_vf_id = -1;
static int hf_fc_vft_hop_ct = -1;

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

/* For FC SOF */
static int proto_fcsof = -1;

static int hf_fcsof = -1;
static int hf_fceof = -1;
static int hf_fccrc = -1;

static int ett_fcsof = -1;
static int ett_fceof = -1;
static int ett_fccrc = -1;


/* Initialize the subtree pointers */
static gint ett_fc = -1;
static gint ett_fctl = -1;
static gint ett_fcbls = -1;
static gint ett_fc_vft = -1;

static expert_field ei_fccrc = EI_INIT;

static dissector_handle_t fc_handle, fcsof_handle;
static dissector_table_t fcftype_dissector_table;

static dissector_handle_t data_handle;

static int fc_tap = -1;

typedef struct _fc_conv_data_t {
    wmem_tree_t *exchanges;
    wmem_tree_t *luns;
} fc_conv_data_t;

/* Reassembly stuff */
static gboolean fc_reassemble = TRUE;
static guint32  fc_max_frame_size = 1024;
static reassembly_table fc_reassembly_table;

typedef struct _fcseq_conv_key {
    guint32 conv_idx;
} fcseq_conv_key_t;

typedef struct _fcseq_conv_data {
    guint32 seq_cnt;
} fcseq_conv_data_t;

static GHashTable *fcseq_req_hash = NULL;

/*
 * Hash Functions
 */
static gint
fcseq_equal(gconstpointer v, gconstpointer w)
{
    const fcseq_conv_key_t *v1 = (const fcseq_conv_key_t *)v;
    const fcseq_conv_key_t *v2 = (const fcseq_conv_key_t *)w;

    return (v1->conv_idx == v2->conv_idx);
}

static guint
fcseq_hash (gconstpointer v)
{
    const fcseq_conv_key_t *key = (const fcseq_conv_key_t *)v;
    guint val;

    val = key->conv_idx;

    return val;
}

static void
fc_exchange_init_protocol(void)
{
    reassembly_table_init(&fc_reassembly_table,
                          &addresses_reassembly_table_functions);

    if (fcseq_req_hash)
        g_hash_table_destroy(fcseq_req_hash);

    fcseq_req_hash = g_hash_table_new(fcseq_hash, fcseq_equal);
}


const value_string fc_fc4_val[] = {
    {FC_TYPE_BLS,        "Basic Link Svc"},
    {FC_TYPE_ELS,        "Ext Link Svc"},
    {FC_TYPE_LLCSNAP,    "LLC_SNAP"},
    {FC_TYPE_IP,         "IP/FC"},
    {FC_TYPE_SCSI,       "FCP"},
    {FC_TYPE_FCCT,       "FC_CT"},
    {FC_TYPE_SWILS,      "SW_ILS"},
    {FC_TYPE_AL,         "AL"},
    {FC_TYPE_SNMP,       "SNMP"},
    {FC_TYPE_SB_FROM_CU, "SB-3(CU->Channel)"},
    {FC_TYPE_SB_TO_CU,   "SB-3(Channel->CU)"},
    {0, NULL}
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
    {FC_FTYPE_SBCCS,     "SBCCS"},
    {FC_FTYPE_OHMS,      "OHMS(Cisco MDS)"},
    {0, NULL}
};

static const value_string fc_wka_vals[] _U_ = {
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
    {0, NULL}
};

static const value_string fc_routing_val[] = {
    {FC_RCTL_DEV_DATA,  "Device_Data"},
    {FC_RCTL_ELS,       "Extended Link Services"},
    {FC_RCTL_LINK_DATA, "FC-4 Link_Data"},
    {FC_RCTL_VIDEO,     "Video_Data"},
    {FC_RCTL_BLS,       "Basic Link Services"},
    {FC_RCTL_LINK_CTL,  "Link_Control Frame"},
    {0, NULL}
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
    {0, NULL}
};


/* For FC SOF */
#define    FC_SOFC1  0xBCB51717
#define    FC_SOFI1  0xBCB55757
#define    FC_SOFN1  0xBCB53737
#define    FC_SOFI2  0xBCB55555
#define    FC_SOFN2  0xBCB53535
#define    FC_SOFI3  0xBCB55656
#define    FC_SOFN3  0xBCB53636
#define    FC_SOFC4  0xBCB51919
#define    FC_SOFI4  0xBCB55959
#define    FC_SOFN4  0xBCB53939
#define    FC_SOFF   0xBCB55858

#define    EOFT_NEG    0xBC957575
#define    EOFT_POS    0xBCB57575
#define    EOFDT_NEG   0xBC959595
#define    EOFDT_POS   0xBCB59595
#define    EOFA_NEG    0xBC95F5F5
#define    EOFA_POS    0xBCB5F5F5
#define    EOFN_NEG    0xBC95D5D5
#define    EOFN_POS    0xBCB5D5D5
#define    EOFNI_NEG   0xBC8AD5D5
#define    EOFNI_POS   0xBCAAD5D5
#define    EOFDTI_NEG  0xBC8A9595
#define    EOFDTI_POS  0xBCAA9595
#define    EOFRT_NEG   0xBC959999
#define    EOFRT_POS   0xBCB59999
#define    EOFRTI_NEG  0xBC8A9999
#define    EOFRTI_POS  0xBCAA9999

static const value_string fc_sof_vals[] = {
    {FC_SOFC1, "SOFc1 - SOF Connect Class 1 (Obsolete)" },
    {FC_SOFI1, "SOFi1 - SOF Initiate Class 1 (Obsolete)" },
    {FC_SOFN1, "SOFn1 - SOF Normal Class 1 (Obsolete)" },
    {FC_SOFI2, "SOFi2 - SOF Initiate Class 2" },
    {FC_SOFN2, "SOFn2 - SOF Normal Class 2" },
    {FC_SOFI3, "SOFi3 - SOF Initiate Class 3" },
    {FC_SOFN3, "SOFn3 - SOF Normal Class 3" },
    {FC_SOFC4, "SOFc4 - SOF Activate Class 4 (Obsolete)" },
    {FC_SOFI4, "SOFi4 - SOF Initiate Class 4 (Obsolete)" },
    {FC_SOFN4, "SOFn4 - SOF Normal Class 4 (Obsolete)" },
    {FC_SOFF,  "SOFf - SOF Fabric" },
    {0, NULL}
};

static const value_string fc_eof_vals[] = {
    {EOFT_NEG,   "EOFt- - EOF Terminate" },
    {EOFT_POS,   "EOFt+ - EOF Terminate" },
    {EOFDT_NEG,  "EOFdt- - EOF Disconnect-Terminate-Class 1 (Obsolete)" },
    {EOFDT_POS,  "EOFdt+ - EOF Disconnect-Terminate-Class 1 (Obsolete)" },
    {EOFA_NEG,   "EOFa- - EOF Abort" },
    {EOFA_POS,   "EOFa+ - EOF Abort" },
    {EOFN_NEG,   "EOFn- - EOF Normal" },
    {EOFN_POS,   "EOFn+ - EOF Normal" },
    {EOFNI_NEG,  "EOFni- - EOF Normal Invalid" },
    {EOFNI_POS,  "EOFni+ - EOF Normal Invalid" },
    {EOFDTI_NEG, "EOFdti- - EOF Disconnect-Terminate-Invalid Class 1 (Obsolete)" },
    {EOFDTI_POS, "EOFdti+ - EOF Disconnect-Terminate-Invalid Class 1 (Obsolete)" },
    {EOFRT_NEG,  "EOFrt- - EOF Remove-Terminate Class 4 (Obsolete)" },
    {EOFRT_POS,  "EOFrt+ - EOF Remove-Terminate Class 4 (Obsolete)" },
    {EOFRTI_NEG, "EOFrti- - EOF Remove-Terminate Invalid Class 4 (Obsolete)" },
    {EOFRTI_POS, "EOFrti+ - EOF Remove-Terminate Invalid Class 4 (Obsolete)" },
    {0, NULL}
};

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
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BLS");

    col_set_str(pinfo->cinfo, COL_INFO, "BA_ACC");

    if (tree) {
        ti = proto_tree_add_text (tree, tvb, 0, tvb_length (tvb), "Basic Link Svc");
        acc_tree = proto_item_add_subtree (ti, ett_fcbls);

        proto_tree_add_item (acc_tree, hf_fc_bls_seqid_vld, tvb, offset++, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (acc_tree, hf_fc_bls_lastvld_seqid, tvb, offset++, 1, ENC_BIG_ENDIAN);
        offset += 2; /* Skip reserved field */
        proto_tree_add_item (acc_tree, hf_fc_bls_oxid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item (acc_tree, hf_fc_bls_rxid, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item (acc_tree, hf_fc_bls_lowseqcnt, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item (acc_tree, hf_fc_bls_hiseqcnt, tvb, offset, 2, ENC_BIG_ENDIAN);
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
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BLS");

    col_set_str(pinfo->cinfo, COL_INFO, "BA_RJT");

    if (tree) {
        ti = proto_tree_add_text (tree, tvb, 0, tvb_length (tvb), "Basic Link Svc");
        rjt_tree = proto_item_add_subtree (ti, ett_fcbls);

        proto_tree_add_item (rjt_tree, hf_fc_bls_rjtcode, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (rjt_tree, hf_fc_bls_rjtdetail, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (rjt_tree, hf_fc_bls_vendor, tvb, offset+3, 1, ENC_BIG_ENDIAN);
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
        case FC_TYPE_SB_FROM_CU:
        case FC_TYPE_SB_TO_CU:
            return FC_FTYPE_SBCCS;
        case FC_TYPE_VENDOR:
             return FC_FTYPE_OHMS;
        default:
            return FC_FTYPE_UNDEF;
        }
    case FC_RCTL_ELS:
        if (((r_ctl & 0x0F) == 0x2) || ((r_ctl & 0x0F) == 0x3))
            return FC_FTYPE_ELS;
        else if (type == FC_TYPE_ELS)
            return FC_FTYPE_OHMS;
        else
             return FC_FTYPE_UNDEF;
    case FC_RCTL_LINK_DATA:
        switch (type) {
        case FC_TYPE_SCSI:
            return FC_FTYPE_SCSI;
        default:
            return FC_FTYPE_LINKDATA;
        }
    case FC_RCTL_VIDEO:
        return FC_FTYPE_VDO;
    case FC_RCTL_BLS:
        if (type == 0)
            return FC_FTYPE_BLS;
        else
            return FC_FTYPE_UNDEF;
    case FC_RCTL_LINK_CTL:
        return FC_FTYPE_LINKCTL;
    default:
        return FC_FTYPE_UNDEF;
    }
}

static const value_string abts_ack_vals[] = {
    {0x000000,  "ABTS - Cont"},
    {0x000010,  "ABTS - Abort"},
    {0x000020,  "ABTS - Stop"},
    {0x000030,  "ABTS - Imm Seq Retx"},
    {0,NULL}
};
#if 0
static const value_string abts_not_ack_vals[] = {
    {0x000000,  "ABTS - Abort/MS"},
    {0x000010,  "ABTS - Abort/SS"},
    {0x000020,  "ABTS - Process/IB"},
    {0x000030,  "ABTS - Discard/MS/Imm Retx"},
    {0,NULL}
};
#endif
static const value_string last_data_frame_vals[] = {
    {0x000000,  "Last Data Frame - No Info"},
    {0x004000,  "Last Data Frame - Seq Imm"},
    {0x008000,  "Last Data Frame - Seq Soon"},
    {0x00c000,  "Last Data Frame - Seq Delyd"},
    {0,NULL}
};
static const value_string ack_0_1_vals[] = {
    {0x003000,  "ACK_0 Required"},
    {0x002000,  "ACK_0 Required"},
    {0x001000,  "ACK_1 Required"},
    {0x000000,  "no ack required"},
    {0,NULL}
};
static const true_false_string tfs_fc_fctl_exchange_responder = {
    "Exchange Responder",
    "Exchange Originator"
};
static const true_false_string tfs_fc_fctl_seq_recipient = {
    "Seq Recipient",
    "Seq Initiator"
};
static const true_false_string tfs_fc_fctl_exchange_first = {
    "Exchg First",
    "NOT exchg first"
};
static const true_false_string tfs_fc_fctl_exchange_last = {
    "Exchg Last",
    "NOT exchg last"
};
static const true_false_string tfs_fc_fctl_seq_last = {
    "Seq Last",
    "NOT seq last"
};
static const true_false_string tfs_fc_fctl_priority = {
    "Priority",
    "CS_CTL"
};
static const true_false_string tfs_fc_fctl_transfer_seq_initiative = {
    "Transfer Seq Initiative",
    "NOT transfer seq initiative"
};
static const true_false_string tfs_fc_fctl_rexmitted_seq = {
    "Retransmitted Sequence",
    "NOT retransmitted sequence"
};
static const true_false_string tfs_fc_fctl_rel_offset = {
    "Rel Offset SET",
    "rel offset NOT set"
};

/*
 * Dissect the VFT header.
 */
static void
dissect_fc_vft(proto_tree *parent_tree,
                tvbuff_t *tvb, int offset)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    guint8 rctl;
    guint8 ver;
    guint8 type;
    guint8 pri;
    guint16 vf_id;
    guint8 hop_ct;

    rctl = tvb_get_guint8(tvb, offset);
    type = tvb_get_guint8(tvb, offset + 1);
    ver = (type >> 6) & 3;
    type = (type >> 2) & 0xf;
    vf_id = tvb_get_ntohs(tvb, offset + 2);
    pri = (vf_id >> 13) & 7;
    vf_id = (vf_id >> 1) & 0xfff;
    hop_ct = tvb_get_guint8(tvb, offset + 4);

    if (parent_tree) {
        item = proto_tree_add_uint_format_value(parent_tree, hf_fc_vft, tvb, offset,
                                    8, vf_id, "VF_ID %d Pri %d Hop Count %d",
                                    vf_id, pri, hop_ct);
        tree = proto_item_add_subtree(item, ett_fc_vft);
    }
    proto_tree_add_uint(tree, hf_fc_vft_rctl, tvb, offset, 1, rctl);
    proto_tree_add_uint(tree, hf_fc_vft_ver, tvb, offset + 1, 1, ver);
    proto_tree_add_uint(tree, hf_fc_vft_type, tvb, offset + 1, 1, type);
    proto_tree_add_uint(tree, hf_fc_vft_pri, tvb, offset + 2, 1, pri);
    proto_tree_add_uint(tree, hf_fc_vft_vf_id, tvb, offset + 2, 2, vf_id);
    proto_tree_add_uint(tree, hf_fc_vft_hop_ct, tvb, offset + 4, 1, hop_ct);
}

/* code to dissect the  F_CTL bitmask */
static void
dissect_fc_fctl(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    guint32 flags;

    flags = tvb_get_guint8 (tvb, offset);
    flags = (flags<<8) | tvb_get_guint8 (tvb, offset+1);
    flags = (flags<<8) | tvb_get_guint8 (tvb, offset+2);

    if(parent_tree){
        item=proto_tree_add_uint(parent_tree, hf_fc_fctl, tvb, offset, 3, flags);
        tree=proto_item_add_subtree(item, ett_fctl);
    }

    proto_tree_add_boolean(tree, hf_fc_fctl_exchange_responder, tvb, offset, 3, flags);
    if (flags&FC_FCTL_EXCHANGE_RESPONDER){
        proto_item_append_text(item, " Exchange Responder");
        if (flags & (~( FC_FCTL_EXCHANGE_RESPONDER )))
            proto_item_append_text(item, ",");
    } else {
        proto_item_append_text(item, " Exchange Originator");
        if (flags & (~( FC_FCTL_EXCHANGE_RESPONDER )))
            proto_item_append_text(item, ",");
    }
    flags&=(~( FC_FCTL_EXCHANGE_RESPONDER ));

    proto_tree_add_boolean(tree, hf_fc_fctl_seq_recipient, tvb, offset, 3, flags);
    if (flags&FC_FCTL_SEQ_RECIPIENT){
        proto_item_append_text(item, " Seq Recipient");
        if (flags & (~( FC_FCTL_SEQ_RECIPIENT )))
            proto_item_append_text(item, ",");
    } else {
        proto_item_append_text(item, " Seq Initiator");
        if (flags & (~( FC_FCTL_SEQ_RECIPIENT )))
            proto_item_append_text(item, ",");
    }
    flags&=(~( FC_FCTL_SEQ_RECIPIENT ));

    proto_tree_add_boolean(tree, hf_fc_fctl_exchange_first, tvb, offset, 3, flags);
    if (flags&FC_FCTL_EXCHANGE_FIRST){
        proto_item_append_text(item, " Exchg First");
        if (flags & (~( FC_FCTL_EXCHANGE_FIRST )))
            proto_item_append_text(item, ",");
    }
    flags&=(~( FC_FCTL_EXCHANGE_FIRST ));

    proto_tree_add_boolean(tree, hf_fc_fctl_exchange_last, tvb, offset, 3, flags);
    if (flags&FC_FCTL_EXCHANGE_LAST){
        proto_item_append_text(item, " Exchg Last");
        if (flags & (~( FC_FCTL_EXCHANGE_LAST )))
            proto_item_append_text(item, ",");
    }
    flags&=(~( FC_FCTL_EXCHANGE_LAST ));

    proto_tree_add_boolean(tree, hf_fc_fctl_seq_last, tvb, offset, 3, flags);
    if (flags&FC_FCTL_SEQ_LAST){
        proto_item_append_text(item, " Seq Last");
        if (flags & (~( FC_FCTL_SEQ_LAST )))
            proto_item_append_text(item, ",");
    }
    flags&=(~( FC_FCTL_SEQ_LAST ));

    proto_tree_add_boolean(tree, hf_fc_fctl_priority, tvb, offset, 3, flags);
    if (flags&FC_FCTL_PRIORITY){
        proto_item_append_text(item, " Priority");
        if (flags & (~( FC_FCTL_PRIORITY )))
            proto_item_append_text(item, ",");
    } else {
        proto_item_append_text(item, " CS_CTL");
        if (flags & (~( FC_FCTL_PRIORITY )))
            proto_item_append_text(item, ",");
    }
    flags&=(~( FC_FCTL_PRIORITY ));

    proto_tree_add_boolean(tree, hf_fc_fctl_transfer_seq_initiative, tvb, offset, 3, flags);
    if (flags&FC_FCTL_TRANSFER_SEQ_INITIATIVE){
        proto_item_append_text(item, " Transfer Seq Initiative");
        if (flags & (~( FC_FCTL_TRANSFER_SEQ_INITIATIVE )))
            proto_item_append_text(item, ",");
    }
    flags&=(~( FC_FCTL_TRANSFER_SEQ_INITIATIVE ));

    proto_tree_add_uint(tree, hf_fc_fctl_last_data_frame, tvb, offset, 3, flags);

    proto_tree_add_uint(tree, hf_fc_fctl_ack_0_1, tvb, offset, 3, flags);

    proto_tree_add_boolean(tree, hf_fc_fctl_rexmitted_seq, tvb, offset, 3, flags);
    if (flags&FC_FCTL_REXMITTED_SEQ){
        proto_item_append_text(item, " Rexmitted Seq");
        if (flags & (~( FC_FCTL_REXMITTED_SEQ )))
            proto_item_append_text(item, ",");
    }
    flags&=(~( FC_FCTL_REXMITTED_SEQ ));

    proto_tree_add_uint(tree, hf_fc_fctl_abts_ack, tvb, offset, 3, flags);

    proto_tree_add_boolean(tree, hf_fc_fctl_rel_offset, tvb, offset, 3, flags);
    if (flags&FC_FCTL_REL_OFFSET){
        proto_item_append_text(item, " Rel Offset");
        if (flags & (~( FC_FCTL_REL_OFFSET )))
            proto_item_append_text(item, ",");
    }

}

static const value_string fc_bls_proto_val[] = {
    {FC_BLS_NOP    , "NOP"},
    {FC_BLS_ABTS   , "ABTS"},
    {FC_BLS_RMC    , "RMC"},
    {FC_BLS_BAACC  , "BA_ACC"},
    {FC_BLS_BARJT  , "BA_RJT"},
    {FC_BLS_PRMT   , "PRMT"},
    {0, NULL}
};

static const value_string fc_els_proto_val[] = {
    {0x01    , "Solicited Data"},
    {0x02    , "Request"},
    {0x03    , "Reply"},
    {0, NULL}
};

/* Code to actually dissect the packets */
static void
dissect_fc_helper (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean is_ifcp, fc_data_t* fc_data)
{
   /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti, *hidden_item;
    proto_tree *fc_tree;
    tvbuff_t *next_tvb;
    int offset = 0, next_offset;
    int vft_offset = -1;
    gboolean is_lastframe_inseq, is_1frame_inseq, is_exchg_resp = 0;
    fragment_head *fcfrag_head;
    guint32 frag_id, frag_size;
    guint8 df_ctl, seq_id;
    guint32 f_ctl;

    guint32 param, exchange_key;
    guint16 real_seqcnt;
    guint8 ftype;

    fc_hdr fchdr;
    fc_exchange_t *fc_ex;
    fc_conv_data_t *fc_conv_data=NULL;

    conversation_t *conversation;
    fcseq_conv_data_t *cdata;
    fcseq_conv_key_t ckey, *req_key;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FC");

    fchdr.r_ctl = tvb_get_guint8 (tvb, offset);
    fchdr.fc_ex = NULL;

    /*
     * If the frame contains a VFT (virtual fabric tag), decode it
     * as a separate header before the FC frame header.
     *
     * This used to be called the Cisco-proprietary EISL field, but is now
     * standardized in FC-FS-2.  See section 10.2.4.
     */
    if (fchdr.r_ctl == FC_RCTL_VFT) {
        vft_offset = offset;
        offset += 8;
        fchdr.r_ctl = tvb_get_guint8 (tvb, offset);
    }

    /* Each fc endpoint pair gets its own TCP session in iFCP but
     * the src/dst ids are undefined(==semi-random) in the FC header.
     * This means we can no track conversations for FC over iFCP by using
     * the FC src/dst addresses.
     * For iFCP: Do not update the pinfo src/dst struct and let it remain
     * being tcpip src/dst so that request/response matching in the FCP layer
     * will use ip addresses instead and still work.
     */
    if(!is_ifcp){
        TVB_SET_ADDRESS (&pinfo->dst, AT_FC, tvb, offset+1, 3);
        TVB_SET_ADDRESS (&pinfo->src, AT_FC, tvb, offset+5, 3);
        pinfo->srcport=0;
        pinfo->destport=0;
    }
    SET_ADDRESS(&fchdr.d_id, pinfo->dst.type, pinfo->dst.len, pinfo->dst.data);
    SET_ADDRESS(&fchdr.s_id, pinfo->src.type, pinfo->src.len, pinfo->src.data);

    fchdr.cs_ctl = tvb_get_guint8 (tvb, offset+4);
    fchdr.type  = tvb_get_guint8 (tvb, offset+8);
    fchdr.fctl=tvb_get_ntoh24(tvb,offset+9);
    fchdr.seqcnt = tvb_get_ntohs (tvb, offset+14);
    fchdr.oxid=tvb_get_ntohs(tvb,offset+16);
    fchdr.rxid=tvb_get_ntohs(tvb,offset+18);
    fchdr.relative_offset=0;
    param = tvb_get_ntohl (tvb, offset+20);
    seq_id = tvb_get_guint8 (tvb, offset+12);

    pinfo->ptype = PT_EXCHG;

    /* set up a conversation and conversation data */
    /* TODO treat the fc address  s_id==00.00.00 as a wildcard matching anything */
    conversation=find_or_create_conversation(pinfo);
    fc_conv_data=(fc_conv_data_t *)conversation_get_proto_data(conversation, proto_fc);
    if(!fc_conv_data){
        fc_conv_data=wmem_new(wmem_file_scope(), fc_conv_data_t);
        fc_conv_data->exchanges=wmem_tree_new(wmem_file_scope());
        fc_conv_data->luns=wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conversation, proto_fc, fc_conv_data);
    }

    /* Set up LUN data. OXID + LUN make up unique exchanges, but LUN is populated in subdissectors
       and not necessarily in every frame. Stub it here for now */
    fchdr.lun = 0xFFFF;
    if (!pinfo->fd->flags.visited) {
        fchdr.lun = (guint16)GPOINTER_TO_UINT(wmem_tree_lookup32(fc_conv_data->luns, fchdr.oxid));
    }

    /* In the interest of speed, if "tree" is NULL, don't do any work not
       necessary to generate protocol tree items. */
    ti = proto_tree_add_protocol_format (tree, proto_fc, tvb, offset, FC_HEADER_SIZE, "Fibre Channel");
    fc_tree = proto_item_add_subtree (ti, ett_fc);

    /*is_ack = ((fchdr.r_ctl == 0xC0) || (fchdr.r_ctl == 0xC1));*/

    /* There are two ways to determine if this is the first frame of a
     * sequence. Either:
     * (i) The SOF bits indicate that this is the first frame OR
     * (ii) This is an SOFf frame and seqcnt is 0.
     */
    is_1frame_inseq = (((fc_data->sof_eof & FC_DATA_SOF_FIRST_FRAME) == FC_DATA_SOF_FIRST_FRAME) ||
                       (((fc_data->sof_eof & FC_DATA_SOF_SOFF) == FC_DATA_SOF_SOFF) &&
                        (fchdr.seqcnt == 0)));

    is_lastframe_inseq = ((fc_data->sof_eof & FC_DATA_EOF_LAST_FRAME) == FC_DATA_EOF_LAST_FRAME);

    is_lastframe_inseq |= fchdr.fctl & FC_FCTL_SEQ_LAST;
    /*is_valid_frame = ((pinfo->sof_eof & 0x40) == 0x40);*/

    ftype = fc_get_ftype (fchdr.r_ctl, fchdr.type);

    col_add_str (pinfo->cinfo, COL_INFO, val_to_str (ftype, fc_ftype_vals,
                                                        "Unknown Type (0x%x)"));

    if (ftype == FC_FTYPE_LINKCTL)
        col_append_fstr (pinfo->cinfo, COL_INFO, ", %s",
                            val_to_str ((fchdr.r_ctl & 0x0F),
                                        fc_lctl_proto_val,
                                        "LCTL 0x%x"));

    if (vft_offset >= 0) {
        dissect_fc_vft(fc_tree, tvb, vft_offset);
    }
    switch (fchdr.r_ctl & 0xF0) {

    case FC_RCTL_DEV_DATA:
    case FC_RCTL_LINK_DATA:
    case FC_RCTL_VIDEO:
        /* the lower 4 bits of R_CTL are the information category */
        proto_tree_add_uint_format_value(fc_tree, hf_fc_rctl, tvb, offset,
                                    FC_RCTL_SIZE, fchdr.r_ctl,
                                    "0x%x(%s/%s)",
                                    fchdr.r_ctl,
                                    val_to_str ((fchdr.r_ctl & 0xF0),
                                                fc_routing_val, "0x%x"),
                                    val_to_str ((fchdr.r_ctl & 0x0F),
                                                fc_iu_val, "0x%x"));
        break;

    case FC_RCTL_LINK_CTL:
        /* the lower 4 bits of R_CTL indicate the type of link ctl frame */
        proto_tree_add_uint_format_value(fc_tree, hf_fc_rctl, tvb, offset,
                                    FC_RCTL_SIZE, fchdr.r_ctl,
                                    "0x%x(%s/%s)",
                                    fchdr.r_ctl,
                                    val_to_str ((fchdr.r_ctl & 0xF0),
                                                fc_routing_val, "0x%x"),
                                    val_to_str ((fchdr.r_ctl & 0x0F),
                                                fc_lctl_proto_val, "0x%x"));
        break;

    case FC_RCTL_BLS:
        switch (fchdr.type) {

        case 0x00:
            /* the lower 4 bits of R_CTL indicate the type of BLS frame */
            proto_tree_add_uint_format_value(fc_tree, hf_fc_rctl, tvb, offset,
                                        FC_RCTL_SIZE, fchdr.r_ctl,
                                        "0x%x(%s/%s)",
                                        fchdr.r_ctl,
                                        val_to_str ((fchdr.r_ctl & 0xF0),
                                                    fc_routing_val, "0x%x"),
                                        val_to_str ((fchdr.r_ctl & 0x0F),
                                                    fc_bls_proto_val, "0x%x"));
            break;

        default:
            proto_tree_add_uint_format_value(fc_tree, hf_fc_rctl, tvb, offset,
                                        FC_RCTL_SIZE, fchdr.r_ctl,
                                        "0x%x(%s/0x%x)",
                                        fchdr.r_ctl,
                                        val_to_str ((fchdr.r_ctl & 0xF0),
                                                    fc_routing_val, "0x%x"),
                                        fchdr.r_ctl & 0x0F);
            break;
        }
        break;

    case FC_RCTL_ELS:
        switch (fchdr.type) {

        case 0x01:
            /* the lower 4 bits of R_CTL indicate the type of ELS frame */
            proto_tree_add_uint_format_value(fc_tree, hf_fc_rctl, tvb, offset,
                                        FC_RCTL_SIZE, fchdr.r_ctl,
                                        "0x%x(%s/%s)",
                                        fchdr.r_ctl,
                                        val_to_str ((fchdr.r_ctl & 0xF0),
                                                    fc_routing_val, "0x%x"),
                                        val_to_str ((fchdr.r_ctl & 0x0F),
                                                    fc_els_proto_val, "0x%x"));
            break;

        default:
            proto_tree_add_uint_format_value(fc_tree, hf_fc_rctl, tvb, offset,
                                        FC_RCTL_SIZE, fchdr.r_ctl,
                                        "0x%x(%s/0x%x)",
                                        fchdr.r_ctl,
                                        val_to_str ((fchdr.r_ctl & 0xF0),
                                                    fc_routing_val, "0x%x"),
                                        fchdr.r_ctl & 0x0F);
            break;
        }
        break;

    default:
        proto_tree_add_uint_format_value(fc_tree, hf_fc_rctl, tvb, offset,
                                    FC_RCTL_SIZE, fchdr.r_ctl,
                                    "0x%x(%s/0x%x)",
                                    fchdr.r_ctl,
                                    val_to_str ((fchdr.r_ctl & 0xF0),
                                                fc_routing_val, "0x%x"),
                                    fchdr.r_ctl & 0x0F);
        break;
    }

    hidden_item = proto_tree_add_uint (fc_tree, hf_fc_ftype, tvb, offset, 1,
                                       ftype);
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    /* XXX - use "fc_wka_vals[]" on this? */
    proto_tree_add_string (fc_tree, hf_fc_did, tvb, offset+1, 3,
                           fc_to_str ((const guint8 *)fchdr.d_id.data));
    hidden_item = proto_tree_add_string (fc_tree, hf_fc_id, tvb, offset+1, 3,
                                         fc_to_str ((const guint8 *)fchdr.d_id.data));
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    proto_tree_add_uint (fc_tree, hf_fc_csctl, tvb, offset+4, 1, fchdr.cs_ctl);

    /* XXX - use "fc_wka_vals[]" on this? */
    proto_tree_add_string (fc_tree, hf_fc_sid, tvb, offset+5, 3,
                           fc_to_str ((const guint8 *)fchdr.s_id.data));
    hidden_item = proto_tree_add_string (fc_tree, hf_fc_id, tvb, offset+5, 3,
                                         fc_to_str ((const guint8 *)fchdr.s_id.data));
    PROTO_ITEM_SET_HIDDEN(hidden_item);

    if (ftype == FC_FTYPE_LINKCTL) {
        if (((fchdr.r_ctl & 0x0F) == FC_LCTL_FBSYB) ||
            ((fchdr.r_ctl & 0x0F) == FC_LCTL_FBSYL)) {
            /* for F_BSY frames, the upper 4 bits of the type field specify the
             * reason for the BSY.
             */
            proto_tree_add_uint_format_value(fc_tree, hf_fc_type, tvb,
                                        offset+8, FC_TYPE_SIZE,
                                        fchdr.type,"0x%x(%s)", fchdr.type,
                                        fclctl_get_typestr ((guint8) (fchdr.r_ctl & 0x0F),
                                                            fchdr.type));
        } else {
            proto_tree_add_item (fc_tree, hf_fc_type, tvb, offset+8, 1, ENC_BIG_ENDIAN);
        }
    } else {
        proto_tree_add_item (fc_tree, hf_fc_type, tvb, offset+8, 1, ENC_BIG_ENDIAN);
    }


    dissect_fc_fctl(pinfo, fc_tree, tvb, offset+9);
    f_ctl = tvb_get_ntoh24(tvb, offset+9);


    proto_tree_add_item (fc_tree, hf_fc_seqid, tvb, offset+12, 1, ENC_BIG_ENDIAN);

    df_ctl = tvb_get_guint8(tvb, offset+13);

    proto_tree_add_uint (fc_tree, hf_fc_dfctl, tvb, offset+13, 1, df_ctl);
    proto_tree_add_uint (fc_tree, hf_fc_seqcnt, tvb, offset+14, 2, fchdr.seqcnt);
    proto_tree_add_uint (fc_tree, hf_fc_oxid, tvb, offset+16, 2, fchdr.oxid);
    proto_tree_add_uint (fc_tree, hf_fc_rxid, tvb, offset+18, 2, fchdr.rxid);

    if (ftype == FC_FTYPE_LINKCTL) {
        if (((fchdr.r_ctl & 0x0F) == FC_LCTL_FRJT) ||
            ((fchdr.r_ctl & 0x0F) == FC_LCTL_PRJT) ||
            ((fchdr.r_ctl & 0x0F) == FC_LCTL_PBSY)) {
            /* In all these cases of Link Ctl frame, the parameter field
             * encodes the detailed error message
             */
            proto_tree_add_uint_format_value(fc_tree, hf_fc_param, tvb,
                                        offset+20, 4, param,
                                        "0x%x(%s)", param,
                                        fclctl_get_paramstr ((fchdr.r_ctl & 0x0F),
                                                             param));
        } else {
            proto_tree_add_item (fc_tree, hf_fc_param, tvb, offset+20, 4, ENC_BIG_ENDIAN);
        }
    } else if (ftype == FC_FTYPE_BLS) {
        if ((fchdr.r_ctl & 0x0F) == FC_BLS_ABTS) {
            proto_tree_add_uint_format_value(fc_tree, hf_fc_param, tvb,
                                        offset+20, 4, param,
                                        "0x%x(%s)", param,
                                        ((param & 0x0F) == 1 ? "Abort Sequence" :
                                         "Abort Exchange"));
        } else {
            proto_tree_add_item (fc_tree, hf_fc_param, tvb, offset+20,
                                 4, ENC_BIG_ENDIAN);
        }
    } else if (ftype == FC_FTYPE_SCSI ) {
        if (f_ctl&FC_FCTL_REL_OFFSET){
            proto_tree_add_item (fc_tree, hf_fc_relative_offset, tvb, offset+20, 4, ENC_BIG_ENDIAN);
            fchdr.relative_offset=tvb_get_ntohl(tvb, offset+20);
        } else {
            proto_tree_add_item (fc_tree, hf_fc_param, tvb, offset+20, 4, ENC_BIG_ENDIAN);
        }
    } else {
        proto_tree_add_item (fc_tree, hf_fc_param, tvb, offset+20, 4, ENC_BIG_ENDIAN);
    }

    /* Skip the Frame_Header */
    next_offset = offset + FC_HEADER_SIZE;

    /* Network_Header present? */
    if (df_ctl & FC_DFCTL_NH) {
        /* Yes - dissect it. */
        if (tree) {
            proto_tree_add_string (fc_tree, hf_fc_nh_da, tvb, next_offset, 8,
                                   fcwwn_to_str (tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 8, ENC_ASCII)));
            proto_tree_add_string (fc_tree, hf_fc_nh_sa, tvb, offset+8, 8,
                                   fcwwn_to_str (tvb_get_string_enc(wmem_packet_scope(), tvb, offset+8, 8, ENC_ASCII)));
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
    } else {
        is_exchg_resp = (f_ctl & FC_FCTL_EXCHANGE_RESPONDER) != 0;
    }

    if (tvb_reported_length (tvb) < FC_HEADER_SIZE)
        THROW(ReportedBoundsError);

    frag_size = tvb_reported_length (tvb)-FC_HEADER_SIZE;

    /* If there is an MDS header, we need to subtract the MDS trailer size
     * Link Ctl, BLS & OHMS are all (encap header + FC Header + encap trailer)
     * and are never fragmented and so we ignore the frag_size assertion for
     *  these frames.
     */
    if ((fc_data->ethertype == ETHERTYPE_UNK) || (fc_data->ethertype == ETHERTYPE_FCFT)) {
        if ((frag_size < MDSHDR_TRAILER_SIZE) ||
            ((frag_size == MDSHDR_TRAILER_SIZE) && (ftype != FC_FTYPE_LINKCTL) &&
             (ftype != FC_FTYPE_BLS) && (ftype != FC_FTYPE_OHMS)))
            THROW(ReportedBoundsError);
        frag_size -= MDSHDR_TRAILER_SIZE;
    } else if (fc_data->ethertype == ETHERTYPE_BRDWALK) {
        if ((frag_size <= 8) ||
            ((frag_size == MDSHDR_TRAILER_SIZE) && (ftype != FC_FTYPE_LINKCTL) &&
             (ftype != FC_FTYPE_BLS) && (ftype != FC_FTYPE_OHMS)))
            THROW(ReportedBoundsError);
        frag_size -= 8;         /* 4 byte of FC CRC +
                                   4 bytes of error+EOF = 8 bytes  */
    }

    if (!is_lastframe_inseq) {
        /* Show this only as a fragmented FC frame */
        col_append_str (pinfo->cinfo, COL_INFO, " (Fragmented)");
    }

    /* If this is a fragment, attempt to check if fully reassembled frame is
     * present, if we're configured to reassemble.
     */
    if ((ftype != FC_FTYPE_LINKCTL) && (ftype != FC_FTYPE_BLS) &&
        (ftype != FC_FTYPE_OHMS) &&
        (!is_lastframe_inseq || !is_1frame_inseq) && fc_reassemble &&
        tvb_bytes_exist(tvb, FC_HEADER_SIZE, frag_size) && tree) {
        /* Add this to the list of fragments */

        /* In certain cases such as FICON, the SEQ_CNT is streaming
         * i.e. continuously increasing. So, zero does not signify the
         * first frame of the sequence. To fix this, we need to save the
         * SEQ_CNT of the first frame in sequence and use this value to
         * determine the actual offset into a frame.
         */
        ckey.conv_idx = conversation->index;

        cdata = (fcseq_conv_data_t *)g_hash_table_lookup (fcseq_req_hash,
                                                          &ckey);

        if (is_1frame_inseq) {
            if (cdata) {
                /* Since we never free the memory used by an exchange, this maybe a
                 * case of another request using the same exchange as a previous
                 * req.
                 */
                cdata->seq_cnt = fchdr.seqcnt;
            }
            else {
                req_key = wmem_new(wmem_file_scope(), fcseq_conv_key_t);
                req_key->conv_idx = conversation->index;

                cdata = wmem_new(wmem_file_scope(), fcseq_conv_data_t);
                cdata->seq_cnt = fchdr.seqcnt;

                g_hash_table_insert (fcseq_req_hash, req_key, cdata);
            }
            real_seqcnt = 0;
        }
        else if (cdata != NULL) {
            real_seqcnt = fchdr.seqcnt - cdata->seq_cnt ;
        }
        else {
            real_seqcnt = fchdr.seqcnt;
        }

        /* Verify that this is a valid fragment */
        if (is_lastframe_inseq && !is_1frame_inseq && !real_seqcnt) {
             /* This is a frame that purports to be the last frame in a
              * sequence, is not the first frame, but has a seqcnt that is
              * 0. This is a bogus frame, don't attempt to reassemble it.
              */
             next_tvb = tvb_new_subset_remaining (tvb, next_offset);
             col_append_str (pinfo->cinfo, COL_INFO, " (Bogus Fragment)");
        } else {

             frag_id = ((fchdr.oxid << 16) ^ seq_id) | is_exchg_resp ;

             /* We assume that all frames are of the same max size */
             fcfrag_head = fragment_add (&fc_reassembly_table,
                                         tvb, FC_HEADER_SIZE,
                                         pinfo, frag_id, NULL,
                                         real_seqcnt * fc_max_frame_size,
                                         frag_size,
                                         !is_lastframe_inseq);

             if (fcfrag_head) {
                  next_tvb = tvb_new_chain(tvb, fcfrag_head->tvb_data);

                  /* Add the defragmented data to the data source list. */
                  add_new_data_source(pinfo, next_tvb, "Reassembled FC");

                  if (tree) {
                      hidden_item = proto_tree_add_boolean (fc_tree, hf_fc_reassembled,
                                                            tvb, offset+9, 1, 1);
                      PROTO_ITEM_SET_HIDDEN(hidden_item);
                  }
             }
             else {
                  if (tree) {
                       hidden_item = proto_tree_add_boolean (fc_tree, hf_fc_reassembled,
                                                             tvb, offset+9, 1, 0);
                       PROTO_ITEM_SET_HIDDEN(hidden_item);
            }
                  next_tvb = tvb_new_subset_remaining (tvb, next_offset);
                  call_dissector (data_handle, next_tvb, pinfo, tree);
                  return;
             }
        }
    } else {
        if (tree) {
            hidden_item = proto_tree_add_boolean (fc_tree, hf_fc_reassembled,
                                                  tvb, offset+9, 1, 0);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
        }
        next_tvb = tvb_new_subset_remaining (tvb, next_offset);
    }

    if ((ftype != FC_FTYPE_LINKCTL) && (ftype != FC_FTYPE_BLS)) {
        /* If relative offset is used, only dissect the pdu with
         * offset 0 (param) */
        if( (fchdr.fctl&FC_FCTL_REL_OFFSET) && param ){
            call_dissector (data_handle, next_tvb, pinfo, tree);
        } else {
            if (!dissector_try_uint_new (fcftype_dissector_table, ftype,
                                next_tvb, pinfo, tree, FALSE, &fchdr)) {
                call_dissector (data_handle, next_tvb, pinfo, tree);
            }
        }
    } else if (ftype == FC_FTYPE_BLS) {
        if ((fchdr.r_ctl & 0x0F) == FC_BLS_BAACC) {
            dissect_fc_ba_acc (next_tvb, pinfo, tree);
        } else if ((fchdr.r_ctl & 0x0F) == FC_BLS_BARJT) {
            dissect_fc_ba_rjt (next_tvb, pinfo, tree);
        } else if ((fchdr.r_ctl & 0x0F) == FC_BLS_ABTS) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "BLS");
            col_set_str(pinfo->cinfo, COL_INFO, "ABTS");
        }
    }

    /* Lun is only populated by subdissectors, and subsequent packets assume the same lun.
       The only way that consistently works is to save the lun on the first pass (with OXID as
       key) when packets are guaranteed to be parsed consecutively */

    /* Set up LUN data */
    if (!pinfo->fd->flags.visited) {
        wmem_tree_insert32(fc_conv_data->luns, fchdr.oxid, GUINT_TO_POINTER((guint)fchdr.lun));
    }

    exchange_key = ((fchdr.oxid & 0xFFFF) | ((fchdr.lun << 16) & 0xFFFF0000));

    /* set up the exchange data */
    /* XXX we should come up with a way to handle when the 16bit oxid wraps
     * so that large traces will work
     */
    fc_ex=(fc_exchange_t*)wmem_tree_lookup32(fc_conv_data->exchanges, exchange_key);
    if(!fc_ex){
        fc_ex=wmem_new(wmem_file_scope(), fc_exchange_t);
        fc_ex->first_exchange_frame=0;
        fc_ex->last_exchange_frame=0;
        fc_ex->fc_time=pinfo->fd->abs_ts;

        wmem_tree_insert32(fc_conv_data->exchanges, exchange_key, fc_ex);
    }

    fchdr.fc_ex = fc_ex;

    /* populate the exchange struct */
    if(!pinfo->fd->flags.visited){
        if(fchdr.fctl&FC_FCTL_EXCHANGE_FIRST){
            fc_ex->first_exchange_frame=pinfo->fd->num;
            fc_ex->fc_time = pinfo->fd->abs_ts;
        }
        if(fchdr.fctl&FC_FCTL_EXCHANGE_LAST){
            fc_ex->last_exchange_frame=pinfo->fd->num;
        }
    }

    /* put some nice exchange data in the tree */
    if(!(fchdr.fctl&FC_FCTL_EXCHANGE_FIRST)){
        proto_item *it;
        it=proto_tree_add_uint(fc_tree, hf_fc_exchange_first_frame, tvb, 0, 0, fc_ex->first_exchange_frame);
        PROTO_ITEM_SET_GENERATED(it);
        if(fchdr.fctl&FC_FCTL_EXCHANGE_LAST){
            nstime_t delta_ts;
            nstime_delta(&delta_ts, &pinfo->fd->abs_ts, &fc_ex->fc_time);
            it=proto_tree_add_time(ti, hf_fc_time, tvb, 0, 0, &delta_ts);
            PROTO_ITEM_SET_GENERATED(it);
        }
    }
    if(!(fchdr.fctl&FC_FCTL_EXCHANGE_LAST)){
        proto_item *it;
        it=proto_tree_add_uint(fc_tree, hf_fc_exchange_last_frame, tvb, 0, 0, fc_ex->last_exchange_frame);
        PROTO_ITEM_SET_GENERATED(it);
    }

    tap_queue_packet(fc_tap, pinfo, &fchdr);
}

static int
dissect_fc (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    fc_data_t* fc_data = (fc_data_t*)data;

    if (!fc_data)
       return 0;

    dissect_fc_helper (tvb, pinfo, tree, FALSE, fc_data);
    return tvb_length(tvb);
}

static int
dissect_fc_ifcp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    fc_data_t* fc_data = (fc_data_t*)data;

    if (!fc_data)
       return 0;

    dissect_fc_helper (tvb, pinfo, tree, TRUE, fc_data);
    return tvb_length(tvb);
}

static void
dissect_fcsof(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

    proto_item *it = NULL;
    proto_tree *fcsof_tree = NULL;
    tvbuff_t *next_tvb, *checksum_tvb;
    guint32 sof = 0;
    guint32 crc = 0;
    guint32 crc_computed = 0;
    guint32 eof = 0;
    gint crc_offset = 0;
    gint eof_offset = 0;
    gint sof_offset = 0;
    const gint FCSOF_TRAILER_LEN = 8;
    const gint FCSOF_HEADER_LEN = 4;
    gint frame_len_for_checksum = 0;
    fc_data_t fc_data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FC");

    crc_offset = tvb_reported_length(tvb) - FCSOF_TRAILER_LEN;
    eof_offset = crc_offset + 4;
    sof_offset = 0;

    /* Get SOF */
    sof = tvb_get_ntohl(tvb, 0);

    /* GET CRC */
    crc = tvb_get_ntohl(tvb, crc_offset);

    /* GET Computed CRC */
    frame_len_for_checksum = crc_offset - FCSOF_HEADER_LEN;
    checksum_tvb = tvb_new_subset_length(tvb, 4, frame_len_for_checksum);
    crc_computed = crc32_802_tvb(checksum_tvb, frame_len_for_checksum);

    /* Get EOF */
    eof = tvb_get_ntohl(tvb, eof_offset);

    it = proto_tree_add_protocol_format(tree, proto_fcsof, tvb, 0,
                                        4, "Fibre Channel Delimiter: SOF: %s EOF: %s",
                                        val_to_str(sof, fc_sof_vals, "0x%x"),
                                        val_to_str(eof, fc_eof_vals, "0x%x"));

    fcsof_tree = proto_item_add_subtree(it, ett_fcsof);

    proto_tree_add_uint(fcsof_tree, hf_fcsof, tvb, sof_offset, 4, sof);

    if (crc == crc_computed) {
        proto_tree_add_uint_format_value(fcsof_tree, hf_fccrc, tvb,
                                       crc_offset, 4, crc,
                                       "%8.8x [valid]", crc);
    } else {
        it = proto_tree_add_uint_format_value(fcsof_tree, hf_fccrc, tvb,
                                       crc_offset, 4, crc,
                                       "%8.8x [error: should be %8.8x]",
                                       crc, crc_computed);

        expert_add_info_format(pinfo, it, &ei_fccrc,
                                   "Bad FC CRC %8.8x %8.x",
                                   crc, crc_computed);
    }

    proto_tree_add_uint(fcsof_tree, hf_fceof, tvb, eof_offset, 4, eof);

    next_tvb = tvb_new_subset_remaining(tvb, 4);

    fc_data.ethertype = 0;
    fc_data.sof_eof = 0;
    if (sof == FC_SOFI2 || sof == FC_SOFI3) {
        fc_data.sof_eof = FC_DATA_SOF_FIRST_FRAME;
    } else if (sof == FC_SOFF) {
        fc_data.sof_eof = FC_DATA_SOF_SOFF;
    }

    if (eof == EOFT_POS || eof == EOFT_NEG) {
        fc_data.sof_eof |= FC_DATA_EOF_LAST_FRAME;
    } else if (eof == EOFDTI_NEG || eof == EOFDTI_POS) {
        fc_data.sof_eof |= FC_DATA_EOF_INVALID;
    }

    /* Call FC dissector */
    call_dissector_with_data(fc_handle, next_tvb, pinfo, tree, &fc_data);
}

/* Register the protocol with Wireshark */

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
            NULL, HFILL }},
        { &hf_fc_ftype,
          {"Frame type", "fc.ftype", FT_UINT8, BASE_HEX, VALS(fc_ftype_vals),
           0x0, "Derived Type", HFILL}},
        { &hf_fc_did,
          { "Dest Addr", "fc.d_id", FT_STRING, BASE_NONE, NULL, 0x0,
            "Destination Address", HFILL}},
        { &hf_fc_csctl,
          {"CS_CTL", "fc.cs_ctl", FT_UINT8, BASE_HEX, NULL, 0x0,
           NULL, HFILL}},
        { &hf_fc_sid,
          {"Src Addr", "fc.s_id", FT_STRING, BASE_NONE, NULL, 0x0,
           "Source Address", HFILL}},
        { &hf_fc_id,
          {"Addr", "fc.id", FT_STRING, BASE_NONE, NULL, 0x0,
           "Source or Destination Address", HFILL}},
        { &hf_fc_type,
          {"Type", "fc.type", FT_UINT8, BASE_HEX, VALS (fc_fc4_val), 0x0,
           NULL, HFILL}},
        { &hf_fc_fctl,
          {"F_CTL", "fc.f_ctl", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        { &hf_fc_seqid,
          {"SEQ_ID", "fc.seq_id", FT_UINT8, BASE_HEX, NULL, 0x0,
           "Sequence ID", HFILL}},
        { &hf_fc_dfctl,
          {"DF_CTL", "fc.df_ctl", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
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
          {"Parameter", "fc.parameter", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},

        { &hf_fc_reassembled,
          {"Reassembled Frame", "fc.reassembled", FT_BOOLEAN, BASE_NONE, NULL,
           0x0, NULL, HFILL}},
        { &hf_fc_nh_da,
          {"Network DA", "fc.nethdr.da", FT_STRING, BASE_NONE, NULL,
           0x0, NULL, HFILL}},
        { &hf_fc_nh_sa,
          {"Network SA", "fc.nethdr.sa", FT_STRING, BASE_NONE, NULL,
           0x0, NULL, HFILL}},

        /* Basic Link Svc field definitions */
        { &hf_fc_bls_seqid_vld,
          {"SEQID Valid", "fc.bls_seqidvld", FT_UINT8, BASE_HEX,
           VALS (fc_bls_seqid_val), 0x0, NULL, HFILL}},
        { &hf_fc_bls_lastvld_seqid,
          {"Last Valid SEQID", "fc.bls_lastseqid", FT_UINT8, BASE_HEX, NULL,
           0x0, NULL, HFILL}},
        { &hf_fc_bls_oxid,
          {"OXID", "fc.bls_oxid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        { &hf_fc_bls_rxid,
          {"RXID", "fc.bls_rxid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        { &hf_fc_bls_lowseqcnt,
          {"Low SEQCNT", "fc.bls_lseqcnt", FT_UINT16, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fc_bls_hiseqcnt,
          {"High SEQCNT", "fc.bls_hseqcnt", FT_UINT16, BASE_HEX, NULL, 0x0, NULL,
           HFILL}},
        { &hf_fc_bls_rjtcode,
          {"Reason", "fc.bls_reason", FT_UINT8, BASE_HEX, VALS(fc_bls_barjt_val),
           0x0, NULL, HFILL}},
        { &hf_fc_bls_rjtdetail,
          {"Reason Explanation", "fc.bls_rjtdetail", FT_UINT8, BASE_HEX,
           VALS (fc_bls_barjt_det_val), 0x0, NULL, HFILL}},
        { &hf_fc_bls_vendor,
          {"Vendor Unique Reason", "fc.bls_vnduniq", FT_UINT8, BASE_HEX, NULL,
           0x0, NULL, HFILL}},
        { &hf_fc_fctl_exchange_responder,
          {"ExgRpd", "fc.fctl.exchange_responder", FT_BOOLEAN, 24, TFS(&tfs_fc_fctl_exchange_responder),
           FC_FCTL_EXCHANGE_RESPONDER, "Exchange Responder?", HFILL}},
        { &hf_fc_fctl_seq_recipient,
          {"SeqRec", "fc.fctl.seq_recipient", FT_BOOLEAN, 24, TFS(&tfs_fc_fctl_seq_recipient),
           FC_FCTL_SEQ_RECIPIENT, "Seq Recipient?", HFILL}},
        { &hf_fc_fctl_exchange_first,
          {"ExgFst", "fc.fctl.exchange_first", FT_BOOLEAN, 24, TFS(&tfs_fc_fctl_exchange_first),
           FC_FCTL_EXCHANGE_FIRST, "First Exchange?", HFILL}},
        { &hf_fc_fctl_exchange_last,
          {"ExgLst", "fc.fctl.exchange_last", FT_BOOLEAN, 24, TFS(&tfs_fc_fctl_exchange_last),
           FC_FCTL_EXCHANGE_LAST, "Last Exchange?", HFILL}},
        { &hf_fc_fctl_seq_last,
          {"SeqLst", "fc.fctl.seq_last", FT_BOOLEAN, 24, TFS(&tfs_fc_fctl_seq_last),
           FC_FCTL_SEQ_LAST, "Last Sequence?", HFILL}},
        { &hf_fc_fctl_priority,
          {"Pri", "fc.fctl.priority", FT_BOOLEAN, 24, TFS(&tfs_fc_fctl_priority),
           FC_FCTL_PRIORITY, "Priority", HFILL}},
        { &hf_fc_fctl_transfer_seq_initiative,
          {"TSI", "fc.fctl.transfer_seq_initiative", FT_BOOLEAN, 24, TFS(&tfs_fc_fctl_transfer_seq_initiative),
           FC_FCTL_TRANSFER_SEQ_INITIATIVE, "Transfer Seq Initiative", HFILL}},
        { &hf_fc_fctl_rexmitted_seq,
          {"RetSeq", "fc.fctl.rexmitted_seq", FT_BOOLEAN, 24, TFS(&tfs_fc_fctl_rexmitted_seq),
           FC_FCTL_REXMITTED_SEQ, "Retransmitted Sequence", HFILL}},
        { &hf_fc_fctl_rel_offset,
          {"RelOff", "fc.fctl.rel_offset", FT_BOOLEAN, 24, TFS(&tfs_fc_fctl_rel_offset),
           FC_FCTL_REL_OFFSET, "rel offset", HFILL}},
        { &hf_fc_fctl_last_data_frame,
          {"LDF", "fc.fctl.last_data_frame", FT_UINT24, BASE_HEX, VALS(last_data_frame_vals),
           FC_FCTL_LAST_DATA_FRAME_MASK, "Last Data Frame?", HFILL}},
        { &hf_fc_fctl_ack_0_1,
          {"A01", "fc.fctl.ack_0_1", FT_UINT24, BASE_HEX, VALS(ack_0_1_vals),
           FC_FCTL_ACK_0_1_MASK, "Ack 0/1 value", HFILL}},
        { &hf_fc_fctl_abts_ack,
          {"AA", "fc.fctl.abts_ack", FT_UINT24, BASE_HEX, VALS(abts_ack_vals),
           FC_FCTL_ABTS_MASK, "ABTS ACK values", HFILL}},
#if 0
        { &hf_fc_fctl_abts_not_ack,
          {"AnA", "fc.fctl.abts_not_ack", FT_UINT24, BASE_HEX, VALS(abts_not_ack_vals),
           FC_FCTL_ABTS_MASK, "ABTS not ACK vals", HFILL}},
#endif
        { &hf_fc_exchange_first_frame,
          { "Exchange First In", "fc.exchange_first_frame", FT_FRAMENUM, BASE_NONE, NULL,
           0, "The first frame of this exchange is in this frame", HFILL }},
        { &hf_fc_exchange_last_frame,
          { "Exchange Last In", "fc.exchange_last_frame", FT_FRAMENUM, BASE_NONE, NULL,
           0, "The last frame of this exchange is in this frame", HFILL }},
        { &hf_fc_time,
          { "Time from Exchange First", "fc.time", FT_RELATIVE_TIME, BASE_NONE, NULL,
           0, "Time since the first frame of the Exchange", HFILL }},
        { &hf_fc_relative_offset,
          {"Relative Offset", "fc.relative_offset", FT_UINT32, BASE_DEC, NULL,
           0, "Relative offset of data", HFILL}},
        { &hf_fc_vft,
          {"VFT Header", "fc.vft", FT_UINT16, BASE_DEC, NULL,
           0, NULL, HFILL}},
        { &hf_fc_vft_rctl,
          {"R_CTL", "fc.vft.rctl", FT_UINT8, BASE_HEX, NULL,
           0, NULL, HFILL}},
        { &hf_fc_vft_ver,
          {"Version", "fc.vft.ver", FT_UINT8, BASE_DEC, NULL,
           0, "Version of VFT header", HFILL}},
        { &hf_fc_vft_type,
          {"Type", "fc.vft.type", FT_UINT8, BASE_DEC, NULL,
           0, "Type of tagged frame", HFILL}},
        { &hf_fc_vft_pri,
          {"Priority", "fc.vft.type", FT_UINT8, BASE_DEC, NULL,
           0, "QoS Priority", HFILL}},
        { &hf_fc_vft_vf_id,
          {"VF_ID", "fc.vft.vf_id", FT_UINT16, BASE_DEC, NULL,
           0, "Virtual Fabric ID", HFILL}},
        { &hf_fc_vft_hop_ct,
          {"HopCT", "fc.vft.hop_ct", FT_UINT8, BASE_DEC, NULL,
           0, "Hop Count", HFILL}},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_fc,
        &ett_fcbls,
        &ett_fc_vft,
        &ett_fctl
    };

    static ei_register_info ei[] = {
        { &ei_fccrc, { "fc.crc.bad", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
    };

    module_t *fc_module;
    expert_module_t* expert_fc;

    /* FC SOF */

    static hf_register_info sof_hf[] = {
        { &hf_fcsof,
          { "SOF", "fc.sof", FT_UINT32, BASE_HEX, VALS(fc_sof_vals), 0,
            NULL, HFILL }},
        { &hf_fceof,
          { "EOF", "fc.eof", FT_UINT32, BASE_HEX, VALS(fc_eof_vals), 0,
            NULL, HFILL }},
        { &hf_fccrc,
          { "CRC", "fc.crc", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
    };

    static gint *sof_ett[] = {
        &ett_fcsof,
        &ett_fceof,
        &ett_fccrc
    };


    /* Register the protocol name and description */
    proto_fc = proto_register_protocol ("Fibre Channel", "FC", "fc");
    fc_handle = new_register_dissector ("fc", dissect_fc, proto_fc);
    new_register_dissector ("fc_ifcp", dissect_fc_ifcp, proto_fc);
    fc_tap = register_tap("fc");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_fc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_fc = expert_register_protocol(proto_fc);
    expert_register_field_array(expert_fc, ei, array_length(ei));

    /* subdissectors called through this table will find the fchdr structure
     * through data parameter of dissector
     */
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

    register_init_routine (fc_exchange_init_protocol);


    /* Register FC SOF/EOF */
    proto_fcsof = proto_register_protocol("Fibre Channel Delimiters", "FCSoF", "fcsof");

    proto_register_field_array(proto_fcsof, sof_hf, array_length(sof_hf));
    proto_register_subtree_array(sof_ett, array_length(sof_ett));

    fcsof_handle = register_dissector("fcsof", dissect_fcsof, proto_fcsof);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_fc (void)
{
    dissector_add_uint("wtap_encap", WTAP_ENCAP_FIBRE_CHANNEL_FC2, fc_handle);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS, fcsof_handle);

    data_handle = find_dissector("data");
}
