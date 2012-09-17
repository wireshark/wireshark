/* packet-forces.c
 * RFC 5810
 * Routines for dissecting IETF ForCES protocol layer messages.Now support the following TML types:TCP+UDP,SCTP.
 * Copyright 2009, NDSC & Zhejiang Gongshang University,Fenggen Jia <fgjia@mail.zjgsu.edu.cn or fenggen.jia@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

static dissector_handle_t ip_handle;

/* Initialize the ForCES protocol and registered fields */
static int proto_forces = -1;

/*Main header*/
static int hf_forces_version = -1;
static int hf_forces_rsvd = -1;
static int hf_forces_messagetype = -1;
static int hf_forces_sid = -1;
static int hf_forces_did = -1;
static int hf_forces_correlator = -1;
static int hf_forces_length = -1;
/*Flags*/
static int hf_forces_flags= -1;
static int hf_forces_flags_ack= -1;
static int hf_forces_flags_pri= -1;
static int hf_forces_flags_rsrvd= -1;
static int hf_forces_flags_em= -1;
static int hf_forces_flags_at= -1;
static int hf_forces_flags_tp= -1;
static int hf_forces_flags_reserved = -1;

static int hf_forces_tlv_type = -1;
static int hf_forces_tlv_length = -1;

/*Initiation of LFBSelect TLV*/
static int hf_forces_lfbselect_tlv_type_lfb_classid = -1;
static int hf_forces_lfbselect_tlv_type_lfb_instanceid = -1;

/*Initiation of Operation TLV*/
static int hf_forces_lfbselect_tlv_type_operation_type = -1;
static int hf_forces_lfbselect_tlv_type_operation_length = -1;
static int hf_forces_lfbselect_tlv_type_operation_path_type = -1;
static int hf_forces_lfbselect_tlv_type_operation_path_length = -1;
static int hf_forces_lfbselect_tlv_type_operation_path_flags = -1;
static int hf_forces_lfbselect_tlv_type_operation_path_flags_selector = -1;
static int hf_forces_lfbselect_tlv_type_operation_path_flags_reserved = -1;
static int hf_forces_lfbselect_tlv_type_operation_path_IDcount = -1;
static int hf_forces_lfbselect_tlv_type_operation_path_IDs = -1;
static int hf_forces_lfbselect_tlv_type_operation_path_data = -1;

/*Initiation of Redirect TLV*/
static int hf_forces_redirect_tlv_meta_data_tlv_type = -1;
static int hf_forces_redirect_tlv_meta_data_tlv_length = -1;
static int hf_forces_redirect_tlv_meta_data_tlv_meta_data_ilv = -1;
static int hf_forces_redirect_tlv_meta_data_tlv_meta_data_ilv_id = -1;
static int hf_forces_redirect_tlv_meta_data_tlv_meta_data_ilv_length = -1;
static int hf_forces_redirect_tlv_redirect_data_tlv_type = -1;
static int hf_forces_redirect_tlv_redirect_data_tlv_length = -1;

/*Initiation of ASResult TLV*/
static int hf_forces_asresult_association_setup_result = -1;

/*Initiation of ASTreason TLV*/
static int hf_forces_astreason_tlv_teardown_reason = -1;

/*Main TLV may be unknown*/
static int hf_forces_unknown_tlv = -1;

/*Message Types */
#define AssociationSetup            0x01
#define AssociationTeardown         0x02
#define Config                      0x03
#define Query                       0x04
#define EventNotification           0x05
#define PacketRedirect              0x06
#define Heartbeat                   0x0F
#define AssociationSetupRepsonse    0x11
#define ConfigResponse              0x13
#define QueryResponse               0x14

/*TLV Types*/
#define Reserved            0x0000
#define REDIRECT_TLV        0x0001
#define ASResult_TLV        0x0010
#define ASTreason_TLV       0x0011
#define LFBselect_TLV       0x1000
#define PATH_DATA_TLV       0x0110
#define KEYINFO_TLV         0x0111
#define FULLDATA_TLV        0x0112
#define SPARSEDATA_TLV      0x0113
#define RESULT_TLV          0x0114
#define METADATA_TLV        0x0115
#define REDIRECTDATA_TLV    0x0116

/*Operation Type*/
#define Reserved            0x0000
#define SET                 0x0001
#define SET_PROP            0x0002
#define SET_RESPONSE        0x0003
#define SET_PROP_RESPONSE   0x0004
#define DEL                 0x0005
#define DEL_RESPONSE        0x0006
#define GET                 0x0007
#define GET_PROP            0x0008
#define GET_RESPONSE        0x0009
#define GET_PROP_RESPONSE   0x000A
#define REPORT              0x000B
#define COMMIT              0x000C
#define COMMIT_RESPONSE     0x000D
#define TRCOMP              0x000E

#define FLAG_SELECTOR       0x8000

#define ForCES_HEADER_LENGTH    24
#define TLV_TL_LENGTH            4 /*Type+length*/
#define MIN_IP_HEADER_LENGTH    20

/*For TCP+UDP TML. There are two bytes added to the ForCES PL message, not strictly combine to the ForCES protocol.
  For other type TMLs,no need to add these 2 bytes.*/
#define TCP_UDP_TML_FOCES_MESSAGE_OFFSET_TCP    2

/*TCP+UDP TML*/
static guint forces_alternate_tcp_port = 0;
static guint forces_alternate_udp_port = 0;
/*SCTP TML*/
static guint forces_alternate_sctp_high_prio_channel_port = 0;
static guint forces_alternate_sctp_med_prio_channel_port  = 0;
static guint forces_alternate_sctp_low_prio_channel_port  = 0;

/*Initialize the subtree pointers*/
static gint  ett_forces = -1;
static gint  ett_forces_main_header = -1;
static gint  ett_forces_flags = -1;
static gint  ett_forces_tlv = -1;
static gint  ett_forces_lfbselect_tlv_type = -1;

/*Operation TLV subtree*/
static gint  ett_forces_lfbselect_tlv_type_operation = -1;
static gint  ett_forces_lfbselect_tlv_type_operation_path = -1;
static gint  ett_forces_lfbselect_tlv_type_operation_path_data = -1;
static gint  ett_forces_lfbselect_tlv_type_operation_path_data_path = -1;
static gint  ett_forces_path_data_tlv = -1;
static gint  ett_forces_path_data_tlv_flags = -1;

/*Selector subtree*/
static gint  ett_forces_lfbselect_tlv_type_operation_path_selector = -1;

/*Redirect TLV subtree*/
static gint  ett_forces_redirect_tlv_type = -1;
static gint  ett_forces_redirect_tlv_meta_data_tlv = -1;
static gint  ett_forces_redirect_tlv_meta_data_tlv_meta_data_ilv = -1;
static gint  ett_forces_redirect_tlv_redirect_data_tlv = -1;

/*ASResult TLV subtree*/
static gint  ett_forces_asresult_tlv = -1;

/*ASReason subtree*/
static gint  ett_forces_astreason_tlv = -1;

/*Main_TLV unknown subtree*/
static gint  ett_forces_unknown_tlv = -1;

/*ACK values and the strings to be displayed*/
static const value_string main_header_flags_ack_vals[] = {
    { 0x0, "NoACK" },
    { 0x1, "SuccessACK" },
    { 0x2, "FailureACK" },
    { 0x3, "AlwaysACK" },
    { 0, NULL}
};

/*Execution mode(EM) values and the strings to be displayed*/
static const value_string main_header_flags_em_vals[] = {
    { 0x0, "Reserved" },
    { 0x1, "Execute-all-or-none" },
    { 0x2, "Execute-until-failure" },
    { 0x3, "Continue-execute-on-failure" },
    { 0, NULL}
};

/*Transaction Phase values and the strings to be displayed*/
static const value_string main_header_flags_tp_vals[] = {
    { 0x0, "SOT (Start of Transaction)" },
    { 0x1, "MOT (Middle of Transaction)" },
    { 0x2, "EOT (End of Transaction)" },
    { 0x3, "ABT (Abort)" },
    { 0, NULL}
};

/*Atomic Transaction(AT) values and the strings to be displayed*/
static const value_string main_header_flags_at_vals[] = {
    { 0x0, "Stand-alone Message"},
    { 0x1, "2PC Transaction Message"},
    { 0, NULL}
};

/*Association Setup Result*/
static const value_string association_setup_result_at_vals[] = {
    { 0x0, "success"},
    { 0x1, "FE ID invalid"},
    { 0x2, "permission denied"},
    { 0, NULL},
};

/*Teardown Reason*/
static const value_string teardown_reason_at_vals[] = {
    { 0x0,   "normal-teardown by administrator"},
    { 0x1,   "error - loss of heartbeats"},
    { 0x2,   "error - out of bandwidth"},
    { 0x3,   "error - out of memory"},
    { 0x4,   "error - application crash"},
    { 0x255, "error - other or unspecified"},
    { 0,     NULL},
};

static const value_string message_type_vals[] = {
    { AssociationSetup,         "AssociationSetup" },
    { AssociationTeardown,      "AssociationTeardown" },
    { Config,                   "Config" },
    { Query,                    "Query" },
    { EventNotification,        "EventNotification" },
    { PacketRedirect,           "PacketRedirect" },
    { Heartbeat,                "Heartbeat" },
    { AssociationSetupRepsonse, "AssociationSetupRepsonse" },
    { ConfigResponse,           "ConfigResponse" },
    { QueryResponse,            "QueryResponse" },
    { 0,                        NULL},
};

static const value_string tlv_type_vals[] = {
    { REDIRECT_TLV,     "REDIRECT-TLV" },
    { ASResult_TLV,     "ASResult-TLV" },
    { ASTreason_TLV,    "ASTreason-TLV" },
    { LFBselect_TLV,    "LFBselect-TLV" },
    { PATH_DATA_TLV,    "PATH DATA-TLV" },
    { KEYINFO_TLV,      "KEYINFO-TLV" },
    { FULLDATA_TLV,     "FULLDATA-TLV" },
    { SPARSEDATA_TLV,   "SPARSEDATA-TLV" },
    { RESULT_TLV,       "RESULT-TLV" },
    { METADATA_TLV,     "METADATA-TLV" },
    { REDIRECTDATA_TLV, "REDIRECTDATA-TLV" },
    { 0,                NULL},
};

static const value_string operation_type_vals[] = {
    { Reserved,          "Reserved" },
    { SET,               "SET" },
    { SET_PROP,          "SET-PROP" },
    { SET_RESPONSE,      "SET-RESPONSE" },
    { SET_PROP_RESPONSE, "SET-PROP-RESPONSE" },
    { DEL,               "DEL" },
    { DEL_RESPONSE,      "DEL-RESPONSE" },
    { GET,               "GET" },
    { GET_PROP,          "GET-PROP" },
    { GET_RESPONSE,      "GET-RESPONSE" },
    { GET_PROP_RESPONSE, "GET-PROP-RESPONSE" },
    { REPORT,            "REPORT" },
    { COMMIT,            "COMMIT" },
    { COMMIT_RESPONSE,   "COMMIT-RESPONSE" },
    { TRCOMP,            "TRCOMP" },
    { 0,                 NULL},
};

static void
dissect_path_data_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_item *ti, *flag_item;
    guint       length_TLV, IDcount, i;
    guint16     type, flag;
    proto_tree *tlv_tree, *path_data_tree, *flag_tree;

    while (tvb_reported_length_remaining(tvb, offset) >= TLV_TL_LENGTH)
    {
        ti = proto_tree_add_text(tree, tvb, offset, TLV_TL_LENGTH, "TLV");
        tlv_tree = proto_item_add_subtree(ti, ett_forces_path_data_tlv);

        type = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tlv_tree, hf_forces_lfbselect_tlv_type_operation_path_type,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        length_TLV = tvb_get_ntohs(tvb, offset+2);
        proto_tree_add_item(tlv_tree, hf_forces_lfbselect_tlv_type_operation_path_length,
                            tvb, offset+2, 2, ENC_BIG_ENDIAN);
        if (length_TLV < TLV_TL_LENGTH)
        {
            expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN, "Bogus TLV length: %u", length_TLV);
            break;
        }
        proto_item_set_len(ti, length_TLV);

        if (type == PATH_DATA_TLV)
        {
            ti = proto_tree_add_text(tree, tvb, offset+TLV_TL_LENGTH, length_TLV-TLV_TL_LENGTH, "Path Data TLV");
            path_data_tree = proto_item_add_subtree(ti, ett_forces_path_data_tlv);

            flag = tvb_get_ntohs(tvb, offset+TLV_TL_LENGTH);
            flag_item = proto_tree_add_item(path_data_tree, hf_forces_lfbselect_tlv_type_operation_path_flags,
                                tvb, offset+TLV_TL_LENGTH, 2, ENC_BIG_ENDIAN);
            flag_tree = proto_item_add_subtree(flag_item, ett_forces_path_data_tlv_flags);
            proto_tree_add_item(flag_tree, hf_forces_lfbselect_tlv_type_operation_path_flags_selector,
                                tvb, offset+TLV_TL_LENGTH, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree, hf_forces_lfbselect_tlv_type_operation_path_flags_reserved,
                                tvb, offset+TLV_TL_LENGTH, 2, ENC_BIG_ENDIAN);

            IDcount = tvb_get_ntohs(tvb, offset + TLV_TL_LENGTH + 2);
            proto_tree_add_item(path_data_tree, hf_forces_lfbselect_tlv_type_operation_path_IDcount,
                                tvb, offset+TLV_TL_LENGTH+2, 2, ENC_BIG_ENDIAN);

            for (i = 0; i < IDcount; i++)
                proto_tree_add_item(path_data_tree, hf_forces_lfbselect_tlv_type_operation_path_IDs,
                                    tvb, offset+TLV_TL_LENGTH+2+(i*4), 4, ENC_BIG_ENDIAN);
        }
        else
        {
            flag = 0;
            proto_tree_add_item(tree, hf_forces_lfbselect_tlv_type_operation_path_data,
                                tvb, offset+TLV_TL_LENGTH, length_TLV-TLV_TL_LENGTH, ENC_NA);
        }

        if ((flag & FLAG_SELECTOR) == 0)
            break;

        offset += length_TLV;
    }
}

static void
dissect_operation_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, gint length_count)
{
    proto_item *ti;
    proto_tree *oper_tree;
    guint       type, length;

    while (tvb_reported_length_remaining(tvb, offset) >= TLV_TL_LENGTH)
    {
        ti = proto_tree_add_text(tree, tvb, offset, length_count, "Operation TLV");
        oper_tree = proto_item_add_subtree(ti, ett_forces_lfbselect_tlv_type_operation);

        type = tvb_get_ntohs(tvb,offset);
        ti = proto_tree_add_item(oper_tree, hf_forces_lfbselect_tlv_type_operation_type,
                                 tvb, offset, 2, ENC_BIG_ENDIAN);
        if (match_strval(type, operation_type_vals) == NULL)
            expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN,
                "Bogus: ForCES Operation TLV (Type:0x%04x) is not supported", type);

        length = tvb_get_ntohs(tvb, offset+2);
        proto_tree_add_uint_format(oper_tree, hf_forces_lfbselect_tlv_type_operation_length,
                                   tvb, offset+2, 2, length, "Length: %u Bytes", length);

        dissect_path_data_tlv(tvb, pinfo, oper_tree, offset+TLV_TL_LENGTH);
        if (length == 0)
            break;
        offset += length;
    }
}

static void
dissect_lfbselecttlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, gint length_count)
{
    guint tlv_length;

    proto_tree_add_item(tree, hf_forces_lfbselect_tlv_type_lfb_classid,    tvb, offset,   4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_forces_lfbselect_tlv_type_lfb_instanceid, tvb, offset+4, 4, ENC_BIG_ENDIAN);

    offset += 8;
    while ((tvb_reported_length_remaining(tvb, offset) > TLV_TL_LENGTH) && (length_count > 12))
    {
        tlv_length = tvb_get_ntohs(tvb, offset+2);
        dissect_operation_tlv(tvb, pinfo, tree, offset, tlv_length);
        if (tlv_length == 0)
            break;
        offset += tlv_length;
    }
}

static void
dissect_redirecttlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    proto_tree *meta_data_tree, *meta_data_ilv_tree, *redirect_data_tree;
    gint        start_offset;
    gint        length_meta, length_ilv, length_redirect;
    proto_item *ti;
    address     src_addr     = pinfo->src,
                src_net_addr = pinfo->net_src,
                dst_addr     = pinfo->dst,
                dst_net_addr = pinfo->net_dst;

    ti = proto_tree_add_text(tree, tvb, offset, TLV_TL_LENGTH, "Meta Data TLV");
    meta_data_tree = proto_item_add_subtree(ti, ett_forces_redirect_tlv_meta_data_tlv);
    proto_tree_add_item(meta_data_tree, hf_forces_redirect_tlv_meta_data_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);

    length_meta = tvb_get_ntohs(tvb, offset+2);
    proto_tree_add_uint_format(meta_data_tree, hf_forces_redirect_tlv_meta_data_tlv_length, tvb, offset+2, 2,
                               length_meta, "Length: %u Bytes", length_meta);
    proto_item_set_len(ti, length_meta);

    start_offset = offset;
    while ((tvb_reported_length_remaining(tvb, offset) >= 8) && (start_offset+length_meta > offset))
    {
        ti = proto_tree_add_text(tree, tvb, offset, TLV_TL_LENGTH, "Meta Data ILV");
        meta_data_ilv_tree =  proto_item_add_subtree(ti, ett_forces_redirect_tlv_meta_data_tlv_meta_data_ilv);

        proto_tree_add_item(meta_data_ilv_tree, hf_forces_redirect_tlv_meta_data_tlv_meta_data_ilv_id,
                                   tvb, offset+8, 4, ENC_BIG_ENDIAN);
        length_ilv = tvb_get_ntohl(tvb, offset+12);
        proto_tree_add_uint_format(meta_data_ilv_tree, hf_forces_redirect_tlv_meta_data_tlv_meta_data_ilv_length,
                                   tvb,  offset+12, 4, length_ilv, "Length: %u Bytes", length_ilv);
        if (length_ilv > 0)
            proto_tree_add_item(meta_data_ilv_tree, hf_forces_redirect_tlv_meta_data_tlv_meta_data_ilv,
                                   tvb, offset+8, length_ilv, ENC_NA);

        proto_item_set_len(ti, length_ilv + 8);
        offset += length_ilv + 8;
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        ti = proto_tree_add_text(tree, tvb, offset, TLV_TL_LENGTH, "Redirect Data TLV");
        redirect_data_tree = proto_item_add_subtree(ti, ett_forces_redirect_tlv_redirect_data_tlv);

        proto_tree_add_item(redirect_data_tree, hf_forces_redirect_tlv_redirect_data_tlv_type,
                            tvb, offset, 2,  ENC_BIG_ENDIAN);
        length_redirect = tvb_get_ntohs(tvb, offset+2);
        proto_tree_add_uint_format(redirect_data_tree, hf_forces_redirect_tlv_redirect_data_tlv_length,
                            tvb, offset+2, 2, length_redirect, "Length: %u Bytes", length_redirect);

        if (tvb_reported_length_remaining(tvb, offset) < length_redirect)
        {
            expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN,
                "Bogus: Redirect Data TLV length (%u bytes) is wrong", length_redirect);
        }
        else if (length_redirect < TLV_TL_LENGTH + MIN_IP_HEADER_LENGTH)
        {
            expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN,
                "Bogus: Redirect Data TLV length (%u bytes) not big enough for IP layer", length_redirect);
        }
        else
        {
            tvbuff_t  *next_tvb;

            next_tvb = tvb_new_subset(tvb, offset+4, length_redirect-TLV_TL_LENGTH, length_redirect-TLV_TL_LENGTH);
            call_dissector(ip_handle, next_tvb, pinfo, redirect_data_tree);

            /* Restore IP info */
            memcpy(&(pinfo->src),     &src_addr,     sizeof(address));
            memcpy(&(pinfo->net_src), &src_net_addr, sizeof(address));
            memcpy(&(pinfo->dst),     &dst_addr,     sizeof(address));
            memcpy(&(pinfo->net_dst), &dst_net_addr, sizeof(address));
        }
    }
}

static void
dissect_forces(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti, *tlv_item;
    proto_tree *forces_tree, *forces_flags_tree;
    proto_tree *forces_main_header_tree, *forces_tlv_tree, *tlv_tree;
    gint        length_count;

    guint8      message_type;
    guint16     tlv_type;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ForCES");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_forces, tvb, 0, -1, ENC_NA);
    forces_tree = proto_item_add_subtree(ti, ett_forces);

    ti = proto_tree_add_text(forces_tree, tvb, 0, ForCES_HEADER_LENGTH, "Common Header");
    forces_main_header_tree = proto_item_add_subtree(ti, ett_forces_main_header);

    proto_tree_add_item(forces_main_header_tree, hf_forces_version, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(forces_main_header_tree, hf_forces_rsvd,    tvb, 0, 1, ENC_BIG_ENDIAN);

    message_type = tvb_get_guint8(tvb, offset+1);
    proto_tree_add_item( forces_main_header_tree, hf_forces_messagetype, tvb, offset+1, 1, ENC_BIG_ENDIAN);

    length_count = tvb_get_ntohs(tvb, offset+2) * 4;  /*multiply 4 DWORD*/
    ti = proto_tree_add_uint_format( forces_main_header_tree, hf_forces_length,
                                     tvb, offset+2, 2, length_count, "Length: %u Bytes", length_count);
    if (length_count != tvb_reported_length_remaining(tvb, offset))
        expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN,
            "Bogus: ForCES Header length (%u bytes) is wrong),should be (%u bytes)",
            length_count, tvb_reported_length_remaining(tvb, offset));
    if (length_count < 24)
        expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN,
            "Bogus: ForCES Header length (%u bytes) is less than 24bytes)", length_count);

    col_add_fstr(pinfo->cinfo, COL_INFO, "Message Type: %s, Total Length:  %u Bytes",
            val_to_str(message_type, message_type_vals, "Unknown messagetype 0x%x"), length_count);

    proto_tree_add_item( forces_main_header_tree, hf_forces_sid,        tvb, offset+4,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item( forces_main_header_tree, hf_forces_did,        tvb, offset+8,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item( forces_main_header_tree, hf_forces_correlator, tvb, offset+12, 8, ENC_BIG_ENDIAN);

    /*Add flags tree*/
    ti = proto_tree_add_item(forces_main_header_tree, hf_forces_flags, tvb, offset+20, 4, ENC_BIG_ENDIAN);
    forces_flags_tree = proto_item_add_subtree(ti, ett_forces_flags);

    proto_tree_add_item(forces_flags_tree, hf_forces_flags_ack,      tvb, offset+20, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(forces_flags_tree, hf_forces_flags_at,       tvb, offset+20, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(forces_flags_tree, hf_forces_flags_em,       tvb, offset+20, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(forces_flags_tree, hf_forces_flags_pri,      tvb, offset+20, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(forces_flags_tree, hf_forces_flags_reserved, tvb, offset+20, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(forces_flags_tree, hf_forces_flags_rsrvd,    tvb, offset+20, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(forces_flags_tree, hf_forces_flags_tp,       tvb, offset+20, 4, ENC_BIG_ENDIAN);

    offset += 24;
    while (tvb_reported_length_remaining(tvb, offset) >= TLV_TL_LENGTH)
    {
        ti = proto_tree_add_text(forces_tree, tvb, offset, TLV_TL_LENGTH, "TLV");
        forces_tlv_tree = proto_item_add_subtree(ti, ett_forces_tlv);

        tlv_type = tvb_get_ntohs(tvb, offset);
        tlv_item = proto_tree_add_item(forces_tlv_tree, hf_forces_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        length_count = tvb_get_ntohs(tvb, offset+2) * 4;
        proto_item_set_len(ti, length_count);
        ti = proto_tree_add_uint_format(forces_tlv_tree, hf_forces_tlv_length,
                                        tvb, offset+2, 2, length_count, "Length: %u Bytes", length_count);
        if (tvb_reported_length_remaining(tvb, offset) < length_count)
            expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN,
                "Bogus: Main TLV length (%u bytes) is wrong", length_count);

        if (length_count < TLV_TL_LENGTH)
        {
            expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN, "Bogus TLV length: %u", length_count);
            break;
        }

        offset       += TLV_TL_LENGTH;
        length_count -= TLV_TL_LENGTH;

        switch(tlv_type)
        {
        case LFBselect_TLV:
            ti = proto_tree_add_text(forces_tlv_tree, tvb, offset, length_count, "LFB select TLV");
            tlv_tree = proto_item_add_subtree(ti, ett_forces_lfbselect_tlv_type);
            dissect_lfbselecttlv(tvb, pinfo, tlv_tree, offset, length_count);
            break;

        case REDIRECT_TLV:
            ti = proto_tree_add_text(forces_tlv_tree, tvb, offset, length_count, "Redirect TLV");
            tlv_tree = proto_item_add_subtree(ti, ett_forces_redirect_tlv_type);
            dissect_redirecttlv(tvb, pinfo, tlv_tree, offset);
            break;

        case ASResult_TLV:
            ti = proto_tree_add_text(forces_tlv_tree, tvb, offset, length_count, "ASResult TLV");
            tlv_tree = proto_item_add_subtree(ti, ett_forces_asresult_tlv);
            proto_tree_add_item(tlv_tree, hf_forces_asresult_association_setup_result, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;

        case ASTreason_TLV:
            ti = proto_tree_add_text(forces_tlv_tree, tvb, offset, length_count, "ASTreason TLV");
            tlv_tree = proto_item_add_subtree(ti, ett_forces_astreason_tlv);
            proto_tree_add_item(tlv_tree, hf_forces_astreason_tlv_teardown_reason, tvb, offset, 4, ENC_BIG_ENDIAN);
            break;

        default:
            expert_add_info_format(pinfo, tlv_item, PI_PROTOCOL, PI_WARN,
                "Bogus: The Main_TLV type is unknown");
            ti = proto_tree_add_text(forces_tlv_tree, tvb, offset, length_count, "Unknown TLV");
            tlv_tree = proto_item_add_subtree(ti, ett_forces_unknown_tlv);
            proto_tree_add_item(tlv_tree, hf_forces_unknown_tlv, tvb, offset, length_count, ENC_NA);
            break;
        }

        offset += length_count;
    }
}

/* Code to actually dissect the TCP packets */
static void
dissect_forces_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_forces(tvb, pinfo, tree, TCP_UDP_TML_FOCES_MESSAGE_OFFSET_TCP);
}

/* Code to actually dissect the ForCES protocol layer packets,like UDP,SCTP and others */
static void
dissect_forces_not_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    dissect_forces(tvb, pinfo, tree, 0);
}

void proto_reg_handoff_forces(void);

void
proto_register_forces(void)
{
    module_t *forces_module;

    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_forces_version,
            { "Version", "forces.flags.version",
            FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_forces_rsvd,
            { "Rsvd", "forces.flags.rsvd",
            FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_forces_messagetype,
            { "Message Type", "forces.messagetype",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_length,
            { "Header Length", "forces.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_sid,
            { "Source ID", "forces.sid",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_did,
            { "Destination ID", "forces.did",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_correlator,
            { "Correlator", "forces.correlator",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_tlv_type,
            { "Type", "forces.tlv.type",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_tlv_length,
            { "Length", "forces.tlv.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        /*flags*/
        { &hf_forces_flags,
            { "Flags", "forces.Flags",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_flags_ack,
            { "ACK indicator", "forces.flags.ack",
            FT_UINT32, BASE_DEC, VALS(main_header_flags_ack_vals), 0xC0000000, NULL, HFILL }
        },
        { &hf_forces_flags_pri,
            { "Priority", "forces.flags.pri",
            FT_UINT32, BASE_DEC, NULL, 0x38000000, NULL, HFILL }
        },
        { &hf_forces_flags_rsrvd,
            { "Rsrvd", "forces.Flags",
            FT_UINT32, BASE_DEC,NULL, 0x07000000, NULL, HFILL }
        },
        { &hf_forces_flags_em,
            { "Execution mode", "forces.flags.em",
            FT_UINT32, BASE_DEC, VALS(main_header_flags_em_vals), 0x00C00000, NULL, HFILL }
        },
        { &hf_forces_flags_at,
            { "Atomic Transaction", "forces.flags.at",
            FT_UINT32, BASE_DEC, VALS(main_header_flags_at_vals), 0x00200000, NULL, HFILL }
        },
        { &hf_forces_flags_tp,
            { "Transaction phase", "forces.flags.tp",
            FT_UINT32, BASE_DEC, VALS(main_header_flags_tp_vals), 0x00180000, NULL, HFILL }
        },
        { &hf_forces_flags_reserved,
            { "Reserved", "forces.flags.reserved",
            FT_UINT32, BASE_DEC,NULL, 0x0007ffff, NULL, HFILL }
        },
        /*LFBSelectTLV*/
        { &hf_forces_lfbselect_tlv_type_lfb_classid,
            { "Class ID", "forces.lfbselect.tlv.type.lfb.classid",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_lfbselect_tlv_type_lfb_instanceid,
            { "Instance ID", "forces.fbselect.tlv.type.lfb.instanceid",
            FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        /*Operation TLV*/
        { &hf_forces_lfbselect_tlv_type_operation_type,
            { "Type", "forces.lfbselect.tlv.type.operation.type",
            FT_UINT16, BASE_DEC, VALS(operation_type_vals), 0x0, NULL, HFILL }
        },
        { &hf_forces_lfbselect_tlv_type_operation_length,
            { "Length", "forces.lfbselect.tlv.type.operation.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_lfbselect_tlv_type_operation_path_type,
            { "Type", "forces.lfbselect.tlv.type.operation.path.type",
            FT_UINT16, BASE_DEC, VALS(tlv_type_vals), 0x0, NULL, HFILL }
        },
        { &hf_forces_lfbselect_tlv_type_operation_path_length,
            { "Length", "forces.lfbselect.tlv.type.operation.path.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_lfbselect_tlv_type_operation_path_data,
            { "Data", "forces.lfbselect.tlv.type.operation.path.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_lfbselect_tlv_type_operation_path_flags,
            {"Path Data Flags", "forces.lfbselect.tlv.type.operation.path.data.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_lfbselect_tlv_type_operation_path_flags_selector,
            {"Selector", "forces.lfbselect.tlv.type.operation.path.data.flags.selector",
            FT_UINT16, BASE_HEX, NULL, 0x80, NULL, HFILL }
        },
        { &hf_forces_lfbselect_tlv_type_operation_path_flags_reserved,
            {"Reserved", "forces.lfbselect.tlv.type.operation.path.data.flags.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x7F, NULL, HFILL }
        },
        { &hf_forces_lfbselect_tlv_type_operation_path_IDcount,
            { "Path Data IDcount", "forces.lfbselect.tlv.type.operation.path.data.IDcount",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_lfbselect_tlv_type_operation_path_IDs,
            { "Path Data IDs", "forces.lfbselect.tlv.type.operation.path.data.IDs",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        /*Meta data TLV*/
        {&hf_forces_redirect_tlv_meta_data_tlv_type,
            { "Type", "forces.redirect.tlv.meta.data.tlv.type",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_redirect_tlv_meta_data_tlv_length,
            { "Length", "forces.redirect.tlv.meta.data.tlv.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_redirect_tlv_meta_data_tlv_meta_data_ilv,
            { "Meta Data ILV", "forces.redirect.tlv.meta.data.tlv.meta.data.ilv",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_redirect_tlv_meta_data_tlv_meta_data_ilv_id,
            { "ID", "forces.redirect.tlv.meta.data.tlv.meta.data.ilv.id",
            FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_redirect_tlv_meta_data_tlv_meta_data_ilv_length,
            { "Length", "forces.redirect.tlv.meta.data.tlv.meta.data.ilv.length",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_redirect_tlv_redirect_data_tlv_type,
            { "Type", "forces.redirect.tlv.redirect.data.tlv.type",
            FT_UINT16, BASE_DEC, VALS(tlv_type_vals), 0x0, NULL, HFILL }
        },
        { &hf_forces_redirect_tlv_redirect_data_tlv_length,
            { "Length", "forces.redirect.tlv.redirect.data.tlv.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_forces_asresult_association_setup_result,
            { "Association Setup Result", "forces.teardown.reason",
            FT_UINT32, BASE_DEC, VALS(association_setup_result_at_vals), 0x0, NULL, HFILL }
        },
        { &hf_forces_astreason_tlv_teardown_reason,
            { "AStreason TLV TearDonw Reason", "forces.astreason.tlv.teardonw.reason",
            FT_UINT32, BASE_DEC, VALS(teardown_reason_at_vals), 0x0, NULL, HFILL }
        },
        { &hf_forces_unknown_tlv,
            { "Data", "forces.unknown.tlv",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_forces,
        &ett_forces_main_header,
        &ett_forces_flags,
        &ett_forces_tlv,
        &ett_forces_lfbselect_tlv_type,
        &ett_forces_lfbselect_tlv_type_operation,
        &ett_forces_lfbselect_tlv_type_operation_path,
        &ett_forces_lfbselect_tlv_type_operation_path_data,
        &ett_forces_lfbselect_tlv_type_operation_path_data_path,
        &ett_forces_lfbselect_tlv_type_operation_path_selector,
        &ett_forces_path_data_tlv,
        &ett_forces_path_data_tlv_flags,
        &ett_forces_redirect_tlv_type,
        &ett_forces_redirect_tlv_meta_data_tlv,
        &ett_forces_redirect_tlv_redirect_data_tlv,
        &ett_forces_redirect_tlv_meta_data_tlv_meta_data_ilv,
        &ett_forces_asresult_tlv,
        &ett_forces_astreason_tlv,
        &ett_forces_unknown_tlv
    };

    /* Register the protocol name and description */
    proto_forces = proto_register_protocol("Forwarding and Control Element Separation Protocol", "ForCES", "forces");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_forces, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    forces_module = prefs_register_protocol(proto_forces,proto_reg_handoff_forces);

    prefs_register_uint_preference(forces_module, "tcp_alternate_port",
                                   "TCP port",
                                   "Decode packets on this TCP port as ForCES",
                                   10, &forces_alternate_tcp_port);

    prefs_register_uint_preference(forces_module, "udp_alternate_port",
                                   "UDP port",
                                   "Decode packets on this UDP port as ForCES",
                                   10, &forces_alternate_udp_port);

    prefs_register_uint_preference(forces_module, "sctp_high_prio_port",
                                   "SCTP High Priority channel port",
                                   "Decode packets on this sctp port as ForCES",
                                   10, &forces_alternate_sctp_high_prio_channel_port);

    prefs_register_uint_preference(forces_module, "sctp_med_prio_port",
                                   "SCTP Meidium Priority channel port",
                                   "Decode packets on this sctp port as ForCES",
                                   10, &forces_alternate_sctp_med_prio_channel_port);

    prefs_register_uint_preference(forces_module, "sctp_low_prio_port",
                                   "SCTP Low Priority channel port",
                                   "Decode packets on this sctp port as ForCES",
                                   10, &forces_alternate_sctp_low_prio_channel_port);
}

void
proto_reg_handoff_forces(void)
{
    static gboolean inited = FALSE;

    static guint alternate_tcp_port = 0; /* 3000 */
    static guint alternate_udp_port = 0;
    static guint alternate_sctp_high_prio_channel_port = 0; /* 6700 */
    static guint alternate_sctp_med_prio_channel_port  = 0;
    static guint alternate_sctp_low_prio_channel_port  = 0;

    static dissector_handle_t  forces_handle_tcp, forces_handle;

    if (!inited) {
        forces_handle_tcp = create_dissector_handle(dissect_forces_tcp,     proto_forces);
        forces_handle     = create_dissector_handle(dissect_forces_not_tcp, proto_forces);
        ip_handle = find_dissector("ip");
        inited = TRUE;
    }

    /* Register TCP port for dissection */
    if ((alternate_tcp_port != 0) && (alternate_tcp_port != forces_alternate_tcp_port))
        dissector_delete_uint("tcp.port", alternate_tcp_port, forces_handle_tcp);
    if ((forces_alternate_tcp_port != 0) && (alternate_tcp_port != forces_alternate_tcp_port))
        dissector_add_uint("tcp.port", forces_alternate_tcp_port, forces_handle_tcp);
    alternate_tcp_port = forces_alternate_tcp_port;

    /* Register UDP port for dissection */
    if ((alternate_udp_port != 0) && (alternate_udp_port != forces_alternate_udp_port))
        dissector_delete_uint("udp.port", alternate_udp_port, forces_handle);
    if ((forces_alternate_udp_port != 0) && (alternate_udp_port != forces_alternate_udp_port))
        dissector_add_uint("udp.port", forces_alternate_udp_port, forces_handle);
    alternate_udp_port = forces_alternate_udp_port;

    /* Register SCTP port for high priority dissection */
    if ((alternate_sctp_high_prio_channel_port != 0) &&
        (alternate_sctp_high_prio_channel_port != forces_alternate_sctp_high_prio_channel_port))
        dissector_delete_uint("sctp.port", alternate_sctp_high_prio_channel_port, forces_handle);
    if ((forces_alternate_sctp_high_prio_channel_port != 0) &&
        (alternate_sctp_high_prio_channel_port != forces_alternate_sctp_high_prio_channel_port))
        dissector_add_uint("sctp.port", forces_alternate_sctp_high_prio_channel_port, forces_handle);
    alternate_sctp_high_prio_channel_port = forces_alternate_sctp_high_prio_channel_port;

    /* Register SCTP port for medium priority dissection */
    if ((alternate_sctp_med_prio_channel_port != 0) &&
        (alternate_sctp_med_prio_channel_port != forces_alternate_sctp_med_prio_channel_port))
        dissector_delete_uint("udp.port", alternate_sctp_med_prio_channel_port, forces_handle);
    if ((forces_alternate_sctp_med_prio_channel_port != 0) &&
        (alternate_sctp_med_prio_channel_port != forces_alternate_sctp_med_prio_channel_port))
        dissector_add_uint("udp.port", forces_alternate_sctp_med_prio_channel_port, forces_handle);
    alternate_sctp_med_prio_channel_port = forces_alternate_sctp_med_prio_channel_port;

    /* Register SCTP port for low priority dissection */
    if ((alternate_sctp_low_prio_channel_port != 0) &&
        (alternate_sctp_low_prio_channel_port != forces_alternate_sctp_low_prio_channel_port))
        dissector_delete_uint("udp.port", alternate_sctp_low_prio_channel_port, forces_handle);
    if ((forces_alternate_sctp_low_prio_channel_port != 0) &&
        (alternate_sctp_low_prio_channel_port != forces_alternate_sctp_low_prio_channel_port))
        dissector_add_uint("udp.port", forces_alternate_sctp_low_prio_channel_port, forces_handle);
    alternate_sctp_low_prio_channel_port = forces_alternate_sctp_low_prio_channel_port;
}

/*
* Editor modelines - http://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* vi: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
