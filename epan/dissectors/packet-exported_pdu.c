/* packet-exported_pdu.c
 * Routines for exported_pdu dissection
 * Copyright 2013, Anders Broman <anders-broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <epan/to_str.h>
#include <epan/address_types.h>
#include <epan/exported_pdu.h>
#include <epan/expert.h>
#include "packet-mtp3.h"
#include "packet-dvbci.h"
#include "packet-tcp.h"

void proto_register_exported_pdu(void);
void proto_reg_handoff_exported_pdu(void);

static int hf_ip_addr;
static int hf_ip_dst;
static int hf_ip_src;
static int hf_ipv6_addr;
static int hf_ipv6_dst;
static int hf_ipv6_src;

static int proto_exported_pdu;
static int hf_exported_pdu_tag;
static int hf_exported_pdu_tag_len;
static int hf_exported_pdu_unknown_tag_val;
static int hf_exported_pdu_prot_name;
static int hf_exported_pdu_heur_prot_name;
static int hf_exported_pdu_dis_table_name;
static int hf_exported_pdu_p2p_dir;
static int hf_exported_pdu_dissector_data;
static int hf_exported_pdu_ddata_version;
static int hf_exported_pdu_ddata_seq;
static int hf_exported_pdu_ddata_nxtseq;
static int hf_exported_pdu_ddata_lastackseq;
static int hf_exported_pdu_ddata_is_reassembled;
static int hf_exported_pdu_ddata_flags;
static int hf_exported_pdu_ddata_urgent_pointer;
static int hf_exported_pdu_ipv4_src;
static int hf_exported_pdu_ipv4_dst;
static int hf_exported_pdu_ipv6_src;
static int hf_exported_pdu_ipv6_dst;
static int hf_exported_pdu_port_type;
static int hf_exported_pdu_src_port;
static int hf_exported_pdu_dst_port;
/** static int hf_exported_pdu_sctp_ppid; **/
static int hf_exported_pdu_ss7_opc;
static int hf_exported_pdu_ss7_dpc;
static int hf_exported_pdu_orig_fno;
static int hf_exported_pdu_dvbci_evt;
static int hf_exported_pdu_exported_pdu;
static int hf_exported_pdu_dis_table_val;
static int hf_exported_pdu_col_proto_str;
static int hf_exported_pdu_col_info_str;

/* Initialize the subtree pointers */
static gint ett_exported_pdu;
static gint ett_exported_pdu_tag;

static int ss7pc_address_type = -1;

static dissector_handle_t exported_pdu_handle;

static expert_field ei_exported_pdu_unsupported_version;
static expert_field ei_exported_pdu_unknown_tag;

static const gchar *user_data_pdu = "data";

#define EXPORTED_PDU_NEXT_DISSECTOR_STR      0
#define EXPORTED_PDU_NEXT_HEUR_DISSECTOR_STR 1
#define EXPORTED_PDU_NEXT_DIS_TABLE_STR      2

static const value_string exported_pdu_tag_vals[] = {
   { EXP_PDU_TAG_END_OF_OPT,       "End-of-options" },
/* 1 - 9 reserved */
   { EXP_PDU_TAG_OPTIONS_LENGTH,        "Total length of the options excluding this TLV" },
   { EXP_PDU_TAG_LINKTYPE,              "Linktype value" },
   { EXP_PDU_TAG_DISSECTOR_NAME,        "PDU content dissector name" },
   { EXP_PDU_TAG_HEUR_DISSECTOR_NAME,   "PDU content heuristic dissector name" },
   { EXP_PDU_TAG_DISSECTOR_TABLE_NAME,  "PDU content dissector table name" },
    /* Add protocol type related tags here */
/* 14 - 19 reserved */
   { EXP_PDU_TAG_IPV4_SRC,              "IPv4 Source Address" },
   { EXP_PDU_TAG_IPV4_DST,              "IPv4 Destination Address" },
   { EXP_PDU_TAG_IPV6_SRC,              "IPv6 Source Address" },
   { EXP_PDU_TAG_IPV6_DST,              "IPv6 Destination Address" },

   { EXP_PDU_TAG_PORT_TYPE,             "Port Type" },
   { EXP_PDU_TAG_SRC_PORT,              "Source Port" },
   { EXP_PDU_TAG_DST_PORT,              "Destination Port" },

   { EXP_PDU_TAG_SS7_OPC,               "SS7 OPC" },
   { EXP_PDU_TAG_SS7_DPC,               "SS7 DPC" },

   { EXP_PDU_TAG_ORIG_FNO,              "Original Frame number" },

   { EXP_PDU_TAG_DVBCI_EVT,             "DVB-CI event" },
   { EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL,  "Dissector table value" },
   { EXP_PDU_TAG_COL_PROT_TEXT,         "Column Protocol String" },
   { EXP_PDU_TAG_TCP_INFO_DATA,         "TCP Dissector Data" },
   { EXP_PDU_TAG_P2P_DIRECTION,         "P2P direction" },
   { EXP_PDU_TAG_COL_INFO_TEXT,         "Column Information String" },
   { EXP_PDU_TAG_USER_DATA_PDU,         "User Data PDU" },

   { 0,        NULL   }
};

static const value_string exported_pdu_port_type_vals[] = {
   { EXP_PDU_PT_NONE,     "NONE" },
   { EXP_PDU_PT_SCTP,     "SCTP" },
   { EXP_PDU_PT_TCP,      "TCP" },
   { EXP_PDU_PT_UDP,      "UDP" },
   { EXP_PDU_PT_DCCP,     "DCCP" },
   { EXP_PDU_PT_IPX,      "IPX" },
   { EXP_PDU_PT_NCP,      "NCP" },
   { EXP_PDU_PT_EXCHG,    "FC EXCHG" },
   { EXP_PDU_PT_DDP,      "DDP" },
   { EXP_PDU_PT_SBCCS,    "FICON SBCCS" },
   { EXP_PDU_PT_IDP,      "IDP" },
   { EXP_PDU_PT_TIPC,     "TIPC" },
   { EXP_PDU_PT_USB,      "USB" },
   { EXP_PDU_PT_I2C,      "I2C" },
   { EXP_PDU_PT_IBQP,     "IBQP" },
   { EXP_PDU_PT_BLUETOOTH,"BLUETOOTH" },
   { EXP_PDU_PT_TDMOP,    "TDMOP" },
   { EXP_PDU_PT_IWARP_MPA,"IWARP_MPA" },

   { 0,        NULL   }
};

static const value_string exported_pdu_p2p_dir_vals[] = {
    { P2P_DIR_SENT, "Sent" },
    { P2P_DIR_RECV, "Received" },
    { P2P_DIR_UNKNOWN, "Unknown" },
    { 0, NULL }
};

static port_type exp_pdu_port_type_to_ws_port_type(guint type)
{
    switch (type)
    {
    case EXP_PDU_PT_NONE:
        return PT_NONE;
    case EXP_PDU_PT_SCTP:
        return PT_SCTP;
    case EXP_PDU_PT_TCP:
        return PT_TCP;
    case EXP_PDU_PT_UDP:
        return PT_UDP;
    case EXP_PDU_PT_DCCP:
        return PT_DCCP;
    case EXP_PDU_PT_IPX:
        return PT_IPX;
    case EXP_PDU_PT_DDP:
        return PT_DDP;
    case EXP_PDU_PT_IDP:
        return PT_IDP;
    case EXP_PDU_PT_USB:
        return PT_USB;
    case EXP_PDU_PT_I2C:
        return PT_I2C;
    case EXP_PDU_PT_IBQP:
        return PT_IBQP;
    case EXP_PDU_PT_BLUETOOTH:
        return PT_BLUETOOTH;
    case EXP_PDU_PT_EXCHG:
    case EXP_PDU_PT_TIPC:
    case EXP_PDU_PT_TDMOP:
    case EXP_PDU_PT_NCP:
    case EXP_PDU_PT_SBCCS:
        //no longer supported
        break;
    }

    DISSECTOR_ASSERT(FALSE);
    return PT_NONE;
}

/* Code to actually dissect the packets */
static int
dissect_exported_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *exported_pdu_ti, *ti, *item;
    proto_tree *exported_pdu_tree, *tag_tree;
    tvbuff_t * payload_tvb = NULL;
    int offset = 0;
    guint32 tag;
    int tag_len;
    int next_proto_type = -1;
    const guint8 *proto_name = NULL;
    const guint8 *dissector_table = NULL;
    const guint8 *col_proto_str = NULL;
    const guint8* col_info_str = NULL;
    dissector_handle_t proto_handle;
    mtp3_addr_pc_t *mtp3_addr;
    guint32 pdu_port_type;
    guint32 dvb_ci_dir;
    guint32 dissector_table_val=0;
    dissector_table_t dis_tbl;
    void* dissector_data = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Exported PDU");

    /* create display subtree for the protocol */
    exported_pdu_ti = proto_tree_add_item(tree, proto_exported_pdu, tvb, offset, -1, ENC_NA);
    exported_pdu_tree = proto_item_add_subtree(exported_pdu_ti, ett_exported_pdu);

    do {
        ti = proto_tree_add_item_ret_uint(exported_pdu_tree, hf_exported_pdu_tag, tvb, offset, 2, ENC_BIG_ENDIAN, &tag);
        offset+=2;
        tag_tree = proto_item_add_subtree(ti, ett_exported_pdu_tag);
        proto_tree_add_item(tag_tree, hf_exported_pdu_tag_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        tag_len = tvb_get_ntohs(tvb, offset);
        proto_item_set_len(ti, 4 + tag_len);
        offset+=2;

        switch(tag) {
            case EXP_PDU_TAG_DISSECTOR_NAME:
                next_proto_type = EXPORTED_PDU_NEXT_DISSECTOR_STR;
                proto_tree_add_item_ret_string(tag_tree, hf_exported_pdu_prot_name, tvb, offset, tag_len, ENC_UTF_8|ENC_NA, pinfo->pool, &proto_name);
                break;
            case EXP_PDU_TAG_HEUR_DISSECTOR_NAME:
                next_proto_type = EXPORTED_PDU_NEXT_HEUR_DISSECTOR_STR;
                proto_tree_add_item_ret_string(tag_tree, hf_exported_pdu_heur_prot_name, tvb, offset, tag_len, ENC_UTF_8|ENC_NA, pinfo->pool, &proto_name);
                break;
            case EXP_PDU_TAG_DISSECTOR_TABLE_NAME:
                next_proto_type = EXPORTED_PDU_NEXT_DIS_TABLE_STR;
                proto_tree_add_item_ret_string(tag_tree, hf_exported_pdu_dis_table_name, tvb, offset, tag_len, ENC_UTF_8 | ENC_NA, pinfo->pool, &dissector_table);
                break;
            case EXP_PDU_TAG_IPV4_SRC:
                proto_tree_add_item(tag_tree, hf_exported_pdu_ipv4_src, tvb, offset, 4, ENC_BIG_ENDIAN);
                /* You can filter on IP by right clicking the Source/Destination columns make that work by filling the IP hf:s*/
                item = proto_tree_add_item(tag_tree, hf_ip_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_item_set_hidden(item);
                item = proto_tree_add_item(tag_tree, hf_ip_src, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_item_set_hidden(item);

                set_address_tvb(&pinfo->net_src, AT_IPv4, 4, tvb, offset);
                copy_address_shallow(&pinfo->src, &pinfo->net_src);
                break;
            case EXP_PDU_TAG_IPV4_DST:
                proto_tree_add_item(tag_tree, hf_exported_pdu_ipv4_dst, tvb, offset, 4, ENC_BIG_ENDIAN);
                /* You can filter on IP by right clicking the Source/Destination columns make that work by filling the IP hf:s*/
                item = proto_tree_add_item(tag_tree, hf_ip_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_item_set_hidden(item);
                item = proto_tree_add_item(tag_tree, hf_ip_dst, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_item_set_hidden(item);
                set_address_tvb(&pinfo->net_dst, AT_IPv4, 4, tvb, offset);
                copy_address_shallow(&pinfo->dst, &pinfo->net_dst);
                break;
            case EXP_PDU_TAG_IPV6_SRC:
                proto_tree_add_item(tag_tree, hf_exported_pdu_ipv6_src, tvb, offset, 16, ENC_NA);
                /* You can filter on IP by right clicking the Source/Destination columns make that work by filling the IP hf:s*/
                item = proto_tree_add_item(tag_tree, hf_ipv6_addr, tvb, offset, 16, ENC_BIG_ENDIAN);
                proto_item_set_hidden(item);
                item = proto_tree_add_item(tag_tree, hf_ipv6_src, tvb, offset, 16, ENC_BIG_ENDIAN);
                proto_item_set_hidden(item);
                set_address_tvb(&pinfo->net_src, AT_IPv6, 16, tvb, offset);
                copy_address_shallow(&pinfo->src, &pinfo->net_src);
                break;
            case EXP_PDU_TAG_IPV6_DST:
                proto_tree_add_item(tag_tree, hf_exported_pdu_ipv6_dst, tvb, offset, 16, ENC_NA);
                /* You can filter on IP by right clicking the Source/Destination columns make that work by filling the IP hf:s*/
                item = proto_tree_add_item(tag_tree, hf_ipv6_addr, tvb, offset, 16, ENC_BIG_ENDIAN);
                proto_item_set_hidden(item);
                item = proto_tree_add_item(tag_tree, hf_ipv6_dst, tvb, offset, 16, ENC_BIG_ENDIAN);
                proto_item_set_hidden(item);
                set_address_tvb(&pinfo->net_dst, AT_IPv6, 16, tvb, offset);
                copy_address_shallow(&pinfo->dst, &pinfo->net_dst);
                break;
            case EXP_PDU_TAG_PORT_TYPE:
                proto_tree_add_item_ret_uint(tag_tree, hf_exported_pdu_port_type, tvb, offset, 4, ENC_BIG_ENDIAN, &pdu_port_type);
                pinfo->ptype = exp_pdu_port_type_to_ws_port_type(pdu_port_type);
                break;
            case EXP_PDU_TAG_SRC_PORT:
                proto_tree_add_item_ret_uint(tag_tree, hf_exported_pdu_src_port, tvb, offset, 4, ENC_BIG_ENDIAN, &pinfo->srcport);
                break;
            case EXP_PDU_TAG_DST_PORT:
                proto_tree_add_item_ret_uint(tag_tree, hf_exported_pdu_dst_port, tvb, offset, 4, ENC_BIG_ENDIAN, &pinfo->destport);
                break;
            case EXP_PDU_TAG_SS7_OPC:
                proto_tree_add_item(tag_tree, hf_exported_pdu_ss7_opc, tvb, offset, 4, ENC_BIG_ENDIAN);
                mtp3_addr = wmem_new0(pinfo->pool, mtp3_addr_pc_t);
                mtp3_addr->pc = tvb_get_ntohl(tvb, offset);
                mtp3_addr->type = (Standard_Type)tvb_get_ntohs(tvb, offset+4);
                mtp3_addr->ni = tvb_get_guint8(tvb, offset+6);
                set_address(&pinfo->src, ss7pc_address_type, sizeof(mtp3_addr_pc_t), (guint8 *) mtp3_addr);
                break;
            case EXP_PDU_TAG_SS7_DPC:
                proto_tree_add_item(tag_tree, hf_exported_pdu_ss7_dpc, tvb, offset, 4, ENC_BIG_ENDIAN);
                mtp3_addr = wmem_new0(pinfo->pool, mtp3_addr_pc_t);
                mtp3_addr->pc = tvb_get_ntohl(tvb, offset);
                mtp3_addr->type = (Standard_Type)tvb_get_ntohs(tvb, offset+4);
                mtp3_addr->ni = tvb_get_guint8(tvb, offset+6);
                set_address(&pinfo->dst, ss7pc_address_type, sizeof(mtp3_addr_pc_t), (guint8 *) mtp3_addr);
                break;
            case EXP_PDU_TAG_ORIG_FNO:
                proto_tree_add_item(tag_tree, hf_exported_pdu_orig_fno, tvb, offset, 4, ENC_BIG_ENDIAN);
                break;
            case EXP_PDU_TAG_DVBCI_EVT:
                proto_tree_add_item_ret_uint(tag_tree, hf_exported_pdu_dvbci_evt,
                        tvb, offset, 1, ENC_BIG_ENDIAN, &dvb_ci_dir);
                dvbci_set_addrs((guint8)dvb_ci_dir, pinfo);
                break;
            case EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL:
                proto_tree_add_item_ret_uint(tag_tree, hf_exported_pdu_dis_table_val, tvb, offset, 4, ENC_BIG_ENDIAN, &dissector_table_val);
                break;
            case EXP_PDU_TAG_COL_PROT_TEXT:
                proto_tree_add_item_ret_string(tag_tree, hf_exported_pdu_col_proto_str, tvb, offset, tag_len, ENC_UTF_8 | ENC_NA, pinfo->pool, &col_proto_str);
                break;
            case EXP_PDU_TAG_TCP_INFO_DATA:
                {
                struct tcpinfo* tcpdata = wmem_new0(pinfo->pool, struct tcpinfo);
                guint32 u32;

                item = proto_tree_add_item(tag_tree, hf_exported_pdu_dissector_data, tvb, offset, tag_len, ENC_NA);

                proto_tree_add_item_ret_uint(tag_tree, hf_exported_pdu_ddata_version, tvb, offset, 2, ENC_BIG_ENDIAN, &u32);
                if (u32 == 1) {
                    /* Keep old bytes-only field, but hide it */
                    proto_item_set_hidden(item);

                    proto_tree_add_item_ret_uint(tag_tree, hf_exported_pdu_ddata_seq, tvb, offset+2, 4, ENC_BIG_ENDIAN, &tcpdata->seq);
                    proto_tree_add_item_ret_uint(tag_tree, hf_exported_pdu_ddata_nxtseq, tvb, offset+6, 4, ENC_BIG_ENDIAN, &tcpdata->nxtseq);
                    proto_tree_add_item_ret_uint(tag_tree, hf_exported_pdu_ddata_lastackseq, tvb, offset+10, 4, ENC_BIG_ENDIAN, &tcpdata->lastackseq);
                    proto_tree_add_item_ret_boolean(tag_tree, hf_exported_pdu_ddata_is_reassembled, tvb, offset+14, 1, ENC_BIG_ENDIAN, &tcpdata->is_reassembled);
                    proto_tree_add_item_ret_uint(tag_tree, hf_exported_pdu_ddata_flags, tvb, offset+15, 2, ENC_BIG_ENDIAN, &u32);
                    tcpdata->flags = u32;
                    proto_tree_add_item_ret_uint(tag_tree, hf_exported_pdu_ddata_urgent_pointer, tvb, offset+17, 2, ENC_BIG_ENDIAN, &u32);
                    tcpdata->urgent_pointer = u32;

                    dissector_data = tcpdata;
                }
                else { /* Only version 1 is currently supported */
                    proto_tree_add_expert(tag_tree, pinfo, &ei_exported_pdu_unsupported_version, tvb, offset, tag_len);
                }

                }
                break;
            case EXP_PDU_TAG_P2P_DIRECTION:
                pinfo->p2p_dir = tvb_get_ntohl(tvb, offset);
                proto_tree_add_item(tag_tree, hf_exported_pdu_p2p_dir, tvb, offset, 4, ENC_NA);
                break;
            case EXP_PDU_TAG_COL_INFO_TEXT:
                proto_tree_add_item_ret_string(tag_tree, hf_exported_pdu_col_info_str, tvb, offset, tag_len, ENC_UTF_8 | ENC_NA, pinfo->pool, &col_info_str);
                break;
            case EXP_PDU_TAG_USER_DATA_PDU:
                next_proto_type = EXPORTED_PDU_NEXT_DISSECTOR_STR;
                proto_name = user_data_pdu;
                break;
            case EXP_PDU_TAG_END_OF_OPT:
                break;
            default:
                proto_tree_add_item(tag_tree, hf_exported_pdu_unknown_tag_val, tvb, offset, tag_len, ENC_NA);
                proto_tree_add_expert(tag_tree, pinfo, &ei_exported_pdu_unknown_tag, tvb, offset, tag_len);
                break;
        }

        offset = offset + tag_len;

    } while(tag != 0);

    /* Limit the Exported PDU tree to the tags without payload. */
    proto_item_set_len(exported_pdu_ti, offset);

    payload_tvb = tvb_new_subset_remaining(tvb, offset);
    proto_tree_add_item(exported_pdu_tree, hf_exported_pdu_exported_pdu, payload_tvb, 0, -1, ENC_NA);

    switch(next_proto_type) {
        case EXPORTED_PDU_NEXT_DISSECTOR_STR:
            proto_handle = find_dissector(proto_name);
            if (proto_handle) {
                if (col_proto_str) {
                    col_add_str(pinfo->cinfo, COL_PROTOCOL, col_proto_str);
                } else {
                    col_clear(pinfo->cinfo, COL_PROTOCOL);
                }
                if (col_info_str) {
                    col_add_str(pinfo->cinfo, COL_INFO, col_info_str);
                }
                else {
                    col_clear(pinfo->cinfo, COL_INFO);
                }
                call_dissector_with_data(proto_handle, payload_tvb, pinfo, tree, dissector_data);
            }
            break;
        case EXPORTED_PDU_NEXT_HEUR_DISSECTOR_STR:
        {
            heur_dtbl_entry_t *heur_diss = find_heur_dissector_by_unique_short_name(proto_name);
            if (heur_diss) {
                if (col_proto_str) {
                    col_add_str(pinfo->cinfo, COL_PROTOCOL, col_proto_str);
                } else {
                    col_clear(pinfo->cinfo, COL_PROTOCOL);
                }
                if (col_info_str) {
                    col_add_str(pinfo->cinfo, COL_INFO, col_info_str);
                }
                else {
                    col_clear(pinfo->cinfo, COL_INFO);
                }
                call_heur_dissector_direct(heur_diss, payload_tvb, pinfo, tree, dissector_data);
            }
            break;
        }
        case EXPORTED_PDU_NEXT_DIS_TABLE_STR:
        {
            dis_tbl = find_dissector_table(dissector_table);
            if (dis_tbl) {
                if (col_proto_str) {
                    col_add_str(pinfo->cinfo, COL_PROTOCOL, col_proto_str);
                } else {
                    col_clear(pinfo->cinfo, COL_PROTOCOL);
                }
                if (col_info_str) {
                    col_add_str(pinfo->cinfo, COL_INFO, col_info_str);
                }
                else {
                    col_clear(pinfo->cinfo, COL_INFO);
                }
                dissector_try_uint_new(dis_tbl, dissector_table_val, payload_tvb, pinfo, tree, FALSE, dissector_data);
            }
        }
        default:
            break;
    }

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 */
void
proto_register_exported_pdu(void)
{
    /*module_t *exported_pdu_module;*/

    static hf_register_info hf[] = {
        { &hf_exported_pdu_tag,
            { "Tag", "exported_pdu.tag",
               FT_UINT16, BASE_DEC, VALS(exported_pdu_tag_vals), 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_tag_len,
            { "Length", "exported_pdu.tag_len",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_unknown_tag_val,
            { "Unknown tags value", "exported_pdu.unknown_tag.val",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_prot_name,
            { "Protocol Name", "exported_pdu.prot_name",
               FT_STRINGZPAD, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_heur_prot_name,
            { "Heuristic Protocol Name", "exported_pdu.heur_prot_name",
               FT_STRINGZPAD, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_dis_table_name,
            { "Dissector Table Name", "exported_pdu.dis_table_name",
               FT_STRINGZPAD, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_p2p_dir,
            { "P2P direction", "exported_pdu.p2p_dir",
               FT_INT32, BASE_DEC, VALS(exported_pdu_p2p_dir_vals), 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_dissector_data,
            { "TCP Dissector Data", "exported_pdu.tcp_dissector_data",
               FT_BYTES, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_ddata_version,
            { "TCP Dissector Data version", "exported_pdu.tcp_dissector_data.version",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_ddata_seq,
            { "Sequence number", "exported_pdu.tcp_dissector_data.seq",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_ddata_nxtseq,
            { "Next sequence number", "exported_pdu.tcp_dissector_data.nxtseq",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_ddata_lastackseq,
            { "Last acked sequence number", "exported_pdu.tcp_dissector_data.lastackseq",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_ddata_is_reassembled,
            { "Is reassembled", "exported_pdu.tcp_dissector_data.is_reassembled",
               FT_BOOLEAN, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_ddata_flags,
            { "Flags", "exported_pdu.tcp_dissector_data.flags",
               FT_UINT16, BASE_HEX, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_ddata_urgent_pointer,
            { "Urgent pointer", "exported_pdu.tcp_dissector_data.urgent_pointer",
               FT_UINT16, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_ipv4_src,
            { "IPv4 Src", "exported_pdu.ipv4_src",
               FT_IPv4, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_ipv4_dst,
            { "IPv4 Dst", "exported_pdu.ipv4_dst",
               FT_IPv4, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_ipv6_src,
            { "IPv6 Src", "exported_pdu.ipv6_src",
               FT_IPv6, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_ipv6_dst,
            { "IPv6 Dst", "exported_pdu.ipv6_dst",
               FT_IPv6, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_port_type,
            { "Port Type", "exported_pdu.port_type",
               FT_UINT32, BASE_DEC, VALS(exported_pdu_port_type_vals), 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_src_port,
            { "Src Port", "exported_pdu.src_port",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_dst_port,
            { "Dst Port", "exported_pdu.dst_port",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_ss7_opc,
            { "SS7 OPC", "exported_pdu.ss7_opc",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_ss7_dpc,
            { "SS7 DPC", "exported_pdu.ss7_dpc",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_orig_fno,
            { "Original Frame Number", "exported_pdu.orig_fno",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_dvbci_evt,
            { "DVB-CI event", "exported_pdu.dvb-ci.event",
               FT_UINT8, BASE_HEX, VALS(dvbci_event), 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_exported_pdu,
            { "Exported PDU data", "exported_pdu.exported_pdu",
               FT_BYTES, BASE_NONE|BASE_NO_DISPLAY_VALUE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_dis_table_val,
            { "Value to use when calling dissector table", "exported_pdu.dis_table_val",
               FT_UINT32, BASE_DEC, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_col_proto_str,
            { "Column protocol string", "exported_pdu.col_proto_str",
               FT_STRINGZPAD, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
        { &hf_exported_pdu_col_info_str,
            { "Column information string", "exported_pdu.col_info_str",
               FT_STRINGZPAD, BASE_NONE, NULL, 0,
              NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_exported_pdu,
        &ett_exported_pdu_tag
    };

    /* Setup expert information */
    static ei_register_info ei[] = {
        { &ei_exported_pdu_unsupported_version,
            { "exported_pdu.tcp_dissector_data.version.invalid",
                PI_PROTOCOL, PI_WARN, "Unsupported TCP Dissector Data version", EXPFILL }
        },
        { &ei_exported_pdu_unknown_tag,
            { "exported_pdu.tag.unknown",
                PI_PROTOCOL, PI_WARN, "Unrecognized tag", EXPFILL }
        },
    };
    expert_module_t *expert_exported_pdu;
    module_t *exported_pdu_module;

    /* Register the protocol name and description */
    proto_exported_pdu = proto_register_protocol("EXPORTED_PDU", "Exported PDU", "exported_pdu");

    expert_exported_pdu = expert_register_protocol(proto_exported_pdu);
    expert_register_field_array(expert_exported_pdu, ei, array_length(ei));

    exported_pdu_handle = register_dissector("exported_pdu", dissect_exported_pdu, proto_exported_pdu);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_exported_pdu, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register configuration preferences */
    exported_pdu_module = prefs_register_protocol(proto_exported_pdu, NULL);
    prefs_register_dissector_preference(exported_pdu_module, "user_data_pdu",
        "User Data PDU dissector", "The dissector to use for User Data PDU", &user_data_pdu);

    /* Register for tapping
     * The tap is registered here but it is to be used by dissectors that
     * want to export their PDUs, see packet-sip.c
     */
    register_export_pdu_tap(EXPORT_PDU_TAP_NAME_LAYER_3);
    register_export_pdu_tap(EXPORT_PDU_TAP_NAME_LAYER_4);
    register_export_pdu_tap(EXPORT_PDU_TAP_NAME_LAYER_7);
}

void
proto_reg_handoff_exported_pdu(void)
{
    static gboolean initialized = FALSE;

    if (!initialized) {
        dissector_add_uint("wtap_encap", WTAP_ENCAP_WIRESHARK_UPPER_PDU, exported_pdu_handle);
        initialized = TRUE;
    }

    ss7pc_address_type = address_type_get_by_name("AT_SS7PC");

    /* Get the hf id of some fields from the IP dissectors to be able to use them here*/
    hf_ip_addr    = proto_registrar_get_id_byname("ip.addr");
    hf_ip_dst     = proto_registrar_get_id_byname("ip.dst");
    hf_ip_src     = proto_registrar_get_id_byname("ip.src");
    hf_ipv6_addr  = proto_registrar_get_id_byname("ipv6.addr");
    hf_ipv6_dst   = proto_registrar_get_id_byname("ipv6.dst");
    hf_ipv6_src   = proto_registrar_get_id_byname("ipv6.src");
}


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
