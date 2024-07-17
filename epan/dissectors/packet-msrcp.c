/* packet-msrcp.c
 * Routines for decoding Microsoft Cluster Route Control Protocol (MSRCP)
 * Copyright 2022, Will Aftring <william.aftring@outlook.com>
 *
 * SPDX-License-Identifier: MIT
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 */


#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/conversation.h>

void proto_register_msrcp(void);
void proto_reg_handoff_msrcp(void);

static dissector_handle_t msrcp_handle;

#define MSRCP_PORT 3343
#define MSRCP_REQUEST 0
#define MSRCP_RESPONSE 1
#define MSRCP_OFFSET_TYPE 6
#define MSRCP_OFFSET_SEQ 12


static const value_string packettypenames[] = {
    {0, "REQUEST" },
    {1, "RESPONSE" },
    {0, NULL}
};

static const value_string headertypenames[] = {
    {0, "MSRCP EXTENSION NONE",},
    {1, "MSRCP IPv4 Pair"},
    {2, "MSRCP IPv6 Pair"},
    {3, "MSRCP Signature"},
    {4, "MSRCP Maximum"},
    {0, NULL}
};

typedef struct _msrcp_conv_info_t {
    wmem_tree_t* pdus;
} msrcp_conv_info_t;

typedef struct _msrcp_transaction_t {
    uint32_t req_frame;
    uint32_t rep_frame;
    nstime_t req_time;
    uint32_t seq;
    bool matched;
} msrcp_transaction_t;

static int proto_msrcp;
static int hf_msrcp_id;
static int hf_msrcp_type;
static int hf_msrcp_vers;
static int hf_msrcp_reserved;
static int hf_msrcp_next_header;
static int hf_msrcp_len;
static int hf_msrcp_seq;
static int hf_msrcp_response_in;
static int hf_msrcp_response_to;
static int hf_msrcp_ext_header;
static int hf_msrcp_ext_next_header;
static int hf_msrcp_ext_len;
static int hf_msrcp_ext_res;

static int ett_msrcp;
static int ett_msrcp_nxt;

static expert_field ei_msrcp_no_resp;

// Handles for subparsing
static dissector_handle_t eth_handle;

static int
dissect_msrcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{

    /*
        Rough Packet layout:
        Identifier:         4 bytes
        Version:            1 byte
        Reserved:           1 byte
        Type:               2 bytes
        NextHeader:         2 bytes
        Total Length:       2 bytes
        SeqNum:             4 bytes
        ExtHeader:          40 bytes
            NextHeader:     2 bytes
            Length:         2 bytes
            Reserved:       4 bytes
            SrcAddr:        16 bytes
            DstAddr:        16 bytes
    */
    unsigned tree_offset = 0;

    proto_tree* msrcp_tree, * nxt_tree;
    proto_item* ti, * nxt_ti;
    tvbuff_t* next_tvb;
    uint32_t        seq;
    uint16_t        type;

    // variables for our expert analysis
    conversation_t* conv = NULL;
    msrcp_conv_info_t* msrcp_info = NULL;
    msrcp_transaction_t* msrcp_trans = NULL;
    wmem_tree_key_t  key[3];

    type = tvb_get_uint8(tvb, MSRCP_OFFSET_TYPE);
    seq = tvb_get_uint32(tvb, MSRCP_OFFSET_SEQ, ENC_LITTLE_ENDIAN);

    conv = find_or_create_conversation(pinfo);
    msrcp_info = (msrcp_conv_info_t*)conversation_get_proto_data(conv, proto_msrcp);
    if (!msrcp_info)
    {
        msrcp_info = wmem_new(wmem_file_scope(), msrcp_conv_info_t);
        msrcp_info->pdus = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conv, proto_msrcp, msrcp_info);
    }

    key[0].length = 1;
    key[0].key = &seq;
    key[1].length = 1;
    key[1].key = &pinfo->num;
    key[2].length = 0;
    key[2].key = NULL;
    if ((type == MSRCP_REQUEST) || (type == MSRCP_RESPONSE))
    {
        if (!pinfo->fd->visited)
        {
            if (type == MSRCP_REQUEST)
            {
                msrcp_trans = wmem_new(wmem_file_scope(), msrcp_transaction_t);
                msrcp_trans->req_frame = pinfo->num;
                msrcp_trans->rep_frame = 0;
                msrcp_trans->req_time = pinfo->abs_ts;
                msrcp_trans->seq = seq;
                msrcp_trans->matched = false;
                wmem_tree_insert32_array(msrcp_info->pdus, key, (void*)msrcp_trans);
            }
            else
            {
                msrcp_trans = (msrcp_transaction_t*)wmem_tree_lookup32_array_le(msrcp_info->pdus, key);
                if (msrcp_trans)
                {
                    if (msrcp_trans->seq != seq)
                    {
                        msrcp_trans = NULL;
                    }
                    else if (msrcp_trans->rep_frame == 0)
                    {
                        msrcp_trans->rep_frame = pinfo->num;
                        msrcp_trans->matched = true;
                    }
                }
            }
        }
        else
        {
            msrcp_trans = (msrcp_transaction_t*)wmem_tree_lookup32_array_le(msrcp_info->pdus, key);
            if (msrcp_trans)
            {
                if (msrcp_trans->seq != seq)
                {
                    msrcp_trans = NULL;
                }
                else if ((!(type == MSRCP_RESPONSE)) && (msrcp_trans->req_frame != pinfo->num))
                {
                    msrcp_transaction_t* retrans_msrcp = wmem_new(pinfo->pool, msrcp_transaction_t);
                    retrans_msrcp->req_frame = msrcp_trans->req_frame;
                    retrans_msrcp->rep_frame = 0;
                    retrans_msrcp->req_time = pinfo->abs_ts;
                    msrcp_trans = retrans_msrcp;
                }
            }
        }
        if (!msrcp_trans)
        {
            msrcp_trans = wmem_new(pinfo->pool, msrcp_transaction_t);
            msrcp_trans->req_frame = 0;
            msrcp_trans->rep_frame = 0;
            msrcp_trans->req_time = pinfo->abs_ts;
            msrcp_trans->matched = false;
        }
    }


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MSRCP");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ID %d (0x%X)",
        val_to_str_const(type, packettypenames, "MSRCP"), seq, seq);


    ti = proto_tree_add_item(tree, proto_msrcp, tvb, 0, -1, ENC_BIG_ENDIAN);
    proto_item_append_text(ti, "Type %s",
        val_to_str_const(type, packettypenames, "MSRCP"));
    msrcp_tree = proto_item_add_subtree(ti, ett_msrcp);

    if (type == MSRCP_REQUEST || type == MSRCP_RESPONSE)
    {
        proto_item* it;
        proto_tree_add_item(msrcp_tree, hf_msrcp_id, tvb, 0, 4, ENC_BIG_ENDIAN);
        tree_offset += 4;
        proto_tree_add_item(msrcp_tree, hf_msrcp_vers, tvb, tree_offset, 1, ENC_LITTLE_ENDIAN);
        tree_offset += 1;
        proto_tree_add_item(msrcp_tree, hf_msrcp_reserved, tvb, tree_offset, 1, ENC_LITTLE_ENDIAN);
        tree_offset += 1;
        proto_tree_add_item(msrcp_tree, hf_msrcp_type, tvb, tree_offset, 2, ENC_LITTLE_ENDIAN);
        tree_offset += 2;
        proto_tree_add_item(msrcp_tree, hf_msrcp_next_header, tvb, tree_offset, 2, ENC_LITTLE_ENDIAN);
        tree_offset += 2;
        proto_tree_add_item(msrcp_tree, hf_msrcp_len, tvb, tree_offset, 2, ENC_LITTLE_ENDIAN);
        tree_offset += 2;
        it = proto_tree_add_item(msrcp_tree, hf_msrcp_seq, tvb, tree_offset, 4, ENC_LITTLE_ENDIAN);
        tree_offset += 4;

        if (msrcp_trans->matched)
        {
            if ((msrcp_trans->req_frame) && (type == MSRCP_RESPONSE))
            {
                it = proto_tree_add_uint(msrcp_tree, hf_msrcp_response_to, tvb, 0, 0, msrcp_trans->req_frame);
                proto_item_set_generated(it);

            }
            else if ((msrcp_trans->rep_frame) && (type == MSRCP_REQUEST))
            {
                it = proto_tree_add_uint(msrcp_tree, hf_msrcp_response_in, tvb, 0, 0, msrcp_trans->rep_frame);
                proto_item_set_generated(it);
            }
        }
        else
        {
            expert_add_info(pinfo, it, &ei_msrcp_no_resp);
            col_prepend_fence_fstr(pinfo->cinfo, COL_INFO, "[Missing MSRCP Response]");
        }

        nxt_ti = proto_tree_add_item(msrcp_tree, hf_msrcp_ext_header, tvb, 0, 0, ENC_ASCII);
        nxt_tree = proto_item_add_subtree(nxt_ti, ett_msrcp_nxt);
        proto_tree_add_item(nxt_tree, hf_msrcp_ext_next_header, tvb, tree_offset, 2, ENC_LITTLE_ENDIAN);
        tree_offset += 2;
        proto_tree_add_item(nxt_tree, hf_msrcp_ext_len, tvb, tree_offset, 2, ENC_LITTLE_ENDIAN);
        tree_offset += 2;
        proto_tree_add_item(nxt_tree, hf_msrcp_ext_res, tvb, tree_offset, 4, ENC_LITTLE_ENDIAN);

    }
    else
    {
        next_tvb = tvb_new_subset_remaining(tvb, 0);
        call_dissector(eth_handle, next_tvb, pinfo, msrcp_tree);
    }

    return tvb_captured_length(tvb);
}


void
proto_register_msrcp(void)
{
    expert_module_t* expert_msrcp;

    static hf_register_info hf[] = {
    { &hf_msrcp_id,
        { "MSRCP ID", "msrcp.id",
        FT_UINT32, BASE_DEC_HEX,
        NULL, 0x0,
        NULL, HFILL},
    },
    { &hf_msrcp_vers,
        { "Version", "msrcp.vers",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_msrcp_reserved,
        { "Reserved", "msrcp.reserved",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_msrcp_type,
        { "MSRCP Type", "msrcp.type",
        FT_UINT16, BASE_DEC,
        VALS(packettypenames), 0x0,
        NULL, HFILL}
    },
    { &hf_msrcp_next_header,
        { "Next Header", "msrcp.nxt_header",
        FT_UINT16, BASE_DEC,
        VALS(headertypenames), 0x0,
        NULL, HFILL}
    },
    { &hf_msrcp_len,
        { "Total Length", "msrcp.len",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_msrcp_seq,
        { "Sequence Number", "msrcp.seq",
        FT_UINT32, BASE_DEC_HEX,
        NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_msrcp_response_in,
        { "Response In", "msrcp.response_in",
        FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
        "The response to this MSRCP request is in frame", HFILL}
    },
    { &hf_msrcp_response_to,
        { "Request In", "msrcp.response_to",
        FT_FRAMENUM,BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
        "This is a response to an MSRCP request in frame", HFILL}
    },
    { &hf_msrcp_ext_header,
        { "Extension Header", "msrcp.ext",
        FT_NONE, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_msrcp_ext_next_header,
        { "Next Header", "msrcp.ext_nxt_header",
        FT_UINT16, BASE_DEC,
        VALS(headertypenames), 0x0, NULL, HFILL}
    },
    { &hf_msrcp_ext_len,
        { "Length", "msrcp.ext_len",
        FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL}
    },
    { &hf_msrcp_ext_res,
        { "Reserved", "msrcp.nxt_res",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL}
    },
    };

    static int* ett[] = {
            &ett_msrcp,
            &ett_msrcp_nxt
    };

    static ei_register_info ei[] = {
        {
            &ei_msrcp_no_resp,
            { "msrcp.no_resp", PI_SEQUENCE, PI_WARN,
              "MSRCP Response not found", EXPFILL }
        }
    };

    proto_msrcp = proto_register_protocol("MSRCP Protocol", "MSRCP", "msrcp");

    proto_register_field_array(proto_msrcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_msrcp = expert_register_protocol(proto_msrcp);
    expert_register_field_array(expert_msrcp, ei, array_length(ei));

    msrcp_handle = register_dissector("msrcp", dissect_msrcp, proto_msrcp);
}

void
proto_reg_handoff_msrcp(void)
{
    eth_handle = find_dissector_add_dependency("eth_withoutfcs", proto_msrcp);
    dissector_add_uint("udp.port", MSRCP_PORT, msrcp_handle);
}
