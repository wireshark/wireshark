/* packet-isis-snp.c
 * Routines for decoding isis complete & partial SNP and their payload
 *
 * Stuart Stanley <stuarts@mxmail.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-isis-clv.h"

void proto_register_isis_csnp(void);
void proto_reg_handoff_isis_csnp(void);
void proto_register_isis_psnp(void);
void proto_reg_handoff_isis_psnp(void);
void proto_register_isis_lsp(void);
void proto_reg_handoff_isis_lsp(void);
void proto_register_isis_hello(void);
void proto_reg_handoff_isis_hello(void);

static int proto_isis_csnp;
static int proto_isis_psnp;

/* csnp packets */
static int hf_isis_csnp_pdu_length;
static int hf_isis_csnp_source_id;
static int hf_isis_csnp_source_circuit;
static int hf_isis_csnp_start_lsp_id;
static int hf_isis_csnp_end_lsp_id;
static int hf_isis_csnp_lsp_id;
static int hf_isis_csnp_lsp_seq_num;
static int hf_isis_csnp_lsp_remain_life;
static int hf_isis_csnp_lsp_checksum;
static int hf_isis_csnp_checksum;
static int hf_isis_csnp_checksum_status;
static int hf_isis_csnp_clv_type;
static int hf_isis_csnp_clv_length;
static int hf_isis_csnp_ip_authentication;
static int hf_isis_csnp_authentication;
static int hf_isis_csnp_instance_identifier;
static int hf_isis_csnp_supported_itid;
static int ett_isis_csnp;
static int ett_isis_csnp_clv_lsp_entries;
static int ett_isis_csnp_lsp_entry;
static int ett_isis_csnp_clv_authentication;
static int ett_isis_csnp_clv_ip_authentication;
static int ett_isis_csnp_clv_instance_identifier;
static int ett_isis_csnp_clv_checksum;
static int ett_isis_csnp_clv_unknown;

static expert_field ei_isis_csnp_short_pdu;
static expert_field ei_isis_csnp_long_pdu;
static expert_field ei_isis_csnp_bad_checksum;
static expert_field ei_isis_csnp_authentication;
static expert_field ei_isis_csnp_short_clv;
static expert_field ei_isis_csnp_clv_unknown;

/* psnp packets */
static int hf_isis_psnp_pdu_length;
static int hf_isis_psnp_source_id;
static int hf_isis_psnp_source_circuit;
static int hf_isis_psnp_clv_type;
static int hf_isis_psnp_clv_length;
static int hf_isis_psnp_ip_authentication;
static int ett_isis_psnp;
static int ett_isis_psnp_clv_lsp_entries;
static int ett_isis_psnp_lsp_entry;
static int ett_isis_psnp_clv_authentication;
static int ett_isis_psnp_clv_ip_authentication;
static int ett_isis_psnp_clv_checksum;
static int ett_isis_psnp_clv_unknown;

static expert_field ei_isis_psnp_short_pdu;
static expert_field ei_isis_psnp_long_pdu;
static expert_field ei_isis_psnp_short_clv;
static expert_field ei_isis_psnp_clv_unknown;

static void
dissect_snp_authentication_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    isis_dissect_authentication_clv(tree, pinfo, tvb, hf_isis_csnp_authentication, hf_isis_clv_key_id, &ei_isis_csnp_authentication, offset, length);
}

static void
dissect_csnp_ip_authentication_clv(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    if ( length != 0 ) {
       proto_tree_add_item(tree, hf_isis_csnp_ip_authentication, tvb, offset, length, ENC_ASCII);
    }
}

static void
dissect_psnp_ip_authentication_clv(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, int offset,
    isis_data_t *isis _U_, int length)
{
    if ( length != 0 ) {
       proto_tree_add_item(tree, hf_isis_psnp_ip_authentication, tvb, offset, length, ENC_ASCII);
    }
}

/*
 * Name: dissect_snp_checksum_clv()
 *
 * Description:
 *      dump and verify the optional checksum in TLV 12
 */
static void
dissect_snp_checksum_clv(tvbuff_t *tvb, packet_info* pinfo,
        proto_tree *tree, int offset, isis_data_t *isis, int length) {

    uint16_t checksum, cacl_checksum=0;

    if ( length != 2 ) {
        proto_tree_add_expert_format(tree, pinfo, &ei_isis_csnp_short_clv, tvb, offset, -1,
            "incorrect checksum length (%u), should be (2)", length );
            return;
    }


    checksum = tvb_get_ntohs(tvb, offset);

    if (checksum == 0) {
        /* No checksum present */
        proto_tree_add_checksum(tree, tvb, offset, hf_isis_csnp_checksum, hf_isis_csnp_checksum_status, &ei_isis_csnp_bad_checksum, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NOT_PRESENT);
    } else {
        if (osi_check_and_get_checksum(tvb, 0, isis->pdu_length, offset, &cacl_checksum)) {
            /* Successfully processed checksum, verify it */
            proto_tree_add_checksum(tree, tvb, offset, hf_isis_csnp_checksum, hf_isis_csnp_checksum_status, &ei_isis_csnp_bad_checksum, pinfo, cacl_checksum, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
        } else {
            /* We didn't capture the entire packet, so we can't verify it */
            proto_tree_add_checksum(tree, tvb, offset, hf_isis_csnp_checksum, hf_isis_csnp_checksum_status, &ei_isis_csnp_bad_checksum, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
        }
    }
}

/*
 * Name: dissect_snp_lsp_entries_clv()
 *
 * Description:
 *    All the snp packets use a common payload format.  We have up
 *    to n entries (based on length), which are made of:
 *        2                   : remaining life time
 *        isis->system_id_len : lsp id
 *        4                   : sequence number
 *        2                   : checksum
 */
static void
dissect_snp_lsp_entries_clv(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, int offset,
    isis_data_t *isis, int length)
{
    proto_tree *subtree;

    while ( length > 0 ) {
        if ( length < 2+isis->system_id_len+2+4+2 ) {
            proto_tree_add_expert_format(tree, pinfo, &ei_isis_csnp_short_clv, tvb, offset, -1,
                "Short SNP header entry (%d vs %d)", length, 2+isis->system_id_len+2+4+2 );
            return;
        }

        subtree = proto_tree_add_subtree(tree, tvb, offset, 2+isis->system_id_len+2+4+2,
                                    ett_isis_csnp_lsp_entry, NULL, "LSP Entry");

        proto_tree_add_item(tree, hf_isis_csnp_lsp_id, tvb, offset+2, isis->system_id_len+2, ENC_NA);

        proto_tree_add_item(subtree, hf_isis_csnp_lsp_seq_num, tvb, offset+2+isis->system_id_len+2, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_isis_csnp_lsp_remain_life, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_isis_csnp_lsp_checksum, tvb, offset+2+isis->system_id_len+2+4, 2, ENC_BIG_ENDIAN);

        length -= 2+isis->system_id_len+2+4+2;
        offset += 2+isis->system_id_len+2+4+2;
    }

}

/*
 * Name: dissect_snp_instance_identifier_clv()
 *
 * Description:
 *    Decode for a snp packets Instance Identifier clv.
 *      Calls into the CLV common one.
 *
 * Input:
 *    tvbuff_t * : tvbuffer for packet data
 *    proto_tree * : proto tree to build on (may be null)
 *    int : current offset into packet data
 *    int : length of IDs in packet.
 *    int : length of this clv
 *
 * Output:
 *    void, will modify proto_tree if not null.
 */
static void
dissect_snp_instance_identifier_clv(tvbuff_t *tvb, packet_info* pinfo _U_,
    proto_tree *tree, int offset, isis_data_t *isis _U_, int length)
{
    isis_dissect_instance_identifier_clv(tree, pinfo, tvb, &ei_isis_csnp_short_clv, hf_isis_csnp_instance_identifier, hf_isis_csnp_supported_itid, offset, length);
}

static const isis_clv_handle_t clv_l1_csnp_opts[] = {
    {
        ISIS_CLV_INSTANCE_IDENTIFIER,
        "Instance Identifier",
        &ett_isis_csnp_clv_instance_identifier,
        dissect_snp_instance_identifier_clv
    },
    {
        ISIS_CLV_LSP_ENTRIES,
        "LSP entries",
        &ett_isis_csnp_clv_lsp_entries,
        dissect_snp_lsp_entries_clv
    },
    {
        ISIS_CLV_AUTHENTICATION,
        "Authentication",
        &ett_isis_csnp_clv_authentication,
        dissect_snp_authentication_clv
    },
    {
        ISIS_CLV_IP_AUTHENTICATION,
        "IP Authentication",
        &ett_isis_csnp_clv_ip_authentication,
        dissect_csnp_ip_authentication_clv
    },
    {
        ISIS_CLV_CHECKSUM,
        "Checksum",
        &ett_isis_csnp_clv_checksum,
        dissect_snp_checksum_clv
    },
    {
        0, "", NULL, NULL
    }
};

static const isis_clv_handle_t clv_l2_csnp_opts[] = {
    {
        ISIS_CLV_INSTANCE_IDENTIFIER,
        "Instance Identifier",
        &ett_isis_csnp_clv_instance_identifier,
        dissect_snp_instance_identifier_clv
    },
    {
        ISIS_CLV_LSP_ENTRIES,
        "LSP entries",
        &ett_isis_csnp_clv_lsp_entries,
        dissect_snp_lsp_entries_clv
    },
    {
        ISIS_CLV_AUTHENTICATION,
        "Authentication",
        &ett_isis_csnp_clv_authentication,
        dissect_snp_authentication_clv
    },
    {
        ISIS_CLV_IP_AUTHENTICATION,
        "IP Authentication",
        &ett_isis_csnp_clv_ip_authentication,
        dissect_csnp_ip_authentication_clv
    },
    {
        ISIS_CLV_CHECKSUM,
        "Checksum",
        &ett_isis_csnp_clv_checksum,
        dissect_snp_checksum_clv
    },
    {
        0, "", NULL, NULL
    }
};

static const isis_clv_handle_t clv_l1_psnp_opts[] = {
    {
        ISIS_CLV_INSTANCE_IDENTIFIER,
        "Instance Identifier",
        &ett_isis_csnp_clv_instance_identifier,
        dissect_snp_instance_identifier_clv
    },
    {
        ISIS_CLV_LSP_ENTRIES,
        "LSP entries",
        &ett_isis_psnp_clv_lsp_entries,
        dissect_snp_lsp_entries_clv
    },
    {
        ISIS_CLV_AUTHENTICATION,
        "Authentication",
        &ett_isis_psnp_clv_authentication,
        dissect_snp_authentication_clv
    },
    {
        ISIS_CLV_IP_AUTHENTICATION,
        "IP Authentication",
        &ett_isis_psnp_clv_ip_authentication,
        dissect_psnp_ip_authentication_clv
    },
    {
        ISIS_CLV_CHECKSUM,
        "Checksum",
        &ett_isis_psnp_clv_checksum,
        dissect_snp_checksum_clv
    },
    {
        0, "", NULL, NULL
    }
};

static const isis_clv_handle_t clv_l2_psnp_opts[] = {
    {
        ISIS_CLV_INSTANCE_IDENTIFIER,
        "Instance Identifier",
        &ett_isis_csnp_clv_instance_identifier,
        dissect_snp_instance_identifier_clv
    },
    {
        ISIS_CLV_LSP_ENTRIES,
        "LSP entries",
        &ett_isis_psnp_clv_lsp_entries,
        dissect_snp_lsp_entries_clv
    },
    {
        ISIS_CLV_AUTHENTICATION,
        "Authentication",
        &ett_isis_psnp_clv_authentication,
        dissect_snp_authentication_clv
    },
    {
        ISIS_CLV_IP_AUTHENTICATION,
        "IP Authentication",
        &ett_isis_psnp_clv_ip_authentication,
        dissect_psnp_ip_authentication_clv
    },
    {
        ISIS_CLV_CHECKSUM,
        "Checksum",
        &ett_isis_psnp_clv_checksum,
        dissect_snp_checksum_clv
    },
    {
        0, "", NULL, NULL
    }
};

static void
dissect_isis_csnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
    const isis_clv_handle_t *opts, isis_data_t *isis)
{
    proto_item    *ti;
    proto_tree    *csnp_tree = NULL;
    uint16_t       pdu_length;
    bool           pdu_length_too_short = false;

    /*
     * We are passed a tvbuff for the entire ISIS PDU, because some ISIS
     * PDUs may contain a checksum CLV, and that's a checksum covering
     * the entire PDU.  Skip the part of the header that's already been
     * dissected.
     */
    offset += 8;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISIS CSNP");

    ti = proto_tree_add_item(tree, proto_isis_csnp, tvb, offset, -1, ENC_NA);
    csnp_tree = proto_item_add_subtree(ti, ett_isis_csnp);

    if (isis->header_length < 8 + 2) {
        /* Not large enough to include the part of the header that
           we dissect here. */
        expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
        return;
    }
    pdu_length = tvb_get_ntohs(tvb, offset);
    ti = proto_tree_add_uint(csnp_tree, hf_isis_csnp_pdu_length, tvb,
            offset, 2, pdu_length);
    if (pdu_length < isis->header_length) {
        expert_add_info(pinfo, ti, &ei_isis_csnp_short_pdu);
        pdu_length_too_short = true;
    } else if (pdu_length > tvb_reported_length(tvb) + isis->header_length) {
        expert_add_info(pinfo, ti, &ei_isis_csnp_long_pdu);
    }
    offset += 2;

    if (isis->header_length < 8 + 2 + isis->system_id_len + 1) {
        /* Not large enough to include the part of the header that
           we dissect here. */
        expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
        return;
    }
    /* ISO 10589:2002 9.10 "Source ID – the system ID of Intermediate System (with zero Circuit ID)" */
    proto_tree_add_item(csnp_tree, hf_isis_csnp_source_id, tvb, offset, isis->system_id_len, ENC_NA);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Source-ID: %s", tvb_print_system_id( pinfo->pool, tvb, offset, isis->system_id_len+1 ));
    offset += isis->system_id_len;
    proto_tree_add_item(csnp_tree, hf_isis_csnp_source_circuit, tvb, offset, 1, ENC_NA);
    offset++;

    if (isis->header_length < 8 + 2 + isis->system_id_len + 1 + isis->system_id_len + 2) {
        /* Not large enough to include the part of the header that
           we dissect here. */
        expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
        return;
    }
    proto_tree_add_item(csnp_tree, hf_isis_csnp_start_lsp_id, tvb, offset, isis->system_id_len + 2, ENC_NA);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Start LSP-ID: %s",
                    tvb_print_system_id( pinfo->pool, tvb, offset, isis->system_id_len+2 ));
    offset += isis->system_id_len + 2;

    proto_tree_add_item(csnp_tree, hf_isis_csnp_end_lsp_id, tvb, offset, isis->system_id_len + 2, ENC_NA);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", End LSP-ID: %s",
                    tvb_print_system_id( pinfo->pool, tvb, offset, isis->system_id_len+2 ));
    offset += isis->system_id_len + 2;

    if (pdu_length_too_short) {
        return;
    }
    isis->pdu_length = pdu_length;
    isis_dissect_clvs(tvb, pinfo, csnp_tree, offset,
            opts, &ei_isis_csnp_short_clv, isis, ett_isis_csnp_clv_unknown,
            hf_isis_csnp_clv_type, hf_isis_csnp_clv_length,
            &ei_isis_csnp_clv_unknown);
}


static int
dissect_isis_l1_csnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    isis_data_t* isis = (isis_data_t*)data;
    dissect_isis_csnp(tvb, pinfo, tree, 0, clv_l1_csnp_opts, isis);
    return tvb_captured_length(tvb);
}

static int
dissect_isis_l2_csnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    isis_data_t* isis = (isis_data_t*)data;
    dissect_isis_csnp(tvb, pinfo, tree, 0, clv_l2_csnp_opts, isis);
    return tvb_captured_length(tvb);
}

static void
dissect_isis_psnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
    const isis_clv_handle_t *opts, isis_data_t *isis)
{
    proto_item    *ti;
    proto_tree    *psnp_tree;
    uint16_t       pdu_length;
    bool           pdu_length_too_short = false;

    /*
     * We are passed a tvbuff for the entire ISIS PDU, because some ISIS
     * PDUs may contain a checksum CLV, and that's a checksum covering
     * the entire PDU.  Skip the part of the header that's already been
     * dissected.
     */
    offset += 8;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISIS PSNP");

    ti = proto_tree_add_item(tree, proto_isis_psnp, tvb, offset, -1, ENC_NA);
    psnp_tree = proto_item_add_subtree(ti, ett_isis_psnp);

    if (isis->header_length < 8 + 2) {
        /* Not large enough to include the part of the header that
           we dissect here. */
        expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
        return;
    }
    pdu_length = tvb_get_ntohs(tvb, offset);
    ti = proto_tree_add_uint(psnp_tree, hf_isis_psnp_pdu_length, tvb,
            offset, 2, pdu_length);
    if (pdu_length < isis->header_length) {
        expert_add_info(pinfo, ti, &ei_isis_psnp_short_pdu);
        pdu_length_too_short = true;
    } else if (pdu_length > tvb_reported_length(tvb) + isis->header_length) {
        expert_add_info(pinfo, ti, &ei_isis_psnp_long_pdu);
    }
    offset += 2;

    if (isis->header_length < 8 + 2 + isis->system_id_len + 1) {
        /* Not large enough to include the part of the header that
           we dissect here. */
        expert_add_info(pinfo, isis->header_length_item, isis->ei_bad_header_length);
        return;
    }
    /* ISO 10589:2002 9.10 "Source ID – the system ID of Intermediate System (with zero Circuit ID)" */
    proto_tree_add_item(psnp_tree, hf_isis_psnp_source_id, tvb, offset, isis->system_id_len, ENC_NA);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Source-ID: %s", tvb_print_system_id( pinfo->pool, tvb, offset, isis->system_id_len+1 ));
    offset += isis->system_id_len;
    proto_tree_add_item(psnp_tree, hf_isis_psnp_source_circuit, tvb, offset, 1, ENC_NA);
    offset++;

    if (pdu_length_too_short) {
        return;
    }
    isis->pdu_length = pdu_length;
    isis_dissect_clvs(tvb, pinfo, psnp_tree, offset,
            opts, &ei_isis_psnp_short_clv, isis, ett_isis_psnp_clv_unknown,
            hf_isis_psnp_clv_type, hf_isis_psnp_clv_length,
            &ei_isis_psnp_clv_unknown);
}

static int
dissect_isis_l1_psnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    isis_data_t* isis = (isis_data_t*)data;
    dissect_isis_psnp(tvb, pinfo, tree, 0, clv_l1_psnp_opts, isis);
    return tvb_captured_length(tvb);
}

static int
dissect_isis_l2_psnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    isis_data_t* isis = (isis_data_t*)data;
    dissect_isis_psnp(tvb, pinfo, tree, 0, clv_l2_psnp_opts, isis);
    return tvb_captured_length(tvb);
}

void
proto_register_isis_csnp(void)
{
    static hf_register_info hf[] = {
        { &hf_isis_csnp_pdu_length,
        { "PDU length",        "isis.csnp.pdu_length", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_csnp_source_id,
        { "Source-ID", "isis.csnp.source_id",
            FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_csnp_source_circuit,
        { "Source-ID-Circuit", "isis.csnp.source_circuit",
            FT_BYTES, BASE_NONE, NULL, 0x0, "Must be Zero", HFILL }},
        { &hf_isis_csnp_start_lsp_id,
        { "Start LSP-ID", "isis.csnp.start_lsp_id",
            FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_csnp_end_lsp_id,
        { "End LSP-ID", "isis.csnp.end_lsp_id",
            FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_csnp_lsp_id,
        { "LSP-ID", "isis.csnp.lsp_id",
            FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_csnp_lsp_seq_num,
        { "LSP Sequence Number",        "isis.csnp.lsp_seq_num", FT_UINT32,
          BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_csnp_lsp_remain_life,
        { "Remaining Lifetime",        "isis.csnp.lsp_remain_life", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_csnp_lsp_checksum,
        { "LSP checksum",        "isis.csnp.lsp_checksum", FT_UINT16,
          BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_csnp_checksum,
        { "Checksum",        "isis.csnp.checksum", FT_UINT16,
          BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_csnp_checksum_status,
        { "Checksum Status",        "isis.csnp.checksum.status", FT_UINT8,
          BASE_NONE, VALS(proto_checksum_vals), 0x0, NULL, HFILL }},
        { &hf_isis_csnp_clv_type,
        { "Type",        "isis.csnp.clv.type", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_csnp_clv_length,
        { "Length",        "isis.csnp.clv.length", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_csnp_ip_authentication,
        { "IP Authentication",        "isis.csnp.ip_authentication", FT_STRING,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_csnp_authentication,
        { "Authentication",        "isis.csnp.authentication", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_csnp_instance_identifier,
        { "Instance Identifier", "isis.csnp.iid", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_isis_csnp_supported_itid,
        { "Supported ITID", "isis.csnp.supported_itid", FT_UINT16,
           BASE_DEC, NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_isis_csnp,
        &ett_isis_csnp_clv_lsp_entries,
        &ett_isis_csnp_lsp_entry,
        &ett_isis_csnp_clv_authentication,
        &ett_isis_csnp_clv_ip_authentication,
        &ett_isis_csnp_clv_instance_identifier,
        &ett_isis_csnp_clv_checksum,
        &ett_isis_csnp_clv_unknown,
    };

    static ei_register_info ei[] = {
        { &ei_isis_csnp_short_pdu, { "isis.csnp.short_pdu", PI_MALFORMED, PI_ERROR, "PDU length less than header length", EXPFILL }},
        { &ei_isis_csnp_long_pdu, { "isis.csnp.long_pdu", PI_MALFORMED, PI_ERROR, "PDU length greater than packet length", EXPFILL }},
        { &ei_isis_csnp_bad_checksum, { "isis.csnp.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
        { &ei_isis_csnp_short_clv, { "isis.csnp.short_clv", PI_MALFORMED, PI_ERROR, "Short packet", EXPFILL }},
        { &ei_isis_csnp_authentication, { "isis.csnp.authentication.unknown", PI_PROTOCOL, PI_WARN, "Unknown authentication type", EXPFILL }},
        { &ei_isis_csnp_clv_unknown, { "isis.csnp.clv.unknown", PI_UNDECODED, PI_NOTE, "Unknown option", EXPFILL }},
    };
    expert_module_t* expert_isis_csnp;

    /* Register the protocol name and description */
    proto_isis_csnp = proto_register_protocol(PROTO_STRING_CSNP, "ISIS CSNP", "isis.csnp");

    proto_register_field_array(proto_isis_csnp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_isis_csnp = expert_register_protocol(proto_isis_csnp);
    expert_register_field_array(expert_isis_csnp, ei, array_length(ei));
}

void
proto_reg_handoff_isis_csnp(void)
{
    dissector_add_uint("isis.type", ISIS_TYPE_L1_CSNP, create_dissector_handle(dissect_isis_l1_csnp, proto_isis_csnp));
    dissector_add_uint("isis.type", ISIS_TYPE_L2_CSNP, create_dissector_handle(dissect_isis_l2_csnp, proto_isis_csnp));
}

void
proto_register_isis_psnp(void)
{
    static hf_register_info hf[] = {
        { &hf_isis_psnp_pdu_length,
        { "PDU length",        "isis.psnp.pdu_length", FT_UINT16,
          BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_psnp_source_id,
        { "Source-ID", "isis.psnp.source_id",
            FT_SYSTEM_ID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_psnp_source_circuit,
        { "Source-ID-Circuit", "isis.psnp.source_circuit",
            FT_BYTES, BASE_NONE, NULL, 0x0, "Must be Zero", HFILL }},
        { &hf_isis_psnp_clv_type,
        { "Type",        "isis.psnp.clv.type", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_psnp_clv_length,
        { "Length",        "isis.psnp.clv.length", FT_UINT8,
          BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_isis_psnp_ip_authentication,
        { "IP Authentication",        "isis.csnp.ip_authentication", FT_STRING,
          BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_isis_psnp,
        &ett_isis_psnp_clv_lsp_entries,
        &ett_isis_psnp_lsp_entry,
        &ett_isis_psnp_clv_authentication,
        &ett_isis_psnp_clv_ip_authentication,
        &ett_isis_psnp_clv_checksum,
        &ett_isis_psnp_clv_unknown,
    };
    static ei_register_info ei[] = {
        { &ei_isis_psnp_short_pdu, { "isis.psnp.short_pdu", PI_MALFORMED, PI_ERROR, "PDU length less than header length", EXPFILL }},
        { &ei_isis_psnp_long_pdu, { "isis.psnp.long_pdu", PI_MALFORMED, PI_ERROR, "PDU length greater than packet length", EXPFILL }},
        { &ei_isis_psnp_short_clv, { "isis.psnp.short_clv", PI_MALFORMED, PI_ERROR, "Short CLV", EXPFILL }},
        { &ei_isis_psnp_clv_unknown, { "isis.psnp.clv.unknown", PI_UNDECODED, PI_NOTE, "Unknown option", EXPFILL }},
    };
    expert_module_t* expert_isis_psnp;

    /* Register the protocol name and description */
    proto_isis_psnp = proto_register_protocol(PROTO_STRING_PSNP, "ISIS PSNP", "isis.psnp");

    proto_register_field_array(proto_isis_psnp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_isis_psnp = expert_register_protocol(proto_isis_psnp);
    expert_register_field_array(expert_isis_psnp, ei, array_length(ei));
}

void
proto_reg_handoff_isis_psnp(void)
{
    dissector_add_uint("isis.type", ISIS_TYPE_L1_PSNP, create_dissector_handle(dissect_isis_l1_psnp, proto_isis_psnp));
    dissector_add_uint("isis.type", ISIS_TYPE_L2_PSNP, create_dissector_handle(dissect_isis_l2_psnp, proto_isis_psnp));
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
