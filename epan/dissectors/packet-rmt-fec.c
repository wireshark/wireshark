/* packet-rmt-fec.c
 * Reliable Multicast Transport (RMT)
 * FEC Building Block dissector
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
 *
 * Forward Error Correction (ALC):
 * -------------------------------
 *
 * The goal of the FEC building block is to describe functionality
 * directly related to FEC codes that is common to all reliable content
 * delivery IP multicast protocols, and to leave out any additional
 * functionality that is specific to particular protocols.
 *
 * References:
 *     RFC 3452, Forward Error Correction Building Block
 *     RFC 3695, Compact Forward Error Correction (FEC) Schemes
 *     Simple XOR, Reed-Solomon, and Parity Check Matrix-based FEC Schemes draft-peltotalo-rmt-bb-fec-supp-xor-pcm-rs-00
 *     IANA RMT FEC parameters (http://www.iana.org/assignments/rmt-fec-parameters)
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

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include "packet-rmt-common.h"

void proto_register_rmt_fec(void);
void proto_reg_handoff_rmt_fec(void);

static int proto_rmt_fec = -1;

static int hf_encoding_id = -1;
static int hf_instance_id = -1;
static int hf_sbn = -1;
static int hf_sbn_with_mask = -1;
static int hf_sbl = -1;
static int hf_esi = -1;
static int hf_esi_with_mask = -1;
static int hf_fti_transfer_length = -1;
static int hf_fti_encoding_symbol_length = -1;
static int hf_fti_max_source_block_length = -1;
static int hf_fti_max_number_encoding_symbols = -1;
static int hf_fti_num_blocks = -1;
static int hf_fti_num_subblocks = -1;
static int hf_fti_alignment = -1;

static int ett_main = -1;

static expert_field ei_fec_encoding_id = EI_INIT;

typedef struct fec_packet_data
{
    guint8 instance_id;

} fec_packet_data_t;


/* String tables */
const value_string string_fec_encoding_id[] =
{
    {   0, "Compact No-Code" },
    {   1, "Raptor" },
    {   2, "Reed-Solomon Codes over GF(2^^m)" },
    {   3, "LDPC Staircase Codes" },
    {   4, "LDPC Triangle Codes" },
    {   5, "Reed-Solomon Codes over GF(2^^8)" },
    {   6, "RaptorQ Code" },
    /* 7-127 Unassigned  */
    { 128, "Small Block, Large Block and Expandable FEC Codes" },
    { 129, "Small Block Systematic FEC Codes" },
    { 130, "Compact FEC Codes" },
    /* 131-255 Unassigned  */
    { 0, NULL }
};

/* Dissection */
/* ---------- */

/* Decode an EXT_FTI extension and fill FEC array */
void fec_decode_ext_fti(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint8 encoding_id)
{
    guint64            transfer_length;
    fec_packet_data_t *fec_data;
    guint8             instance_id = 0;
    proto_item        *ti;

    if (encoding_id == 6){
        /* Raptor Q uses 40-bit transfer length */
        transfer_length = tvb_get_ntoh40(tvb, offset+2);
    }
    else {
        /* Decode 48-bit length field */
        transfer_length = tvb_get_ntoh48(tvb, offset+2);
    }

    if (encoding_id >= 128)
    {
        instance_id = (guint8) tvb_get_ntohs(tvb, offset+8);

        /* Decode FEC Instance ID */
        fec_data = wmem_new0(wmem_file_scope(), fec_packet_data_t);
        fec_data->instance_id = instance_id;

        p_add_proto_data(wmem_file_scope(), pinfo, proto_rmt_fec, 0, fec_data);
    }

    if (encoding_id == 6){
        /* Raptor Q uses 40-bit transfer length */
        proto_tree_add_uint64(tree, hf_fti_transfer_length, tvb, offset+2, 5, transfer_length);
    }
    else {
        proto_tree_add_uint64(tree, hf_fti_transfer_length, tvb, offset+2, 6, transfer_length);
        ti = proto_tree_add_item(tree, hf_instance_id, tvb,  offset+8, 2, ENC_BIG_ENDIAN);
        if ((encoding_id < 128) && (encoding_id != 0)) {
            expert_add_info(pinfo, ti, &ei_fec_encoding_id);
        }
    }

    switch (encoding_id)
    {
    case 1:
        proto_tree_add_item(tree, hf_fti_encoding_symbol_length,      tvb, offset+10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_fti_num_blocks,                  tvb, offset+12, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_fti_num_subblocks,               tvb, offset+14, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_fti_alignment,                   tvb, offset+15, 1, ENC_BIG_ENDIAN);
        break;

    case 6:
        proto_tree_add_item(tree, hf_fti_encoding_symbol_length,      tvb, offset+8,  2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_fti_num_blocks,                  tvb, offset+10, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_fti_num_subblocks,               tvb, offset+11, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_fti_alignment,                   tvb, offset+13, 1, ENC_BIG_ENDIAN);
        break;

    case 0:
    case 2:
    case 128:
    case 130:
        proto_tree_add_item(tree, hf_fti_encoding_symbol_length,      tvb, offset+10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_fti_max_source_block_length,     tvb, offset+12, 4, ENC_BIG_ENDIAN);
        break;

    case 129:
        proto_tree_add_item(tree, hf_fti_encoding_symbol_length,      tvb, offset+10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_fti_max_source_block_length,     tvb, offset+12, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_fti_max_number_encoding_symbols, tvb, offset+14, 2, ENC_BIG_ENDIAN);
        break;

    case 132:
        proto_tree_add_item(tree, hf_fti_encoding_symbol_length,      tvb, offset+10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_fti_max_source_block_length,     tvb, offset+12, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_fti_max_number_encoding_symbols, tvb, offset+16, 4, ENC_BIG_ENDIAN);
        break;
    }
}

/* Dissect a FEC header:
 * fec - ptr to the logical FEC packet representation to fill
 * hf - ptr to header fields array
 * ett - ptr to ett array
 * prefs - ptr to FEC prefs array
 * tvb - buffer
 * pinfo - packet info
 * tree - tree where to add FEC header subtree
 * offset - ptr to offset to use and update
 */
static int
dissect_fec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item          *ti;
    proto_tree          *fec_tree;
    guint                offset      = 0;
    fec_data_exchange_t *fec         = (fec_data_exchange_t*)data;
    guint8               encoding_id = 0;
    fec_packet_data_t   *packet_data = (fec_packet_data_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_rmt_fec, 0);

    if (fec != NULL)
    {
        encoding_id = fec->encoding_id;
    }

    /* Create the FEC subtree */
    ti = proto_tree_add_item(tree, proto_rmt_fec, tvb, offset, -1, ENC_NA);
    fec_tree = proto_item_add_subtree(ti, ett_main);

    proto_tree_add_uint(fec_tree, hf_encoding_id, tvb, offset, 0, encoding_id);

    if (encoding_id >= 128 && (packet_data != NULL))
        proto_tree_add_uint(fec_tree, hf_instance_id, tvb, offset, 0, packet_data->instance_id);

    switch (encoding_id)
    {
    case 0:
    case 1:
    case 130:
        proto_tree_add_item(fec_tree, hf_sbn, tvb, offset,   2, ENC_BIG_ENDIAN);
        proto_tree_add_item(fec_tree, hf_esi, tvb, offset+2, 2, ENC_BIG_ENDIAN);

        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "SBN: %u", tvb_get_ntohs(tvb, offset));
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "ESI: 0x%X", tvb_get_ntohs(tvb, offset+2));

        offset += 4;
        break;

    case 2:
    case 128:
    case 132:
        proto_tree_add_item(fec_tree, hf_sbn, tvb, offset,   4, ENC_BIG_ENDIAN);
        proto_tree_add_item(fec_tree, hf_esi, tvb, offset+4, 4, ENC_BIG_ENDIAN);

        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "SBN: %u", tvb_get_ntohl(tvb, offset));
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "ESI: 0x%X", tvb_get_ntohl(tvb, offset+4));

        offset += 8;
        break;

    case 3:
    case 4:
        proto_tree_add_item(fec_tree, hf_sbn_with_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(fec_tree, hf_esi_with_mask, tvb, offset, 4, ENC_BIG_ENDIAN);

        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "SBN: %u", tvb_get_ntohl(tvb, offset) >> 20);
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "ESI: 0x%X", tvb_get_ntohl(tvb, offset) & 0xfffff);

        offset += 4;
        break;

    case 6:
        proto_tree_add_item(fec_tree, hf_sbn, tvb, offset,   1, ENC_BIG_ENDIAN);
        proto_tree_add_item(fec_tree, hf_esi, tvb, offset+1, 3, ENC_BIG_ENDIAN);

        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "SBN: %u", tvb_get_guint8(tvb, offset));
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "ESI: 0x%X", tvb_get_ntoh24(tvb, offset+1));

        offset += 4;
        break;

    case 129:
        proto_tree_add_item(fec_tree, hf_sbn, tvb, offset,   4, ENC_BIG_ENDIAN);
        proto_tree_add_item(fec_tree, hf_sbl, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(fec_tree, hf_esi, tvb, offset+6, 2, ENC_BIG_ENDIAN);

        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "SBN: %u", tvb_get_ntohl(tvb, offset));
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "ESI: 0x%X", tvb_get_ntohs(tvb, offset+6));

        offset += 8;
        break;
    }

    return offset;
}

void proto_register_rmt_fec(void)
{
    static hf_register_info hf[] = {
        { &hf_encoding_id,
          { "FEC Encoding ID", "rmt-fec.encoding_id",
            FT_UINT8, BASE_DEC, VALS(string_fec_encoding_id), 0x0,
            NULL, HFILL }
        },
        { &hf_instance_id,
          { "FEC Instance ID", "rmt-fec.instance_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sbn,
          { "Source Block Number", "rmt-fec.sbn",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sbn_with_mask,
          { "Source Block Number", "rmt-fec.sbn",
            FT_UINT32, BASE_DEC, NULL, 0xFFF00000,
            NULL, HFILL }
        },
        { &hf_sbl,
          { "Source Block Length", "rmt-fec.sbl",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_esi,
          { "Encoding Symbol ID", "rmt-fec.esi",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_esi_with_mask,
          { "Encoding Symbol ID", "rmt-fec.esi",
            FT_UINT32, BASE_HEX, NULL, 0x000FFFFF,
            NULL, HFILL }
        },
        { &hf_fti_transfer_length,
          { "Transfer Length", "rmt-fec.fti.transfer_length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fti_encoding_symbol_length,
          { "Encoding Symbol Length", "rmt-fec.fti.encoding_symbol_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fti_max_source_block_length,
          { "Maximum Source Block Length", "rmt-fec.fti.max_source_block_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fti_max_number_encoding_symbols,
          { "Maximum Number of Encoding Symbols", "rmt-fec.fti.max_number_encoding_symbols",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fti_num_blocks,
          { "Number of Source Blocks", "rmt-fec.fti.num_blocks",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fti_num_subblocks,
          { "Number of Sub-Blocks", "rmt-fec.fti.num_subblocks",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fti_alignment,
          { "Symbol Alignment", "rmt-fec.fti.alignment",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_main,
    };

    static ei_register_info ei[] = {
        { &ei_fec_encoding_id, { "rmt-fec.encoding_id.not0", PI_PROTOCOL, PI_WARN, "FEC Encoding ID < 128, should be zero", EXPFILL }},
    };

    expert_module_t* expert_rmt_fec;

    /* Register the protocol name and description */
    proto_rmt_fec = proto_register_protocol("Forward Error Correction (FEC)", "RMT-FEC", "rmt-fec");
    register_dissector("rmt-fec", dissect_fec, proto_rmt_fec);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_rmt_fec, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_rmt_fec = expert_register_protocol(proto_rmt_fec);
    expert_register_field_array(expert_rmt_fec, ei, array_length(ei));
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
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
