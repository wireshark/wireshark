/* packet-smpte-2110-20.c
 * SMPTE ST2110-20
 *
 * Copyright 2023, Sergey V. Lobanov <sergey@lobanov.in>
 *
 * References:
 *     SMPTE ST 2110-20:2022, Uncompressed Active Video
 *     RFC4175, RTP Payload Format for Uncompressed Video
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/proto_data.h>

#include "packet-rtp.h"

void proto_reg_handoff_st2110_20(void);
void proto_register_st2110_20(void);

static dissector_handle_t st2110_20_handle;

/* Initialize the protocol and registered fields */
static int proto_st2110_20;
static int proto_rtp;

static int hf_st2110_ext_seqno;
static int hf_st2110_seqno;
static int hf_st2110_rtp_time;
static int hf_st2110_srd_index;
static int hf_st2110_srd_length;
static int hf_st2110_field_ident;
static int hf_st2110_row_num;
static int hf_st2110_continuation;
static int hf_st2110_srd_offset;
static int hf_st2110_srd_data;
static int hf_st2110_srd_rows;

/* Initialize the subtree pointers */
static int ett_st2110_20;
static int ett_st2110_20_srd_row;


static int
dissect_st2110_20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void* data _U_)
{
    proto_item *item;
    proto_tree *st2110_20_tree;

    int offset = 0;

    struct _rtp_packet_info *rtp_pkt_info = (struct _rtp_packet_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_rtp, RTP_CONVERSATION_PROTO_DATA);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ST2110-20");

    item = proto_tree_add_item(tree, proto_st2110_20, tvb, 0, -1, ENC_NA);
    st2110_20_tree = proto_item_add_subtree(item, ett_st2110_20);

    /* Extract original RTP sequence number from low bits */
    uint32_t rtp_seqno = (rtp_pkt_info != NULL) ? (rtp_pkt_info->extended_seqno & 0xFFFF) : 0;
    /* ST2110-20 extended sequence number field */
    uint32_t ext_seqno = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
    /* Sequence number (RTP seqno is low bits, ST2110-20 ext seqno is high bits) */
    uint32_t seqno = (ext_seqno << 16) + rtp_seqno;

    /* Extract original RTP timestamp */
    uint32_t rtp_time = (rtp_pkt_info != NULL) ? (uint32_t)(rtp_pkt_info->extended_timestamp & 0xFFFFFFFF) : 0;

    proto_tree_add_item(st2110_20_tree, hf_st2110_ext_seqno, tvb, offset, 2, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_GENERATED(
            proto_tree_add_uint(st2110_20_tree, hf_st2110_seqno, tvb, offset, 2, seqno)
    );
    PROTO_ITEM_SET_GENERATED(
            proto_tree_add_uint(st2110_20_tree, hf_st2110_rtp_time, NULL, 0, 0, rtp_time)
    );
    offset += 2; /* st2110-20 ext seqno */

    /* According to ST2110-20:2022 6.2.1, max three SRD headers might be in a packet */
    uint16_t srd_lengths[3] = {0, 0, 0}; /* store for second pass */
    proto_tree* srd_header_trees[3] = {NULL, NULL, NULL}; /* store for second pass */
    uint8_t srd_rows = 0; /* rows count */
    uint16_t first_row; /* first row number */
    for (uint8_t srd_idx = 0; srd_idx < 3 ; srd_idx++) {
        proto_tree *srd_header_tree = proto_tree_add_subtree_format(st2110_20_tree, tvb, offset, 6,
                                    ett_st2110_20_srd_row, &item, "Sample Row Data %u", srd_idx);
        srd_header_trees[srd_idx] = srd_header_tree;
        PROTO_ITEM_SET_GENERATED(
            proto_tree_add_uint(srd_header_tree, hf_st2110_srd_index, NULL, 0, 0, srd_idx)
        );

        srd_lengths[srd_idx] = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
        proto_tree_add_item(srd_header_tree, hf_st2110_srd_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        first_row = (srd_idx == 0) ? (tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN) & 0x7FFF) : first_row;
        proto_tree_add_item(srd_header_tree, hf_st2110_field_ident, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(srd_header_tree, hf_st2110_row_num, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        uint16_t cont_bit = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN) >> 15;
        proto_tree_add_item(srd_header_tree, hf_st2110_continuation, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(srd_header_tree, hf_st2110_srd_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        srd_rows++;

        if (cont_bit != 1) /* if continuation is not set, then no more headers*/
            break;
    }

    PROTO_ITEM_SET_GENERATED(
        proto_tree_add_uint(st2110_20_tree, hf_st2110_srd_rows, NULL, 0, 0, srd_rows)
    );

    /* Second pass, get SRD data and add it to the same trees created for SRD headers */
    for (uint8_t srd_idx = 0; srd_idx < srd_rows ; srd_idx++) {
        uint16_t srd_length = srd_lengths[srd_idx];

        proto_tree_add_item(srd_header_trees[srd_idx], hf_st2110_srd_data, tvb, offset, srd_length, ENC_NA);
        offset += srd_length;
    }

    col_add_fstr(pinfo->cinfo, COL_INFO, "Seq=%u, Time=%u, FirstRow=%u, Rows=%u", seqno, rtp_time, first_row, srd_rows);

    return offset;
}

void
proto_register_st2110_20(void)
{
    module_t *st2110_20_module;

    static hf_register_info hf[] = {
        { &hf_st2110_ext_seqno,
          { "Extended Sequence Number", "st2110_20.ext_seq",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_st2110_seqno,
          { "Sequence Number", "st2110_20.seq",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_st2110_rtp_time,
          { "RTP Timestamp", "st2110_20.rtp_timestamp",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_st2110_srd_index,
          { "SRD Header Index", "st2110_20.srd_index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_st2110_srd_length,
          { "SRD Length", "st2110_20.srd_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_st2110_field_ident,
          { "Field Identification Bit", "st2110_20.srd_field_ident",
            FT_UINT16, BASE_DEC, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_st2110_row_num,
          { "SRD Row Number", "st2110_20.srd_row_num",
            FT_UINT16, BASE_DEC, NULL, 0x7FFF,
            NULL, HFILL }
        },
        { &hf_st2110_continuation,
          { "SRD Continuation Bit", "st2110_20.srd_cont_bit",
            FT_UINT16, BASE_DEC, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_st2110_srd_offset,
          { "SRD Offset", "st2110_20.srd_offset",
            FT_UINT16, BASE_DEC, NULL, 0x7FFF,
            NULL, HFILL }
        },
        { &hf_st2110_srd_data,
          { "SRD Data", "st2110_20.srd_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_st2110_srd_rows,
          { "SRD Rows", "st2110_20.srd_rows",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static int *ett[] =
    {
        &ett_st2110_20,
        &ett_st2110_20_srd_row
    };

    proto_st2110_20  = proto_register_protocol("SMPTE ST2110-20 (Uncompressed Active Video)", "ST2110-20", "st2110_20");

    proto_register_field_array(proto_st2110_20, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    st2110_20_module = prefs_register_protocol(proto_st2110_20, NULL);

    prefs_register_obsolete_preference(st2110_20_module, "dynamic.payload.type");
    st2110_20_handle = register_dissector("st2110_20", dissect_st2110_20, proto_st2110_20);
}

void
proto_reg_handoff_st2110_20(void)
{
    dissector_add_string("rtp_dyn_payload_type" , "ST2110-20", st2110_20_handle);
    dissector_add_uint_range_with_preference("rtp.pt", "", st2110_20_handle);
    proto_rtp = proto_get_id_by_filter_name("rtp");
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
