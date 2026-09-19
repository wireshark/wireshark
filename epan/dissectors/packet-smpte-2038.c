/* packet-smpte-2038.c
 * SMPTE ST 2038:2021, "Carriage of Ancillary Data Packets in an MPEG-2 Transport Stream."
 *
 * Copyright (c) 2026, Devin Heitmueller <dheitmueller@ltnglobal.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/tfs.h>
#include <wsutil/array.h>

#include "packet-smpte-291-vanc.h"

#define ST2038_REGISTRATION_ID 0x56414e43U /* "VANC" */

void proto_register_st2038(void);
void proto_reg_handoff_st2038(void);

static int proto_st2038;
static dissector_handle_t st2038_handle;

static int hf_st2038_anc_packet;
static int hf_st2038_anc_count;
static int hf_st2038_reserved;
static int hf_st2038_c_not_y;
static int hf_st2038_line_number;
static int hf_st2038_horizontal_offset;
static int hf_st2038_data_count;
static int hf_st2038_udw_bytes;
static int hf_st2038_udw_array;
static int hf_st2038_checksum;
static int hf_st2038_checksum_calculated;
static int hf_st2038_alignment_bits;
static int hf_st2038_stuffing_bytes;

static int ett_st2038;
static int ett_st2038_anc_packet;
static int ett_st2038_udw;

static expert_field ei_st2038_reserved;
static expert_field ei_st2038_bad_parity;
static expert_field ei_st2038_bad_checksum;
static expert_field ei_st2038_bad_alignment;
static expert_field ei_st2038_nonstandard_stuffing;
static expert_field ei_st2038_multiple_lines;
static expert_field ei_st2038_truncated;

static const struct true_false_string tfs_c_not_y = {
    "Color-difference channel (C)",
    "Luminance channel (Y)"
};

static bool
all_remaining_bytes_ff(tvbuff_t *tvb, unsigned byte_offset)
{
    unsigned len = tvb_captured_length(tvb);

    for (unsigned i = byte_offset; i < len; i++) {
        if (tvb_get_uint8(tvb, i) != 0xff)
            return false;
    }
    return true;
}

/* SMPTE ST 2038:2021, Sec. 4.2, Table 2 -- ANC data PES payload record syntax. */
static int
dissect_st2038(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    unsigned captured_length = tvb_captured_length(tvb);
    unsigned reported_length = tvb_reported_length(tvb);
    unsigned total_bits = captured_length * 8U;
    unsigned bit_offset = 0;
    unsigned packet_index = 0;
    int first_line = -1;
    proto_item *root_ti;
    proto_item *ti;
    proto_tree *root;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ST 2038");
    col_set_str(pinfo->cinfo, COL_INFO, "SMPTE ST 2038 ANC Data");

    root_ti = proto_tree_add_item(tree, proto_st2038, tvb, 0, -1, ENC_NA);
    root = proto_item_add_subtree(root_ti, ett_st2038);

    if (captured_length < reported_length) {
        expert_add_info_format(pinfo, root_ti, &ei_st2038_truncated,
                               "ST 2038 payload reports %u bytes, but only %u were captured",
                               reported_length, captured_length);
    }

    while (bit_offset < total_bits) {
        unsigned start_bit;
        unsigned reserved;
        unsigned line_number;
        uint16_t did_word, second_word, dc_word;
        uint8_t did, sdid_or_dbn;
        bool type1;
        unsigned data_count;
        unsigned required_bits;
        unsigned align_bits;
        unsigned udw_start_bit;
        unsigned udw_start_byte;
        unsigned udw_octet_length;
        uint16_t cs_calc;
        st291_vanc_packet_t anc;
        proto_item *packet_ti, *cs_ti, *udw_ti;
        proto_tree *packet_tree, *udw_tree;

        /* At a compliant record boundary, 0xff can only be trailing stuffing. */
        if ((bit_offset & 7U) == 0 && bit_offset + 8 <= total_bits &&
            tvb_get_uint8(tvb, bit_offset / 8) == 0xff) {
            unsigned byte_offset = bit_offset / 8;
            unsigned remaining = captured_length - byte_offset;

            if (all_remaining_bytes_ff(tvb, byte_offset)) {
                proto_tree_add_item(root, hf_st2038_stuffing_bytes, tvb,
                                    byte_offset, remaining, ENC_NA);
                bit_offset = total_bits;
                break;
            }

            /*
             * Interoperability workaround also used by libklvanc: some
             * encoders insert extra '1' bits between ANC records even when
             * Table 2 requires no alignment bits at an already byte-aligned
             * boundary. Skip them until the next record's leading zero and
             * flag the stream as non-conformant.
             */
            {
                unsigned stuff_start = bit_offset;
                while (bit_offset < total_bits &&
                       tvb_get_bits8(tvb, bit_offset, 1) == 1)
                    bit_offset++;

                if (bit_offset > stuff_start) {
                    unsigned skipped = bit_offset - stuff_start;
                    unsigned shown = MIN(skipped, 64U);
                    ti = proto_tree_add_bits_item(root,
                        hf_st2038_alignment_bits, tvb, stuff_start,
                        shown, ENC_BIG_ENDIAN);
                    if (skipped > shown)
                        proto_item_append_text(ti, " (showing first %u of %u bits)",
                                               shown, skipped);
                    expert_add_info(pinfo, ti, &ei_st2038_nonstandard_stuffing);
                }
            }

            if (bit_offset >= total_bits)
                break;
        }

        start_bit = bit_offset;
        required_bits = 6 + 1 + 11 + 12 + 10 + 10 + 10 + 10;
        if (total_bits - bit_offset < required_bits) {
            expert_add_info(pinfo, root_ti, &ei_st2038_truncated);
            break;
        }

        reserved = tvb_get_bits8(tvb, bit_offset, 6);
        bit_offset += 6;
        bit_offset += 1;
        line_number = tvb_get_bits16(tvb, bit_offset, 11, ENC_BIG_ENDIAN);
        bit_offset += 11;
        bit_offset += 12;
        if (!st291_vanc_packet_from_packed(tvb, pinfo, bit_offset,
                                           total_bits - bit_offset, &anc)) {
            expert_add_info(pinfo, root_ti, &ei_st2038_truncated);
            break;
        }

        did_word = anc.words[0];
        second_word = anc.words[1];
        dc_word = anc.words[2];
        did = anc.did;
        sdid_or_dbn = anc.sdid_or_dbn;
        type1 = (did & 0x80U) != 0;
        data_count = anc.data_count;

        packet_ti = proto_tree_add_none_format(root, hf_st2038_anc_packet,
            tvb, start_bit / 8,
            (70U + data_count * 10U + 7U) / 8U,
            "ANC Packet %u: line %u, DID 0x%02x, %s 0x%02x",
            packet_index + 1, line_number, did,
            type1 ? "DBN" : "SDID", sdid_or_dbn);
        st291_append_packet_description(packet_ti, did, sdid_or_dbn);
        packet_tree = proto_item_add_subtree(packet_ti, ett_st2038_anc_packet);

        proto_tree_add_bits_item(packet_tree, hf_st2038_reserved, tvb,
                                 start_bit, 6, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(packet_tree, hf_st2038_c_not_y, tvb,
                                 start_bit + 6, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(packet_tree, hf_st2038_line_number, tvb,
                                 start_bit + 7, 11, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(packet_tree, hf_st2038_horizontal_offset, tvb,
                                 start_bit + 18, 12, ENC_BIG_ENDIAN);

        st291_tree_add_did(packet_tree, tvb, (start_bit + 30) / 8, 2, did);
        if (type1)
            st291_tree_add_dbn(packet_tree, tvb, (start_bit + 40) / 8, 2, sdid_or_dbn);
        else
            st291_tree_add_sdid(packet_tree, tvb, (start_bit + 40) / 8, 2, did, sdid_or_dbn);

        proto_tree_add_bits_item(packet_tree, hf_st2038_data_count, tvb,
                                 start_bit + 50, 10, ENC_BIG_ENDIAN);

        if (reserved != 0)
            expert_add_info_format(pinfo, packet_ti, &ei_st2038_reserved,
                                   "Reserved six-bit field is 0x%x, expected 0", reserved);

        if (!anc.did_parity_ok)
            expert_add_info_format(pinfo, packet_ti, &ei_st2038_bad_parity,
                                   "Invalid ST 291 DID parity/inverse bits (raw word 0x%03x); decoding bits 7..0",
                                   did_word);
        if (!anc.second_word_parity_ok)
            expert_add_info_format(pinfo, packet_ti, &ei_st2038_bad_parity,
                                   "Invalid ST 291 %s parity/inverse bits (raw word 0x%03x); decoding bits 7..0",
                                   type1 ? "DBN" : "SDID", second_word);
        if (!anc.data_count_parity_ok)
            expert_add_info_format(pinfo, packet_ti, &ei_st2038_bad_parity,
                                   "Invalid ST 291 data-count parity/inverse bits (raw word 0x%03x); decoding bits 7..0",
                                   dc_word);

        if (first_line < 0)
            first_line = (int)line_number;
        else if ((unsigned)first_line != line_number)
            expert_add_info_format(pinfo, packet_ti, &ei_st2038_multiple_lines,
                                   "ST 2038 requires one raster line per PES packet; first ANC packet used line %d",
                                   first_line);

        /*
         * Mirror the ST 2110-40 presentation: show the octets touched by
         * the packed 10-bit UDW bitstream as one item, rather than adding
         * one protocol-tree row for every individual UDW.  The generated
         * byte-oriented UDW Array below remains the public subdissector
         * payload (bits b7..b0 from each 10-bit word).
         */
        udw_start_bit = start_bit + 60U;
        if (data_count > 0) {
            udw_start_byte = udw_start_bit / 8U;
            udw_octet_length = ((udw_start_bit & 7U) + data_count * 10U + 7U) / 8U;
            ti = proto_tree_add_item(packet_tree, hf_st2038_udw_bytes, tvb,
                                     udw_start_byte, udw_octet_length, ENC_NA);
            proto_item_set_hidden(ti);
        }

        bit_offset = start_bit + 30U + (3U + data_count) * 10U;
        cs_ti = proto_tree_add_bits_item(packet_tree, hf_st2038_checksum, tvb,
                                         bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;

        cs_calc = anc.checksum_calculated;

        ti = proto_tree_add_uint(packet_tree,
            hf_st2038_checksum_calculated, tvb, 0, 0, cs_calc);
        proto_item_set_generated(ti);

        if (!anc.checksum_ok)
            expert_add_info(pinfo, cs_ti, &ei_st2038_bad_checksum);

        /* Table 2 requires '1' bits until the next byte boundary. */
        align_bits = (8U - (bit_offset & 7U)) & 7U;
        if (align_bits != 0) {
            uint8_t alignment;

            if (total_bits - bit_offset < align_bits) {
                expert_add_info(pinfo, packet_ti, &ei_st2038_truncated);
                break;
            }

            alignment = tvb_get_bits8(tvb, bit_offset, align_bits);
            ti = proto_tree_add_bits_item(packet_tree,
                hf_st2038_alignment_bits, tvb, bit_offset, align_bits,
                ENC_BIG_ENDIAN);
            if (alignment != ((1U << align_bits) - 1U))
                expert_add_info(pinfo, ti, &ei_st2038_bad_alignment);
            bit_offset += align_bits;
        }

        if (data_count > 0) {
            udw_ti = proto_tree_add_item(packet_tree, hf_st2038_udw_array,
                                         anc.packed_udw_tvb, 0,
                                         tvb_captured_length(anc.packed_udw_tvb),
                                         ENC_NA);
        } else {
            udw_ti = proto_tree_add_item(packet_tree, hf_st2038_udw_array,
                                         tvb, bit_offset / 8U, 0, ENC_NA);
            proto_item_set_generated(udw_ti);
        }
        udw_tree = proto_item_add_subtree(udw_ti, ett_st2038_udw);

        {
            st291_vanc_dissector_data_t st291_data = {
                .top_tree = tree,
                .payload_index = packet_index,
            };
            st291_vanc_dissect_packet(&anc, pinfo, udw_tree, udw_ti,
                                      &st291_data);
        }

        packet_index++;
    }

    /*
     * Generated convenience field: number of complete ANC records parsed
     * from this ST 2038 PES payload.  This is not an on-wire ST 2038 field.
     * Keeping the field present even when the value is zero makes filters
     * such as "st2038.anc_count == 0" useful.
     */
    ti = proto_tree_add_uint(root, hf_st2038_anc_count, tvb, 0, 0, packet_index);
    proto_item_set_generated(ti);

    col_add_fstr(pinfo->cinfo, COL_INFO, "SMPTE ST 2038 ANC Data, %u ANC packet%s",
                 packet_index, packet_index == 1 ? "" : "s");

    return tvb_captured_length(tvb);
}

void
proto_register_st2038(void)
{
    static hf_register_info hf[] = {
        { &hf_st2038_anc_packet,
          { "ANC Packet", "st2038.anc_packet", FT_NONE, BASE_NONE,
            NULL, 0, NULL, HFILL } },
        { &hf_st2038_anc_count,
          { "ANC Packet Count", "st2038.anc_count", FT_UINT32, BASE_DEC,
            NULL, 0, "Number of complete ANC packets in this PES payload", HFILL } },
        { &hf_st2038_reserved,
          { "Reserved", "st2038.reserved", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL } },
        { &hf_st2038_c_not_y,
          { "C/Y Channel", "st2038.c_not_y", FT_BOOLEAN, BASE_NONE,
            TFS(&tfs_c_not_y), 0, NULL, HFILL } },
        { &hf_st2038_line_number,
          { "Line Number", "st2038.line_number", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL } },
        { &hf_st2038_horizontal_offset,
          { "Horizontal Offset", "st2038.horizontal_offset", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL } },
        { &hf_st2038_data_count,
          { "Data Count Word", "st2038.data_count", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL } },
        { &hf_st2038_udw_bytes,
          { "UDW Bytes", "st2038.udw", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL } },
        { &hf_st2038_udw_array,
          { "User Data Words", "st2038.udw_array", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL } },
        { &hf_st2038_checksum,
          { "Checksum Word", "st2038.checksum", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL } },
        { &hf_st2038_checksum_calculated,
          { "Calculated Checksum", "st2038.checksum_calculated", FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL } },
        { &hf_st2038_alignment_bits,
          { "Alignment / Stuffing Bits", "st2038.alignment_bits", FT_UINT64, BASE_HEX,
            NULL, 0, NULL, HFILL } },
        { &hf_st2038_stuffing_bytes,
          { "Stuffing Bytes", "st2038.stuffing_bytes", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL } },
    };

    static int *ett[] = {
        &ett_st2038,
        &ett_st2038_anc_packet,
        &ett_st2038_udw,
    };

    static ei_register_info ei[] = {
        { &ei_st2038_reserved,
          { "st2038.reserved.nonzero", PI_PROTOCOL, PI_WARN,
            "Reserved bits are non-zero", EXPFILL } },
        { &ei_st2038_bad_parity,
          { "st2038.st291_parity_bad", PI_CHECKSUM, PI_WARN,
            "Invalid ST 291 parity/inverse bits", EXPFILL } },
        { &ei_st2038_bad_checksum,
          { "st2038.checksum.bad", PI_CHECKSUM, PI_WARN,
            "ST 291 checksum does not match", EXPFILL } },
        { &ei_st2038_bad_alignment,
          { "st2038.alignment.bad", PI_MALFORMED, PI_WARN,
            "ST 2038 alignment bits must be one", EXPFILL } },
        { &ei_st2038_nonstandard_stuffing,
          { "st2038.inter_record_stuffing", PI_PROTOCOL, PI_WARN,
            "Non-standard inter-record stuffing bits accepted for interoperability",
            EXPFILL } },
        { &ei_st2038_multiple_lines,
          { "st2038.multiple_lines", PI_PROTOCOL, PI_WARN,
            "One ST 2038 PES packet contains ANC data from multiple raster lines",
            EXPFILL } },
        { &ei_st2038_truncated,
          { "st2038.truncated", PI_MALFORMED, PI_WARN,
            "Truncated ST 2038 ANC record", EXPFILL } },
    };

    expert_module_t *expert;

    proto_st2038 = proto_register_protocol(
        "SMPTE ST 2038 Ancillary Data in MPEG-2 TS", "ST 2038", "st2038");
    proto_register_field_array(proto_st2038, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert = expert_register_protocol(proto_st2038);
    expert_register_field_array(expert, ei, array_length(ei));

    st2038_handle = register_dissector("st2038", dissect_st2038, proto_st2038);
}

void
proto_reg_handoff_st2038(void)
{
    dissector_add_uint("mpeg-pes.registration", ST2038_REGISTRATION_ID,
                       st2038_handle);
}

/*
 * Editor modelines - https://www.wireshark.org/tools/modelines.html
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
