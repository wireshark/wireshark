/* packet-smpte-2110-40.c
 * SMPTE ST 2110-40:2018, "Professional Media Over Managed IP Networks:
 * SMPTE ST 291-1 Ancillary Data," using the RTP payload syntax defined by
 * IETF RFC 8331, "RTP Payload for SMPTE ST 291-1 Ancillary Data."
 *
 * This dissector is heavily derived from the NEOAdvancedTechnology Lua
 * dissector by Thomas Edwards <thomas.edwards@disney.com> distributed
 * under the GPL v2 (or later).
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

#include <string.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/tfs.h>

#include "packet-smpte-291-vanc.h"

#define ST2110_40_RTP_NAME "smpte291"

static const struct true_false_string tfs_c_y = {
    "C:Color-difference", "Y:Luma"
};

static const struct true_false_string tfs_stream_num = {
    "StreamNum used", "StreamNum not used"
};


static int proto_st2110_40;

static int hf_st2110_40_esn;
static int hf_st2110_40_length;
static int hf_st2110_40_anc_count;
static int hf_st2110_40_field;
static int hf_st2110_40_c;
static int hf_st2110_40_data_count;
static int hf_st2110_40_line_number;
static int hf_st2110_40_horizontal_offset;
static int hf_st2110_40_s;
static int hf_st2110_40_stream_num;
static int hf_st2110_40_udw;
static int hf_st2110_40_udw_array;
static int hf_st2110_40_checksum;
static int hf_st2110_40_checksum_calc;

static int hf_st2110_40_anc_packet;

static int ett_st2110_40;
static int ett_st2110_40_anc_packet;
static int ett_st2110_40_udw;

static expert_field ei_st2110_40_bad_checksum = EI_INIT;
static expert_field ei_st2110_40_bad_length = EI_INIT;
static expert_field ei_st2110_40_truncated = EI_INIT;
static expert_field ei_st2110_40_bad_reserved = EI_INIT;
static expert_field ei_st2110_40_bad_field = EI_INIT;
static expert_field ei_st2110_40_bad_parity = EI_INIT;
static expert_field ei_st2110_40_bad_word_align = EI_INIT;
static expert_field ei_st2110_40_bad_sdid = EI_INIT;

static dissector_handle_t st2110_40_handle;

static const value_string st2110_40_field_vals[] = {
    { 0, "unspecified or progressive scan" },
    { 1, "not valid" },
    { 2, "Field 1" },
    { 3, "Field 2" },
    { 0, NULL }
};

static const char *
line_number_desc(uint16_t v)
{
    switch (v) {
    case 0x7ff: return "Without specific line location within the field or frame";
    case 0x7fe: return "Line between 2nd line after RP 168 switch line to the last line before active video";
    case 0x7fd: return "Line number larger than can be represented in 11 bits";
    default: return NULL;
    }
}

static const char *
horizontal_offset_desc(uint16_t v)
{
    switch (v) {
    case 0xfff: return "Without specific horizontal location";
    case 0xffe: return "Horizontal ancillary data space (HANC)";
    case 0xffd: return "Between SAV and EAV";
    case 0xffc: return "Horizontal offset is larger than can be represented in 12 bits";
    default: return NULL;
    }
}


/* SMPTE ST 2110-40:2018, Sec. 5.2; IETF RFC 8331, Sec. 2 -- RTP ANC payload syntax. */
static int
dissect_st2110_40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    unsigned captured = tvb_captured_length(tvb);
    unsigned claimed_length, packet_total, payload_end, anc_count, offset = 8, i;
    unsigned parsed_anc_count = 0;
    unsigned field_value;
    uint32_t reserved;
    proto_item *root_ti;
    proto_item *ti;
    proto_tree *root;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ST 2110-40");
    col_set_str(pinfo->cinfo, COL_INFO, "SMPTE ST 2110-40 ANC Data");

    if (captured < 8)
        return 0;

    claimed_length = tvb_get_ntohs(tvb, 2);
    packet_total = claimed_length + 8;
    payload_end = MIN(packet_total, captured);


    root_ti = proto_tree_add_item(tree, proto_st2110_40, tvb, 0, payload_end, ENC_NA);
    root = proto_item_add_subtree(root_ti, ett_st2110_40);

    proto_tree_add_item(root, hf_st2110_40_esn, tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(root, hf_st2110_40_length, tvb, 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(root, hf_st2110_40_anc_count, tvb, 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(root, hf_st2110_40_field, tvb, 5, 1, ENC_BIG_ENDIAN);

    anc_count = tvb_get_uint8(tvb, 4);
    field_value = tvb_get_bits8(tvb, 5 * 8, 2);
    reserved = tvb_get_bits32(tvb, 5 * 8 + 2, 22, ENC_BIG_ENDIAN);

    if (packet_total > captured) {
        expert_add_info_format(pinfo, root_ti, &ei_st2110_40_bad_length,
                               "ST 2110-40 payload claims %u bytes, but only %u were captured",
                               packet_total, captured);
    }

    if (anc_count == 0 && claimed_length != 0) {
        expert_add_info_format(pinfo, root_ti, &ei_st2110_40_bad_length,
                               "ANC_Count is zero, but Length is %u (RFC 8331 requires Length=0)",
                               claimed_length);
    } else if (anc_count != 0 && claimed_length == 0) {
        expert_add_info_format(pinfo, root_ti, &ei_st2110_40_bad_length,
                               "ANC_Count is %u, but Length is zero", anc_count);
    }

    if (field_value == 1) {
        expert_add_info(pinfo, root_ti, &ei_st2110_40_bad_field);
    }

    if (reserved != 0) {
        expert_add_info_format(pinfo, root_ti, &ei_st2110_40_bad_reserved,
                               "The 22 reserved RTP payload-header bits are non-zero (0x%x)",
                               reserved);
    }

    for (i = 0; i < anc_count; i++) {
        unsigned data_count, packet_len, udw_length, checksum_offset;
        unsigned content_bits, align_bits;
        uint8_t did, sdid_or_dbn;
        bool type1;
        uint16_t did_word, second_word, dc_word;
        uint16_t line_number, horiz_offset;
        uint16_t cs_received, cs_calc;
        st291_vanc_packet_t anc;
        proto_item *packet_ti, *cs_ti, *tree_data_ti;
        proto_tree *packet_tree, *tree_data;
        const char *desc;

        if (offset + 8 > payload_end) {
            expert_add_info(pinfo, root_ti, &ei_st2110_40_truncated);
            break;
        }

        if (!st291_vanc_packet_from_packed(tvb, pinfo, (offset + 4) * 8,
                                           (payload_end - offset - 4) * 8,
                                           &anc)) {
            if (anc.word_count != 0) {
                expert_add_info_format(pinfo, root_ti, &ei_st2110_40_truncated,
                                       "ANC packet %u extends past the RFC 8331 Length boundary",
                                       i + 1);
            } else {
                expert_add_info_format(pinfo, root_ti, &ei_st2110_40_truncated,
                                       "ANC packet %u contains a truncated ST 291 header",
                                       i + 1);
            }
            break;
        }

        did_word = anc.words[0];
        second_word = anc.words[1];
        dc_word = anc.words[2];

        did = anc.did;
        sdid_or_dbn = anc.sdid_or_dbn;
        type1 = (did & 0x80U) != 0;
        data_count = anc.data_count;

        packet_len = ((72 + data_count * 10 + 31) / 32) * 4;
        if (offset + packet_len > payload_end) {
            expert_add_info_format(pinfo, root_ti, &ei_st2110_40_truncated,
                                   "ANC packet %u extends past the RFC 8331 Length boundary",
                                   i + 1);
            break;
        }

        packet_ti = proto_tree_add_none_format(root, hf_st2110_40_anc_packet, tvb, offset, packet_len,
                                               "Packet %u", i + 1);
        packet_tree = proto_item_add_subtree(packet_ti, ett_st2110_40_anc_packet);

        proto_tree_add_item(packet_tree, hf_st2110_40_c, tvb, offset, 1, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(packet_tree, hf_st2110_40_line_number, tvb, offset, 2, ENC_BIG_ENDIAN);
        line_number = tvb_get_bits16(tvb, offset * 8 + 1, 11, ENC_BIG_ENDIAN);
        desc = line_number_desc(line_number);
        if (desc)
            proto_item_append_text(ti, ": %s", desc);

        ti = proto_tree_add_item(packet_tree, hf_st2110_40_horizontal_offset, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
        horiz_offset = tvb_get_bits16(tvb, (offset + 1) * 8 + 4, 12, ENC_BIG_ENDIAN);
        desc = horizontal_offset_desc(horiz_offset);
        if (desc)
            proto_item_append_text(ti, ": %s", desc);
        proto_tree_add_item(packet_tree, hf_st2110_40_s, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(packet_tree, hf_st2110_40_stream_num, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
        st291_tree_add_did(packet_tree, tvb, offset + 4, 2, did);
        if (type1)
            st291_tree_add_dbn(packet_tree, tvb, offset + 5, 2, sdid_or_dbn);
        else
            st291_tree_add_sdid(packet_tree, tvb, offset + 5, 2, did, sdid_or_dbn);
        proto_tree_add_item(packet_tree, hf_st2110_40_data_count, tvb, offset + 6, 2, ENC_BIG_ENDIAN);

        if (type1)
            proto_item_append_text(packet_ti, ": DID 0x%02x, DBN 0x%02x", did, sdid_or_dbn);
        else
            proto_item_append_text(packet_ti, ": DID 0x%02x, SDID 0x%02x", did, sdid_or_dbn);

        st291_append_packet_description(packet_ti, did, sdid_or_dbn);


        if (!anc.did_parity_ok)
            expert_add_info_format(pinfo, packet_ti, &ei_st2110_40_bad_parity,
                                   "Invalid ST 291 DID parity (raw word 0x%03x)", did_word);
        if (!anc.second_word_parity_ok)
            expert_add_info_format(pinfo, packet_ti, &ei_st2110_40_bad_parity,
                                   "Invalid ST 291 %s parity (raw word 0x%03x)",
                                   type1 ? "DBN" : "SDID", second_word);
        if (!anc.data_count_parity_ok)
            expert_add_info_format(pinfo, packet_ti, &ei_st2110_40_bad_parity,
                                   "Invalid ST 291 DC parity (raw word 0x%03x)", dc_word);

        if (!type1 && sdid_or_dbn == 0) {
            expert_add_info(pinfo, packet_ti, &ei_st2110_40_bad_sdid);
        }

        /*
         * Preserve the original packed-byte filter field without a duplicate
         * visible tree entry. The
         * first UDW begins six bits into tvb[offset+7].  For DC=0 there
         * are no UDW bits at all.
         */
        if (data_count > 0) {
            udw_length = (6 + data_count * 10 + 7) / 8;
            if (offset + 7 + udw_length <= payload_end) {
                ti = proto_tree_add_item(packet_tree, hf_st2110_40_udw, tvb, offset + 7, udw_length, ENC_NA);
                proto_item_set_hidden(ti);
            }
        }

        cs_received = anc.checksum;
        checksum_offset = (unsigned)(((uint64_t)(offset + 4) * 8 +
                                      (3U + data_count) * 10) / 8);
        cs_ti = proto_tree_add_uint_format_value(packet_tree, hf_st2110_40_checksum,
                                                 tvb, checksum_offset, 2,
                                                 cs_received, "0x%03x", cs_received);
        cs_calc = anc.checksum_calculated;
        ti = proto_tree_add_uint_format_value(packet_tree, hf_st2110_40_checksum_calc,
                                              tvb, checksum_offset, 0,
                                              cs_calc, "0x%03x", cs_calc);
        proto_item_set_generated(ti);
        if (!anc.checksum_ok)
            expert_add_info(pinfo, cs_ti, &ei_st2110_40_bad_checksum);

        /*
         * RFC 8331 requires zero-valued word_align bits after every ANC
         * packet, including the final packet.
         */
        content_bits = 72 + data_count * 10;
        align_bits = packet_len * 8 - content_bits;
        if (align_bits > 0 && tvb_get_bits32(tvb, offset * 8 + content_bits, align_bits, ENC_BIG_ENDIAN) != 0) {
            expert_add_info_format(pinfo, packet_ti, &ei_st2110_40_bad_word_align,
                                   "%u word_align bit%s must be zero",
                                   align_bits, align_bits == 1 ? "" : "s");
        }

        if (data_count > 0) {
            tree_data_ti = proto_tree_add_item(packet_tree, hf_st2110_40_udw_array,
                                               anc.packed_udw_tvb, 0,
                                               tvb_captured_length(anc.packed_udw_tvb),
                                               ENC_NA);
            tree_data = proto_item_add_subtree(tree_data_ti, ett_st2110_40_udw);
        } else {
            /* Preserve the existing empty generated field without adding an
             * empty Packet Bytes data source. */
            tree_data_ti = proto_tree_add_item(packet_tree, hf_st2110_40_udw_array,
                                               tvb, offset + 7, 0, ENC_NA);
            proto_item_set_generated(tree_data_ti);
            tree_data = proto_item_add_subtree(tree_data_ti, ett_st2110_40_udw);
        }

        {
            st291_vanc_dissector_data_t st291_data = {
                .top_tree = tree,
                .payload_index = i,
            };

            st291_vanc_dissect_packet(&anc, pinfo, tree_data, tree_data_ti,
                                      &st291_data);
        }

        parsed_anc_count++;
        offset += packet_len;
    }

    col_add_fstr(pinfo->cinfo, COL_INFO,
                 "SMPTE ST 2110-40 ANC Data, %u ANC packet%s",
                 parsed_anc_count, parsed_anc_count == 1 ? "" : "s");

    if (packet_total <= captured && offset != packet_total) {
        expert_add_info_format(pinfo, root_ti, &ei_st2110_40_bad_length,
                               "Length is %u bytes, but ANC_Count=%u accounts for %u bytes",
                               claimed_length, anc_count, offset >= 8 ? offset - 8 : 0);
    }

    return captured;
}

void
proto_register_st2110_40(void)
{
    static hf_register_info hf[] = {
        { &hf_st2110_40_esn, { "Extended Sequence Number", "st2110_40.extendedsequencenumber", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_st2110_40_length, { "Length", "st2110_40.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_st2110_40_anc_count, { "ANC Count", "st2110_40.anc_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_st2110_40_field, { "(F)ield", "st2110_40.f", FT_UINT8, BASE_HEX, VALS(st2110_40_field_vals), 0xC0, NULL, HFILL } },
        { &hf_st2110_40_c, { "(C) or Y", "st2110_40.c", FT_BOOLEAN, 8, TFS(&tfs_c_y), 0x80, NULL, HFILL } },
        { &hf_st2110_40_data_count, { "Data Count", "st2110_40.data_count", FT_UINT16, BASE_DEC, NULL, 0x03FC, NULL, HFILL } },
        { &hf_st2110_40_line_number, { "Line Number", "st2110_40.line_number", FT_UINT16, BASE_DEC, NULL, 0x7FF0, NULL, HFILL } },
        { &hf_st2110_40_horizontal_offset, { "Horizontal Offset", "st2110_40.ho", FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL } },
        { &hf_st2110_40_s, { "S", "st2110_40.s", FT_BOOLEAN, 8, TFS(&tfs_stream_num), 0x80, NULL, HFILL } },
        { &hf_st2110_40_stream_num, { "Stream Number", "st2110_40.streamnum", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL } },
        { &hf_st2110_40_udw, { "UDW Bytes", "st2110_40.udw", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_st2110_40_udw_array, { "User Data Words", "st2110_40.udw_array", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_st2110_40_checksum, { "Checksum Word", "st2110_40.checksum", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_st2110_40_checksum_calc, { "Calculated Checksum", "st2110_40.checksum_calculated", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },

        { &hf_st2110_40_anc_packet, { "ANC Packet", "st2110_40.anc_packet", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    static int *ett[] = {
        &ett_st2110_40,
        &ett_st2110_40_anc_packet,
        &ett_st2110_40_udw,
    };

    static ei_register_info ei[] = {
        { &ei_st2110_40_bad_checksum,
          { "st2110_40.checksum.bad", PI_CHECKSUM, PI_WARN,
            "The calculated ANC checksum and ANC checksum word do not match", EXPFILL } },
        { &ei_st2110_40_bad_length,
          { "st2110_40.length.bad", PI_MALFORMED, PI_WARN,
            "Invalid ST 2110-40 payload length", EXPFILL } },
        { &ei_st2110_40_truncated,
          { "st2110_40.truncated", PI_MALFORMED, PI_WARN,
            "Truncated ST 2110-40 ANC packet", EXPFILL } },
        { &ei_st2110_40_bad_reserved,
          { "st2110_40.reserved.nonzero", PI_PROTOCOL, PI_WARN,
            "Reserved bits are non-zero", EXPFILL } },
        { &ei_st2110_40_bad_field,
          { "st2110_40.field.invalid", PI_PROTOCOL, PI_WARN,
            "F field value 1 is invalid", EXPFILL } },
        { &ei_st2110_40_bad_parity,
          { "st2110_40.st291_parity_bad", PI_CHECKSUM, PI_WARN,
            "Invalid ST 291 parity", EXPFILL } },
        { &ei_st2110_40_bad_word_align,
          { "st2110_40.word_align.nonzero", PI_MALFORMED, PI_WARN,
            "RFC 8331 word_align bits are non-zero", EXPFILL } },
        { &ei_st2110_40_bad_sdid,
          { "st2110_40.st291_sdid_reserved", PI_PROTOCOL, PI_WARN,
            "SDID 0x00 is reserved for Type 2 ANC packets", EXPFILL } },
    };

    expert_module_t *expert;

    proto_st2110_40 = proto_register_protocol("SMPTE ST2110-40 (ST291-1 Ancillary Data)", "ST2110-40", "st2110_40");
    proto_register_field_array(proto_st2110_40, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert = expert_register_protocol(proto_st2110_40);
    expert_register_field_array(expert, ei, array_length(ei));

    st2110_40_handle = register_dissector("st2110_40", dissect_st2110_40, proto_st2110_40);
}

void
proto_reg_handoff_st2110_40(void)
{
    /* SDP/RTSP RTP encoding-name lookup. */
    dissector_add_string("rtp_dyn_payload_type", ST2110_40_RTP_NAME, st2110_40_handle);

    dissector_add_uint_range_with_preference("rtp.pt", "", st2110_40_handle);
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
