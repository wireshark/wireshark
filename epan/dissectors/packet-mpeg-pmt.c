/* packet-mpeg-pmt.c
 * Routines for MPEG2 (ISO/ISO 13818-1) Program Map Table (PMT) dissection
 * Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-mp2t.h"
#include "packet-mpeg-sect.h"
#include "packet-mpeg-descriptor.h"

void proto_register_mpeg_pmt(void);
void proto_reg_handoff_mpeg_pmt(void);

static int proto_mpeg_pmt;
static int hf_mpeg_pmt_program_number;
static int hf_mpeg_pmt_reserved1;
static int hf_mpeg_pmt_version_number;
static int hf_mpeg_pmt_current_next_indicator;
static int hf_mpeg_pmt_section_number;
static int hf_mpeg_pmt_last_section_number;
static int hf_mpeg_pmt_reserved2;
static int hf_mpeg_pmt_pcr_pid;
static int hf_mpeg_pmt_reserved3;
static int hf_mpeg_pmt_program_info_length;


static int hf_mpeg_pmt_stream_type;
static int hf_mpeg_pmt_stream_reserved1;
static int hf_mpeg_pmt_stream_elementary_pid;
static int hf_mpeg_pmt_stream_reserved2;
static int hf_mpeg_pmt_stream_es_info_length;

static int ett_mpeg_pmt;
static int ett_mpeg_pmt_stream;

static dissector_handle_t mpeg_pmt_handle;

#define MPEG_PMT_RESERVED1_MASK                   0xC0
#define MPEG_PMT_VERSION_NUMBER_MASK              0x3E
#define MPEG_PMT_CURRENT_NEXT_INDICATOR_MASK      0x01

#define MPEG_PMT_RESERVED2_MASK                 0xE000
#define MPEG_PMT_PCR_PID_MASK                   0x1FFF
#define MPEG_PMT_RESERVED3_MASK                 0xF000
#define MPEG_PMT_PROGRAM_INFO_LENGTH_MASK       0x0FFF

#define MPEG_PMT_STREAM_RESERVED1_MASK          0xE000
#define MPEG_PMT_STREAM_ELEMENTARY_PID_MASK     0x1FFF

#define MPEG_PMT_STREAM_RESERVED2_MASK          0xF000
#define MPEG_PMT_STREAM_ES_INFO_LENGTH_MASK     0x0FFF


static const value_string mpeg_pmt_stream_type_vals[] = {
    { 0x00, "ITU-T | ISO/IEC Reserved" },
    { 0x01, "ISO/IEC 11172 Video" },
    { 0x02, "ITU-T Rec. H.262 | ISO/IEC 13818-2 Video or ISO/IEC 11172-2 constrained parameter video stream" },
    { 0x03, "ISO/IEC 11172 Audio" },
    { 0x04, "ISO/IEC 13818-3 Audio" },
    { 0x05, "ITU-T Rec. H.222.0 | ISO/IEC 13818-1 private_sections" },
    { 0x06, "ITU-T Rec. H.222.0 | ISO/IEC 13818-1 PES packets containing private data" },
    { 0x07, "ISO/IEC 13522 MHEG" },
    { 0x08, "ITU-T Rec. H.222.0 | ISO/IEC 13818-1 Annex A DSM-CC" },
    { 0x09, "ITU-T Rec. H.222.1" },
    { 0x0A, "ISO/IEC 13818-6 type A" },
    { 0x0B, "ISO/IEC 13818-6 type B" },
    { 0x0C, "ISO/IEC 13818-6 type C" },
    { 0x0D, "ISO/IEC 13818-6 type D" },
    { 0x0E, "ITU-T Rec. H.222.0 | ISO/IEC 13818-1 auxiliary" },
    { 0x0F, "ISO/IEC 13818-7 Audio with ADTS transport syntax" },
    { 0x10, "ISO/IEC 14496-2 Visual" },
    { 0x11, "ISO/IEC 14496-3 Audio with the LATM transport syntax as defined in ISO/IEC 14496-3 / AMD 1" },
    { 0x12, "ISO/IEC 14496-1 SL-packetized stream or FlexMux stream carried in PES packets" },
    { 0x13, "ISO/IEC 14496-1 SL-packetized stream or FlexMux stream carried in ISO/IEC14496_sections" },
    { 0x14, "ISO/IEC 13818-6 Synchronized Download Protocol" },
    { 0x15, "Metadata carried in PES packets" },
    { 0x16, "Metadata carried in metadata sections" },
    { 0x17, "Metadata carried in ISO/IEC 13818-6 Data Carousel" },
    { 0x18, "Metadata carried in ISO/IEC 13818-6 Object Carousel" },
    { 0x19, "Metadata carried in ISO/IEC 13818-6 Synchronized Download Protocol" },
    { 0x1A, "IPMP stream (defined in ISO/IEC 13818-11, MPEG-2 IPMP)" },
    { 0x1B, "AVC video stream as defined in ITU-T Rec. H.264 | ISO/IEC 14496-10 Video" },
    { 0x24, "ITU-T Rec. H.265 and ISO/IEC 23008-2 (Ultra HD video) in a packetized stream" },
    { 0x7F, "IPMP stream" },
    { 0x81, "ATSC A/52 Audio" },
    { 0x86, "SCTE-35 Splice Information" },
    { 0xA1, "ETV-AM BIF Data Stream" },
    { 0xC0, "ETV-AM EISS Signaling" },
    { 0x00, NULL }
};
value_string_ext mpeg_pmt_stream_type_vals_ext = VALUE_STRING_EXT_INIT(mpeg_pmt_stream_type_vals);

static int
dissect_mpeg_pmt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    unsigned   offset = 0, length = 0;
    unsigned   prog_info_len, es_info_len;
    uint32_t stream_type;
    uint16_t pid;
    bool current;

    proto_item *ti;
    proto_tree *mpeg_pmt_tree;
    proto_tree *mpeg_pmt_stream_tree;

    /* The TVB should start right after the section_length in the Section packet */

    col_set_str(pinfo->cinfo, COL_INFO, "Program Map Table (PMT)");

    ti = proto_tree_add_item(tree, proto_mpeg_pmt, tvb, offset, -1, ENC_NA);
    mpeg_pmt_tree = proto_item_add_subtree(ti, ett_mpeg_pmt);

    offset += packet_mpeg_sect_header(tvb, offset, mpeg_pmt_tree, &length, NULL);
    length -= 4;

    proto_tree_add_item(mpeg_pmt_tree, hf_mpeg_pmt_program_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(mpeg_pmt_tree, hf_mpeg_pmt_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(mpeg_pmt_tree, hf_mpeg_pmt_version_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_boolean(mpeg_pmt_tree, hf_mpeg_pmt_current_next_indicator, tvb, offset, 1, ENC_BIG_ENDIAN, &current);
    offset += 1;

    proto_tree_add_item(mpeg_pmt_tree, hf_mpeg_pmt_section_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(mpeg_pmt_tree, hf_mpeg_pmt_last_section_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(mpeg_pmt_tree, hf_mpeg_pmt_reserved2, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(mpeg_pmt_tree, hf_mpeg_pmt_pcr_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    prog_info_len = tvb_get_ntohs(tvb, offset) & MPEG_PMT_PROGRAM_INFO_LENGTH_MASK;
    proto_tree_add_item(mpeg_pmt_tree, hf_mpeg_pmt_reserved3, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(mpeg_pmt_tree, hf_mpeg_pmt_program_info_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    offset += proto_mpeg_descriptor_loop_dissect(tvb, offset, prog_info_len, mpeg_pmt_tree);

    while (offset < length) {

        pid = tvb_get_ntohs(tvb, offset + 1) & MPEG_PMT_STREAM_ELEMENTARY_PID_MASK;
        es_info_len = tvb_get_ntohs(tvb, offset + 3) & MPEG_PMT_STREAM_ES_INFO_LENGTH_MASK;

        mpeg_pmt_stream_tree = proto_tree_add_subtree_format(mpeg_pmt_tree, tvb, offset, 5 + es_info_len,
                            ett_mpeg_pmt_stream, NULL, "Stream PID=0x%04hx", pid);

        proto_tree_add_item_ret_uint(mpeg_pmt_stream_tree, hf_mpeg_pmt_stream_type,      tvb, offset, 1, ENC_BIG_ENDIAN, &stream_type);
        if (current) {
            mp2t_add_stream_type(pinfo, pid, stream_type);
        }
        offset += 1;

        proto_tree_add_item(mpeg_pmt_stream_tree, hf_mpeg_pmt_stream_reserved1,     tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(mpeg_pmt_stream_tree, hf_mpeg_pmt_stream_elementary_pid,    tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(mpeg_pmt_stream_tree, hf_mpeg_pmt_stream_reserved2,     tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(mpeg_pmt_stream_tree, hf_mpeg_pmt_stream_es_info_length,    tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        offset += proto_mpeg_descriptor_loop_dissect(tvb, offset, es_info_len, mpeg_pmt_stream_tree);
    }

    offset += packet_mpeg_sect_crc(tvb, pinfo, mpeg_pmt_tree, 0, offset);

    proto_item_set_len(ti, offset);
    return offset;
}


void
proto_register_mpeg_pmt(void)
{

    static hf_register_info hf[] = {

        { &hf_mpeg_pmt_program_number, {
            "Program Number", "mpeg_pmt.pg_num",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_pmt_reserved1, {
            "Reserved", "mpeg_pmt.reserved1",
            FT_UINT8, BASE_HEX, NULL, MPEG_PMT_RESERVED1_MASK, NULL, HFILL
        } },

        { &hf_mpeg_pmt_version_number, {
            "Version Number", "mpeg_pmt.version",
            FT_UINT8, BASE_HEX, NULL, MPEG_PMT_VERSION_NUMBER_MASK, NULL, HFILL
        } },

        { &hf_mpeg_pmt_current_next_indicator, {
            "Current/Next Indicator", "mpeg_pmt.cur_next_ind",
            FT_BOOLEAN, 8, TFS(&tfs_current_not_yet), MPEG_PMT_CURRENT_NEXT_INDICATOR_MASK, NULL, HFILL
        } },

        { &hf_mpeg_pmt_section_number, {
            "Section Number", "mpeg_pmt.sect_num",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_pmt_last_section_number, {
            "Last Section Number", "mpeg_pmt.last_sect_num",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_mpeg_pmt_reserved2, {
            "Reserved", "mpeg_pmt.reserved2",
            FT_UINT16, BASE_HEX, NULL, MPEG_PMT_RESERVED2_MASK, NULL, HFILL
        } },

        { &hf_mpeg_pmt_pcr_pid, {
            "PCR PID", "mpeg_pmt.pcr_pid",
            FT_UINT16, BASE_HEX, NULL, MPEG_PMT_PCR_PID_MASK, NULL, HFILL
        } },

        { &hf_mpeg_pmt_reserved3, {
            "Reserved", "mpeg_pmt.reserved3",
            FT_UINT16, BASE_HEX, NULL, MPEG_PMT_RESERVED3_MASK, NULL, HFILL
        } },

        { &hf_mpeg_pmt_program_info_length, {
            "Program Info Length", "mpeg_pmt.prog_info_len",
            FT_UINT16, BASE_DEC, NULL, MPEG_PMT_PROGRAM_INFO_LENGTH_MASK, NULL, HFILL
        } },


        { &hf_mpeg_pmt_stream_type, {
            "Stream type", "mpeg_pmt.stream.type",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mpeg_pmt_stream_type_vals_ext, 0, NULL, HFILL
        } },

        { &hf_mpeg_pmt_stream_reserved1, {
            "Reserved", "mpeg_pmt.stream.reserved1",
            FT_UINT16, BASE_HEX, NULL, MPEG_PMT_STREAM_RESERVED1_MASK, NULL, HFILL
        } },

        { &hf_mpeg_pmt_stream_elementary_pid, {
            "Elementary PID", "mpeg_pmt.stream.elementary_pid",
            FT_UINT16, BASE_HEX, NULL, MPEG_PMT_STREAM_ELEMENTARY_PID_MASK, NULL, HFILL
        } },

        { &hf_mpeg_pmt_stream_reserved2, {
            "Reserved", "mpeg_pmt.stream.reserved2",
            FT_UINT16, BASE_HEX, NULL, MPEG_PMT_STREAM_RESERVED2_MASK, NULL, HFILL
        } },

        { &hf_mpeg_pmt_stream_es_info_length, {
            "ES Info Length", "mpeg_pmt.stream.es_info_len",
            FT_UINT16, BASE_DEC, NULL, MPEG_PMT_STREAM_ES_INFO_LENGTH_MASK, NULL, HFILL
        } },

    };

    static int *ett[] = {
        &ett_mpeg_pmt,
        &ett_mpeg_pmt_stream,
    };

    proto_mpeg_pmt = proto_register_protocol("MPEG2 Program Map Table", "MPEG PMT", "mpeg_pmt");

    proto_register_field_array(proto_mpeg_pmt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    mpeg_pmt_handle = register_dissector("mpeg_pmt", dissect_mpeg_pmt, proto_mpeg_pmt);
}


void
proto_reg_handoff_mpeg_pmt(void)
{
    dissector_add_uint("mpeg_sect.tid", MPEG_PMT_TID, mpeg_pmt_handle);
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
