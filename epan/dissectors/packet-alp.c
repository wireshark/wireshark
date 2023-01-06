/* packet-alp.c
 * Routines for ALP dissection
 * Copyright 2020, Nick Kelsey <nickk@silicondust.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * ATSC Link-Layer Protocol (A/330)
 * https://www.atsc.org/atsc-30-standard/a3302016-link-layer-protocol/
 */

#include <config.h>
#include <stdbool.h>
#include <epan/packet.h>

void proto_reg_handoff_alp(void);
void proto_register_alp(void);

static int proto_alp = -1;
static gint ett_alp = -1;
static gint ett_alp_si = -1;
static gint ett_alp_he = -1;
static gint ett_alp_sig_info = -1;

static dissector_handle_t alp_handle;
static dissector_handle_t ip_handle;
static dissector_handle_t ts_handle;

static int hf_alp_packet_type = -1;
#define ALP_PACKET_TYPE_MASK 0xE0
#define ALP_PACKET_TYPE_IPV4 0
#define ALP_PACKET_TYPE_SIGNALLING 4
#define ALP_PACKET_TYPE_MPEG_TS 7
static const value_string alp_packet_type_vals[] = {
    { 0, "IPv4 packet" },
    { 1, "Reserved" },
    { 2, "Compressed IPv4 packet" },
    { 3, "Reserved" },
    { 4, "Link layer signalling packet" },
    { 5, "Reserved" },
    { 6, "Packet type extension" },
    { 7, "MPEG-2 transport stream" },
    { 0, NULL }
};

static int hf_alp_mpegts_numts = -1;
static int hf_alp_mpegts_ahf = -1;
static int hf_alp_mpegts_hdm = -1;
static int hf_alp_mpegts_dnp = -1;
#define ALP_MPEGTS_NUMTS_MASK 0x1E
#define ALP_MPEGTS_AHF_MASK 0x01
#define ALP_MPEGTS_HDM_MASK 0x80
#define ALP_MPEGTS_DNP_MASK 0x7F

static int hf_alp_payload_configuration = -1;
static int hf_alp_header_mode = -1;
static int hf_alp_segmentation_concatenation = -1;
#define ALP_PAYLOAD_CONFIGURATION_MASK 0x10
#define ALP_HEADER_MODE_MASK 0x08
#define ALP_SEGMENTATION_CONCATENATION_MASK 0x08
static const value_string alp_segmentation_concatenation_vals[] = {
    { 0, "Packet segment" },
    { 1, "Concatenated packets" },
    { 0, NULL }
};

static int hf_alp_length = -1;
#define ALP_LENGTH_MASK 0x07FF

static int hf_alp_single_length = -1;
static int hf_alp_single_sif = -1;
static int hf_alp_single_hef = -1;
#define ALP_SINGLE_LENGTH_MASK 0x07FFF8
#define ALP_SINGLE_SIF_MASK 0x02
#define ALP_SINGLE_HEF_MASK 0x01

static int hf_alp_segment_sequence_number = -1;
static int hf_alp_segment_last_indicator = -1;
static int hf_alp_segment_sif = -1;
static int hf_alp_segment_hef = -1;
#define ALP_SEGMENT_SEQUENCE_NUMBER_MASK 0xF8
#define ALP_SEGMENT_LAST_INDICATOR_MASK 0x04
#define ALP_SEGMENT_SIF_MASK 0x02
#define ALP_SEGMENT_HEF_MASK 0x01

static int hf_alp_concat_length = -1;
static int hf_alp_concat_count = -1;
static int hf_alp_concat_sif = -1;
#define ALP_CONCAT_LENGTH_MASK 0x07FFF0
#define ALP_CONCAT_COUNT_MASK 0x0E
#define ALP_CONCAT_SIF_MASK 0x01

static int hf_alp_si = -1;
static int hf_alp_sid = -1;

static int hf_alp_header_extension = -1;
static int hf_alp_header_extension_type = -1;
static int hf_alp_header_extension_length = -1;

static int hf_alp_sig_info = -1;
static int hf_alp_sig_info_type = -1;
static int hf_alp_sig_info_type_extension = -1;
static int hf_alp_sig_info_version = -1;
static int hf_alp_sig_info_format = -1;
static int hf_alp_sig_info_encoding = -1;
#define ALP_SIG_INFO_FORMAT_MASK 0xC0
#define ALP_SIG_INFO_ENCODING_MASK 0x30
static const value_string alp_sig_info_type_vals[] = {
    { 0x01, "Link Mapping Table" },
    { 0x02, "ROHC-U Description Table" },
    { 0, NULL }
};
static const value_string alp_sig_info_format_vals[] = {
    { 0, "Binary" },
    { 1, "XML" },
    { 2, "JSON" },
    { 3, "Reserved" },
    { 0, NULL }
};
static const value_string alp_sig_info_encoding_vals[] = {
    { 0, "No Compression" },
    { 1, "DEFLATE" },
    { 2, "Reserved" },
    { 3, "Reserved" },
    { 0, NULL }
};

static int hf_alp_junk = -1;

static int
dissect_alp_mpegts(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, proto_tree *alp_tree)
{
    guint8 header0 = tvb_get_guint8(tvb, offset);
    guint8 ahf = header0 & ALP_MPEGTS_AHF_MASK;
    guint8 numts = (header0 & ALP_MPEGTS_NUMTS_MASK) >> 1;
    if (numts == 0) {
        numts = 16;
    }

    PROTO_ITEM_SET_GENERATED(
        proto_tree_add_uint(alp_tree, hf_alp_mpegts_numts, tvb, offset, 1, numts)
    );
    proto_tree_add_item(alp_tree, hf_alp_mpegts_ahf, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    guint8 hdm = 0;
    guint8 dnp = 0;

    if (ahf) {
        guint8 header1 = tvb_get_guint8(tvb, offset);
        hdm = header1 & ALP_MPEGTS_HDM_MASK;
        dnp = header1 & ALP_MPEGTS_DNP_MASK;
        if ((hdm == 0) && (dnp == 0)) {
            dnp = 128;
        }

        proto_tree_add_item(alp_tree, hf_alp_mpegts_hdm, tvb, offset, 1, ENC_BIG_ENDIAN);
        PROTO_ITEM_SET_GENERATED(
            proto_tree_add_uint(alp_tree, hf_alp_mpegts_dnp, tvb, offset, 1, dnp)
        );
        offset++;
    }

    while (dnp--) {
        guchar *ts_frame = (guchar*)wmem_alloc(pinfo->pool, 188);

        ts_frame[0] = 0x47;
        ts_frame[1] = 0x1F;
        ts_frame[2] = 0xFF;
        ts_frame[3] = 0x10;
        ts_frame[4] = 0x00;
        memset(ts_frame + 5, 0xFF, 183);

        tvbuff_t *ts_frame_tvb = tvb_new_child_real_data(tvb, ts_frame, 188, 188);
        call_dissector(ts_handle, ts_frame_tvb, pinfo, tree);
    }

    guchar *ts_frame = (guchar*)wmem_alloc(pinfo->pool, 188);

    ts_frame[0] = 0x47;
    memcpy(ts_frame + 1, tvb_get_ptr(tvb, offset, -1), 187);
    offset += 187;

    guchar header[4];
    memcpy(header, ts_frame, 4);

    tvbuff_t *ts_frame_tvb = tvb_new_child_real_data(tvb, ts_frame, 188, 188);
    call_dissector(ts_handle, ts_frame_tvb, pinfo, tree);

    while (numts--) {
        ts_frame = (guchar*)wmem_alloc(pinfo->pool, 188);

        if (hdm) {
            header[3] = (header[3] & 0xF0) | ((header[3] + 1) & 0x0F);
            memcpy(ts_frame, header, 4);
            memcpy(ts_frame + 4, tvb_get_ptr(tvb, offset, -1), 184);
            offset += 184;
        } else {
            ts_frame[0] = 0x47;
            memcpy(ts_frame + 1, tvb_get_ptr(tvb, offset, -1), 187);
            offset += 187;
        }

        ts_frame_tvb = tvb_new_child_real_data(tvb, ts_frame, 188, 188);
        call_dissector(ts_handle, ts_frame_tvb, pinfo, tree);
    }

    if (offset < (gint)tvb_captured_length(tvb)) {
        gint junk_length = tvb_captured_length(tvb) - offset;
        proto_tree_add_bytes_format(alp_tree, hf_alp_junk, tvb, offset, -1, NULL, "Junk at end (%u byte%s)", junk_length, (junk_length == 1) ? "" : "s");
    }

    return tvb_captured_length(tvb);
}

static int
dissect_alp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ALP");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_alp, tvb, 0, -1, ENC_NA);
    proto_tree *alp_tree = proto_item_add_subtree(ti, ett_alp);

    gint offset = 0;
    guint8 packet_type = tvb_get_guint8(tvb, offset) >> 5;
    proto_tree_add_item(alp_tree, hf_alp_packet_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    if (packet_type == ALP_PACKET_TYPE_MPEG_TS) {
        return dissect_alp_mpegts(tvb, offset, pinfo, tree, alp_tree);
    }

    bool payload_configuration = (tvb_get_guint8(tvb, offset) & ALP_PAYLOAD_CONFIGURATION_MASK) != 0;
    proto_tree_add_item(alp_tree, hf_alp_payload_configuration, tvb, offset, 1, ENC_BIG_ENDIAN);

    bool sif = false;
    bool hef = false;
    guint16 payload_length = 0;

    if (payload_configuration == 0) {
        bool header_mode = (tvb_get_guint8(tvb, offset) & ALP_HEADER_MODE_MASK) != 0;
        proto_tree_add_item(alp_tree, hf_alp_header_mode, tvb, offset, 1, ENC_BIG_ENDIAN);

        if (header_mode == 0) {
            payload_length = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN) & ALP_LENGTH_MASK;
            proto_tree_add_item(alp_tree, hf_alp_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        } else {
            payload_length = (tvb_get_guint24(tvb, offset, ENC_BIG_ENDIAN) & ALP_SINGLE_LENGTH_MASK) >> 3;
            proto_tree_add_item(alp_tree, hf_alp_single_length, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 2;

            sif = (tvb_get_guint8(tvb, offset) & ALP_SINGLE_SIF_MASK) != 0;
            hef = (tvb_get_guint8(tvb, offset) & ALP_SINGLE_HEF_MASK) != 0;
            proto_tree_add_item(alp_tree, hf_alp_single_sif, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(alp_tree, hf_alp_single_hef, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
        }
    } else {
        bool segmentation_concatenation = (tvb_get_guint8(tvb, offset) & ALP_SEGMENTATION_CONCATENATION_MASK) != 0;
        proto_tree_add_item(alp_tree, hf_alp_segmentation_concatenation, tvb, offset, 1, ENC_BIG_ENDIAN);

        if (segmentation_concatenation == 0) {
            payload_length = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN) & ALP_LENGTH_MASK;
            proto_tree_add_item(alp_tree, hf_alp_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            sif = (tvb_get_guint8(tvb, offset) & ALP_SEGMENT_SIF_MASK) != 0;
            hef = (tvb_get_guint8(tvb, offset) & ALP_SEGMENT_HEF_MASK) != 0;
            proto_tree_add_item(alp_tree, hf_alp_segment_sequence_number, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(alp_tree, hf_alp_segment_last_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(alp_tree, hf_alp_segment_sif, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(alp_tree, hf_alp_segment_hef, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
        } else {
            payload_length = (tvb_get_guint24(tvb, offset, ENC_BIG_ENDIAN) & ALP_CONCAT_LENGTH_MASK) >> 4;
            proto_tree_add_item(alp_tree, hf_alp_concat_length, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 2;

            guint8 count = (tvb_get_guint8(tvb, offset) & ALP_CONCAT_COUNT_MASK) >> 1;
            sif = (tvb_get_guint8(tvb, offset) & ALP_CONCAT_SIF_MASK) != 0;
            proto_tree_add_item(alp_tree, hf_alp_concat_count, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(alp_tree, hf_alp_concat_sif, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            guint32 skip = (guint32)count * 12;
            if (count & 0x01) {
                skip += 4;
           }
           offset += skip / 8;
        }
    }

    if (sif) {
        proto_item *si_item = proto_tree_add_item(alp_tree, hf_alp_si, tvb, offset, 1, ENC_NA);
        proto_tree *si_tree = proto_item_add_subtree(si_item, ett_alp_si);

        proto_tree_add_item(si_tree, hf_alp_sid, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    if (hef) {
        guint8 he_length_m1 = tvb_get_guint8(tvb, offset + 1);
        guint16 he_length = (guint16)he_length_m1 + 1;
        proto_item *he_item = proto_tree_add_item(alp_tree, hf_alp_header_extension, tvb, offset, 2 + he_length, ENC_NA);
        proto_tree *he_tree = proto_item_add_subtree(he_item, ett_alp_he);

        proto_tree_add_item(he_tree, hf_alp_header_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        PROTO_ITEM_SET_GENERATED(
            proto_tree_add_uint(he_tree, hf_alp_header_extension_length, tvb, offset, 1, he_length)
        );
        offset++;

        tvbuff_t *he_data_tvb = tvb_new_subset_length(tvb, offset, he_length);
        call_data_dissector(he_data_tvb, pinfo, he_tree);
        offset += he_length;
    }

    if (packet_type == ALP_PACKET_TYPE_SIGNALLING) {
        proto_item *sig_info_item = proto_tree_add_item(alp_tree, hf_alp_sig_info, tvb, offset, 5, ENC_NA);
        proto_tree *sig_info_tree = proto_item_add_subtree(sig_info_item, ett_alp_sig_info);

        proto_tree_add_item(sig_info_tree, hf_alp_sig_info_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(sig_info_tree, hf_alp_sig_info_type_extension, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(sig_info_tree, hf_alp_sig_info_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(sig_info_tree, hf_alp_sig_info_format, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sig_info_tree, hf_alp_sig_info_encoding, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    if (payload_length > 0) {
        tvbuff_t *payload_tvb = tvb_new_subset_length(tvb, offset, payload_length);
        offset += payload_length;

        if ((packet_type == ALP_PACKET_TYPE_IPV4) && (payload_configuration == 0)) {
            call_dissector(ip_handle, payload_tvb, pinfo, tree);
        } else {
            call_data_dissector(payload_tvb, pinfo, tree);
        }
    }

    if (offset < (gint)tvb_captured_length(tvb)) {
        gint junk_length = tvb_captured_length(tvb) - offset;
        proto_tree_add_bytes_format(alp_tree, hf_alp_junk, tvb, offset, -1, NULL, "Junk at end (%u byte%s)", junk_length, (junk_length == 1) ? "" : "s");
    }

    return tvb_captured_length(tvb);
}

void
proto_register_alp(void)
{
    static hf_register_info hf[] = {
        { &hf_alp_packet_type, {
            "Packet Type", "alp.type",
            FT_UINT8, BASE_DEC, VALS(alp_packet_type_vals), ALP_PACKET_TYPE_MASK, NULL, HFILL
        } },

        { &hf_alp_mpegts_numts, {
            "Number of TS packets", "alp.numts",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_mpegts_ahf, {
            "Additional Header Flag", "alp.ahf",
            FT_UINT8, BASE_DEC, NULL, ALP_MPEGTS_AHF_MASK, NULL, HFILL
        } },
        { &hf_alp_mpegts_hdm, {
            "Header Deletion Mode", "alp.hdm",
            FT_UINT8, BASE_DEC, NULL, ALP_MPEGTS_HDM_MASK, NULL, HFILL
        } },
        { &hf_alp_mpegts_dnp, {
            "Deleted Null Packets", "alp.dnp",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_alp_payload_configuration, {
            "Payload Configuration", "alp.pc",
            FT_UINT8, BASE_DEC, NULL, ALP_PAYLOAD_CONFIGURATION_MASK, NULL, HFILL
        } },
        { &hf_alp_header_mode, {
            "Header Mode", "alp.hm",
            FT_UINT8, BASE_DEC, NULL, ALP_HEADER_MODE_MASK, NULL, HFILL
        } },
        { &hf_alp_segmentation_concatenation, {
            "Segmentation Concatenation", "alp.sc",
            FT_UINT8, BASE_DEC, VALS(alp_segmentation_concatenation_vals), ALP_SEGMENTATION_CONCATENATION_MASK, NULL, HFILL
        } },

        { &hf_alp_length, {
            "Length", "alp.length",
            FT_UINT16, BASE_DEC, NULL, ALP_LENGTH_MASK, NULL, HFILL
        } },

        { &hf_alp_single_length, {
            "Length", "alp.length",
            FT_UINT24, BASE_DEC, NULL, ALP_SINGLE_LENGTH_MASK, NULL, HFILL
        } },
        { &hf_alp_single_sif, {
            "Sub-stream Identifier Flag", "alp.sif",
            FT_UINT8, BASE_DEC, NULL, ALP_SINGLE_SIF_MASK, NULL, HFILL
        } },
        { &hf_alp_single_hef, {
            "Header Extension Flag", "alp.hef",
            FT_UINT8, BASE_DEC, NULL, ALP_SINGLE_HEF_MASK, NULL, HFILL
        } },

        { &hf_alp_segment_sequence_number, {
            "Segment Sequence Number", "alp.ssn",
            FT_UINT8, BASE_DEC, NULL, ALP_SEGMENT_SEQUENCE_NUMBER_MASK, NULL, HFILL
        } },
        { &hf_alp_segment_last_indicator, {
            "Last Segment Indicator", "alp.lsi",
            FT_UINT8, BASE_DEC, NULL, ALP_SEGMENT_LAST_INDICATOR_MASK, NULL, HFILL
        } },
        { &hf_alp_segment_sif, {
            "Sub-stream Identifier Flag", "alp.sif",
            FT_UINT8, BASE_DEC, NULL, ALP_SEGMENT_SIF_MASK, NULL, HFILL
        } },
        { &hf_alp_segment_hef, {
            "Header Extension Flag", "alp.hef",
            FT_UINT8, BASE_DEC, NULL, ALP_SEGMENT_HEF_MASK, NULL, HFILL
        } },

        { &hf_alp_concat_length, {
            "Length", "alp.length",
            FT_UINT24, BASE_DEC, NULL, ALP_CONCAT_LENGTH_MASK, NULL, HFILL
        } },
        { &hf_alp_concat_count, {
            "Concatenation Count", "alp.cc",
            FT_UINT8, BASE_DEC, NULL, ALP_CONCAT_COUNT_MASK, NULL, HFILL
        } },
        { &hf_alp_concat_sif, {
            "Sub-stream Identifier Flag", "alp.sif",
            FT_UINT8, BASE_DEC, NULL, ALP_CONCAT_SIF_MASK, NULL, HFILL
        } },

        { &hf_alp_si, {
            "Sub-stream Identification", "alp.si",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_sid, {
            "Sub-stream Identifier", "alp.si_sid",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_alp_header_extension, {
            "Header Extension", "alp.he",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_header_extension_type, {
            "Header Extension Type", "alp.he.type",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_header_extension_length, {
            "Header Extension Length", "alp.he.length",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0, NULL, HFILL
        } },

        { &hf_alp_sig_info, {
            "Signalling Information Header", "alp.sih",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_sig_info_type, {
            "Signalling Type", "alp.sih_type",
            FT_UINT8, BASE_HEX, VALS(alp_sig_info_type_vals), 0, NULL, HFILL
        } },
        { &hf_alp_sig_info_type_extension, {
            "Signalling Type Extension", "alp.sih_type_ext",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_sig_info_version, {
            "Signalling Version", "alp.sih_version",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_sig_info_format, {
            "Signalling Format", "alp.sih_format",
            FT_UINT8, BASE_DEC, VALS(alp_sig_info_format_vals), ALP_SIG_INFO_FORMAT_MASK, NULL, HFILL
        } },
        { &hf_alp_sig_info_encoding, {
            "Signalling Encoding", "alp.sih_encoding",
            FT_UINT8, BASE_DEC, VALS(alp_sig_info_encoding_vals), ALP_SIG_INFO_ENCODING_MASK, NULL, HFILL
        } },

        { &hf_alp_junk, {
            "Junk", "alp.junk",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
    };

    static gint *ett[] = {
        &ett_alp,
        &ett_alp_si,
        &ett_alp_he,
        &ett_alp_sig_info,
    };

    proto_alp = proto_register_protocol("ATSC Link-Layer Protocol", "ALP", "alp");
    proto_register_field_array(proto_alp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_alp(void)
{
    alp_handle = create_dissector_handle(dissect_alp, proto_alp);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_ATSC_ALP, alp_handle);

    ip_handle = find_dissector("ip");
    ts_handle = find_dissector("mp2t");
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
