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
#include <epan/packet.h>
#include <epan/to_str.h>
#include <wiretap/wtap.h>

void proto_reg_handoff_alp(void);
void proto_register_alp(void);

static int proto_alp;
static int ett_alp;
static int ett_alp_si;
static int ett_alp_he;
static int ett_alp_sig_info;
static int ett_alp_lmt;
static int ett_alp_lmt_plp;
static int ett_alp_lmt_plp_mc;

static dissector_handle_t alp_handle;
static dissector_handle_t ip_handle;
static dissector_handle_t ts_handle;

static int hf_alp_packet_type;
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

static int hf_alp_mpegts_numts;
static int hf_alp_mpegts_ahf;
static int hf_alp_mpegts_hdm;
static int hf_alp_mpegts_dnp;
#define ALP_MPEGTS_NUMTS_MASK 0x1E
#define ALP_MPEGTS_AHF_MASK 0x01
#define ALP_MPEGTS_HDM_MASK 0x80
#define ALP_MPEGTS_DNP_MASK 0x7F

static int hf_alp_payload_configuration;
static int hf_alp_header_mode;
static int hf_alp_segmentation_concatenation;
#define ALP_PAYLOAD_CONFIGURATION_MASK 0x10
#define ALP_HEADER_MODE_MASK 0x08
#define ALP_SEGMENTATION_CONCATENATION_MASK 0x08
static const value_string alp_segmentation_concatenation_vals[] = {
    { 0, "Packet segment" },
    { 1, "Concatenated packets" },
    { 0, NULL }
};

static int hf_alp_length;
#define ALP_LENGTH_MASK 0x07FF

static int hf_alp_single_length;
static int hf_alp_single_sif;
static int hf_alp_single_hef;
#define ALP_SINGLE_LENGTH_MASK 0x07FFF8
#define ALP_SINGLE_SIF_MASK 0x02
#define ALP_SINGLE_HEF_MASK 0x01

static int hf_alp_segment_sequence_number;
static int hf_alp_segment_last_indicator;
static int hf_alp_segment_sif;
static int hf_alp_segment_hef;
#define ALP_SEGMENT_SEQUENCE_NUMBER_MASK 0xF8
#define ALP_SEGMENT_LAST_INDICATOR_MASK 0x04
#define ALP_SEGMENT_SIF_MASK 0x02
#define ALP_SEGMENT_HEF_MASK 0x01

static int hf_alp_concat_length;
static int hf_alp_concat_count;
static int hf_alp_concat_sif;
#define ALP_CONCAT_LENGTH_MASK 0x07FFF0
#define ALP_CONCAT_COUNT_MASK 0x0E
#define ALP_CONCAT_SIF_MASK 0x01

static int hf_alp_si;
static int hf_alp_sid;

static int hf_alp_header_extension;
static int hf_alp_header_extension_type;
static int hf_alp_header_extension_length;

static int hf_alp_header_extension_sony_l1d_timeinfo;
static int hf_alp_header_extension_sony_l1d_timeinfo_flag;
static int hf_alp_header_extension_sony_l1d_timeinfo_sec;
static int hf_alp_header_extension_sony_l1d_timeinfo_ms;
static int hf_alp_header_extension_sony_l1d_timeinfo_us;
static int hf_alp_header_extension_sony_l1d_timeinfo_ns;
static int hf_alp_header_extension_sony_l1d_timeinfo_time;
static int hf_alp_header_extension_sony_l1d_timeinfo_time_ns;
static int hf_alp_header_extension_sony_plp_id;
static int hf_alp_header_extension_sony_plp_unk;
#define ALP_HE_SONY_L1D_TIME_FLAG_MASK 0xC000000000000000
#define ALP_HE_SONY_L1D_TIME_SEC_MASK  0x3FFFFFFFC0000000
#define ALP_HE_SONY_L1D_TIME_MS_MASK   0x000000003FF00000
#define ALP_HE_SONY_L1D_TIME_US_MASK   0x00000000000FFC00
#define ALP_HE_SONY_L1D_TIME_NS_MASK   0x00000000000003FF
#define ALP_HE_SONY_PLP_NUM_MASK 0xFC
#define ALP_HE_SONY_PLP_UNK_MASK 0x03

static int hf_alp_sig_info;
static int hf_alp_sig_info_type;
static int hf_alp_sig_info_type_extension;
static int hf_alp_sig_info_version;
static int hf_alp_sig_info_format;
static int hf_alp_sig_info_encoding;
#define ALP_SIG_INFO_FORMAT_MASK 0xC0
#define ALP_SIG_INFO_ENCODING_MASK 0x30
#define ALP_SIG_INFO_TYPE_LMT 0x01
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

static int hf_alp_lmt;
static int hf_alp_lmt_numplp;
static int hf_alp_lmt_reserved;
static int hf_alp_lmt_plp;
static int hf_alp_lmt_plp_id;
static int hf_alp_lmt_plp_reserved;
static int hf_alp_lmt_plp_nummc;
static int hf_alp_lmt_plp_mc;
static int hf_alp_lmt_plp_mc_src_ip;
static int hf_alp_lmt_plp_mc_dst_ip;
static int hf_alp_lmt_plp_mc_src_port;
static int hf_alp_lmt_plp_mc_dst_port;
static int hf_alp_lmt_plp_mc_sid_flag;
static int hf_alp_lmt_plp_mc_comp_flag;
static int hf_alp_lmt_plp_mc_reserved;
static int hf_alp_lmt_plp_mc_sid;
static int hf_alp_lmt_plp_mc_context_id;

#define ALP_LMT_NUMPLP_MASK 0xFC
#define ALP_LMT_RESERVED_MASK 0x03
#define ALP_LMT_PLP_ID_MASK 0xFC
#define ALP_LMT_PLP_RESERVED_MASK 0x03
#define ALP_LMT_PLP_MC_SID_MASK 0x80
#define ALP_LMT_PLP_MC_COMP_MASK 0x40
#define ALP_LMT_PLP_MC_RESERVED_MASK 0x3F

static int hf_alp_junk;

static int
dissect_alp_mpegts(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, proto_tree *alp_tree)
{
    uint8_t header0 = tvb_get_uint8(tvb, offset);
    uint8_t ahf = header0 & ALP_MPEGTS_AHF_MASK;
    uint8_t numts = (header0 & ALP_MPEGTS_NUMTS_MASK) >> 1;
    if (numts == 0) {
        numts = 16;
    }

    PROTO_ITEM_SET_GENERATED(
        proto_tree_add_uint(alp_tree, hf_alp_mpegts_numts, tvb, offset, 1, numts)
    );
    proto_tree_add_item(alp_tree, hf_alp_mpegts_ahf, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    uint8_t hdm = 0;
    uint8_t dnp = 0;

    if (ahf) {
        uint8_t header1 = tvb_get_uint8(tvb, offset);
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
        unsigned char *ts_frame = (unsigned char*)wmem_alloc(pinfo->pool, 188);

        ts_frame[0] = 0x47;
        ts_frame[1] = 0x1F;
        ts_frame[2] = 0xFF;
        ts_frame[3] = 0x10;
        ts_frame[4] = 0x00;
        memset(ts_frame + 5, 0xFF, 183);

        tvbuff_t *ts_frame_tvb = tvb_new_child_real_data(tvb, ts_frame, 188, 188);
        call_dissector(ts_handle, ts_frame_tvb, pinfo, tree);
    }

    unsigned char *ts_frame = (unsigned char*)wmem_alloc(pinfo->pool, 188);

    ts_frame[0] = 0x47;
    tvb_memcpy(tvb, ts_frame + 1, offset, 187);
    offset += 187;

    unsigned char header[4];
    memcpy(header, ts_frame, 4);

    tvbuff_t *ts_frame_tvb = tvb_new_child_real_data(tvb, ts_frame, 188, 188);
    call_dissector(ts_handle, ts_frame_tvb, pinfo, tree);

    while (--numts) {
        ts_frame = (unsigned char*)wmem_alloc(pinfo->pool, 188);

        if (hdm) {
            header[3] = (header[3] & 0xF0) | ((header[3] + 1) & 0x0F);
            memcpy(ts_frame, header, 4);
            tvb_memcpy(tvb, ts_frame + 4, offset, 184);
            offset += 184;
        } else {
            ts_frame[0] = 0x47;
            tvb_memcpy(tvb, ts_frame + 1, offset, 187);
            offset += 187;
        }

        ts_frame_tvb = tvb_new_child_real_data(tvb, ts_frame, 188, 188);
        call_dissector(ts_handle, ts_frame_tvb, pinfo, tree);
    }

    if (offset < (int)tvb_captured_length(tvb)) {
        int junk_length = tvb_captured_length(tvb) - offset;
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

    int offset = 0;
    uint8_t packet_type = tvb_get_uint8(tvb, offset) >> 5;
    proto_tree_add_item(alp_tree, hf_alp_packet_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    if (packet_type == ALP_PACKET_TYPE_MPEG_TS) {
        return dissect_alp_mpegts(tvb, offset, pinfo, tree, alp_tree);
    }

    bool payload_configuration = (tvb_get_uint8(tvb, offset) & ALP_PAYLOAD_CONFIGURATION_MASK) != 0;
    proto_tree_add_item(alp_tree, hf_alp_payload_configuration, tvb, offset, 1, ENC_BIG_ENDIAN);

    bool sif = false;
    bool hef = false;
    uint16_t payload_length = 0;

    if (payload_configuration == 0) {
        bool header_mode = (tvb_get_uint8(tvb, offset) & ALP_HEADER_MODE_MASK) != 0;
        proto_tree_add_item(alp_tree, hf_alp_header_mode, tvb, offset, 1, ENC_BIG_ENDIAN);

        if (header_mode == 0) {
            payload_length = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN) & ALP_LENGTH_MASK;
            proto_tree_add_item(alp_tree, hf_alp_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        } else {
            payload_length = (tvb_get_uint24(tvb, offset, ENC_BIG_ENDIAN) & ALP_SINGLE_LENGTH_MASK) >> 3;
            proto_tree_add_item(alp_tree, hf_alp_single_length, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 2;

            sif = (tvb_get_uint8(tvb, offset) & ALP_SINGLE_SIF_MASK) != 0;
            hef = (tvb_get_uint8(tvb, offset) & ALP_SINGLE_HEF_MASK) != 0;
            proto_tree_add_item(alp_tree, hf_alp_single_sif, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(alp_tree, hf_alp_single_hef, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
        }
    } else {
        bool segmentation_concatenation = (tvb_get_uint8(tvb, offset) & ALP_SEGMENTATION_CONCATENATION_MASK) != 0;
        proto_tree_add_item(alp_tree, hf_alp_segmentation_concatenation, tvb, offset, 1, ENC_BIG_ENDIAN);

        if (segmentation_concatenation == 0) {
            payload_length = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN) & ALP_LENGTH_MASK;
            proto_tree_add_item(alp_tree, hf_alp_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            sif = (tvb_get_uint8(tvb, offset) & ALP_SEGMENT_SIF_MASK) != 0;
            hef = (tvb_get_uint8(tvb, offset) & ALP_SEGMENT_HEF_MASK) != 0;
            proto_tree_add_item(alp_tree, hf_alp_segment_sequence_number, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(alp_tree, hf_alp_segment_last_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(alp_tree, hf_alp_segment_sif, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(alp_tree, hf_alp_segment_hef, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
        } else {
            payload_length = (tvb_get_uint24(tvb, offset, ENC_BIG_ENDIAN) & ALP_CONCAT_LENGTH_MASK) >> 4;
            proto_tree_add_item(alp_tree, hf_alp_concat_length, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 2;

            uint8_t count = (tvb_get_uint8(tvb, offset) & ALP_CONCAT_COUNT_MASK) >> 1;
            sif = (tvb_get_uint8(tvb, offset) & ALP_CONCAT_SIF_MASK) != 0;
            proto_tree_add_item(alp_tree, hf_alp_concat_count, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(alp_tree, hf_alp_concat_sif, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            uint32_t skip = (uint32_t)count * 12;
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
        uint8_t he_length_m1 = tvb_get_uint8(tvb, offset + 1);
        uint16_t he_length = (uint16_t)he_length_m1 + 1;
        proto_item *he_item = proto_tree_add_item(alp_tree, hf_alp_header_extension, tvb, offset, 2 + he_length, ENC_NA);
        proto_tree *he_tree = proto_item_add_subtree(he_item, ett_alp_he);

        uint8_t he_type = tvb_get_uint8(tvb, offset);

        proto_tree_add_item(he_tree, hf_alp_header_extension_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        PROTO_ITEM_SET_GENERATED(
            proto_tree_add_uint(he_tree, hf_alp_header_extension_length, tvb, offset, 1, he_length)
        );
        offset++;

        if (he_type == 0xF0 && he_length == 8) {
            /* Sony L1D Time Info Extension */
            uint64_t sony_time = tvb_get_uint64(tvb, offset, ENC_BIG_ENDIAN);
            uint64_t sony_sec = (sony_time & ALP_HE_SONY_L1D_TIME_SEC_MASK) >> 30;
            uint64_t sony_ms = (sony_time & ALP_HE_SONY_L1D_TIME_MS_MASK) >> 20;
            uint64_t sony_us = (sony_time & ALP_HE_SONY_L1D_TIME_US_MASK) >> 10;
            uint64_t sony_ns = sony_time & ALP_HE_SONY_L1D_TIME_NS_MASK;
            uint64_t ns_part = sony_ns + sony_us * 1000 + sony_ms * 1000000;
            uint64_t ns_full = ns_part + sony_sec * 1000000000;
            nstime_t abs_time = {
                .secs = (time_t) sony_sec,
                .nsecs = (int) ns_part
            };
            col_add_fstr(pinfo->cinfo, COL_INFO, "Sony L1D TAI Time: %s (%" PRIu64 ")",
                abs_time_to_str(pinfo->pool, &abs_time, ABSOLUTE_TIME_UTC, false), ns_full);

            proto_tree_add_item(he_tree, hf_alp_header_extension_sony_l1d_timeinfo, tvb, offset, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(he_tree, hf_alp_header_extension_sony_l1d_timeinfo_flag, tvb, offset, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(he_tree, hf_alp_header_extension_sony_l1d_timeinfo_sec, tvb, offset, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(he_tree, hf_alp_header_extension_sony_l1d_timeinfo_ms, tvb, offset, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(he_tree, hf_alp_header_extension_sony_l1d_timeinfo_us, tvb, offset, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(he_tree, hf_alp_header_extension_sony_l1d_timeinfo_ns, tvb, offset, 8, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(
                proto_tree_add_time(he_tree, hf_alp_header_extension_sony_l1d_timeinfo_time, tvb, offset, 8, &abs_time)
            );
            PROTO_ITEM_SET_GENERATED(
                proto_tree_add_uint64(he_tree, hf_alp_header_extension_sony_l1d_timeinfo_time_ns, tvb, offset, 8, ns_full)
            );
            offset += 8;
        } else if (he_type == 0xF1 && he_length == 1) {
            /* Sony PLP Extension */
            col_add_fstr(pinfo->cinfo, COL_INFO, "Sony PLP Extension: PLP %u", (tvb_get_uint8(tvb, offset) & ALP_HE_SONY_PLP_NUM_MASK) >> 2);
            proto_tree_add_item(he_tree, hf_alp_header_extension_sony_plp_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(he_tree, hf_alp_header_extension_sony_plp_unk, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
        } else {
            tvbuff_t *he_data_tvb = tvb_new_subset_length(tvb, offset, he_length);
            call_data_dissector(he_data_tvb, pinfo, he_tree);
            offset += he_length;
        }
    }

    if (packet_type == ALP_PACKET_TYPE_SIGNALLING) {
        proto_item *sig_info_item = proto_tree_add_item(alp_tree, hf_alp_sig_info, tvb, offset, 5, ENC_NA);
        proto_tree *sig_info_tree = proto_item_add_subtree(sig_info_item, ett_alp_sig_info);

        uint8_t sig_info_type = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(sig_info_tree, hf_alp_sig_info_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(sig_info_tree, hf_alp_sig_info_type_extension, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(sig_info_tree, hf_alp_sig_info_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(sig_info_tree, hf_alp_sig_info_format, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sig_info_tree, hf_alp_sig_info_encoding, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        if (sig_info_type == ALP_SIG_INFO_TYPE_LMT) {
            proto_item *lmt_item = proto_tree_add_item(alp_tree, hf_alp_lmt, tvb, offset, payload_length, ENC_NA);
            proto_tree *lmt_tree = proto_item_add_subtree(lmt_item, ett_alp_lmt);

            uint8_t lmt_numplp = ((tvb_get_uint8(tvb, offset) & ALP_LMT_NUMPLP_MASK) >> 2) + 1;
            col_add_fstr(pinfo->cinfo, COL_INFO, "Link Mapping Table, number of PLPs: %u", lmt_numplp);
            PROTO_ITEM_SET_GENERATED(
                proto_tree_add_uint(lmt_tree, hf_alp_lmt_numplp, tvb, offset, 1, lmt_numplp)
            );
            proto_tree_add_item(lmt_tree, hf_alp_lmt_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            for(uint8_t i = 0; i < lmt_numplp; i++) {
                /* Fist pass. Calculate PLP entry length */
                int lmt_plp_length = 2;
                uint8_t lmt_mc_nummc = tvb_get_uint8(tvb, offset + 1);
                int plp_mc_len = 0;
                for(uint8_t j = 0; j < lmt_mc_nummc; j++) {
                    uint8_t lmt_mc_plp_flags = tvb_get_uint8(tvb, offset + 2 + plp_mc_len + 12);
                    plp_mc_len += 13;
                    uint8_t lmt_mc_plp_sid_flag = lmt_mc_plp_flags & ALP_LMT_PLP_MC_SID_MASK;
                    uint8_t lmt_mc_plp_comp_flag = lmt_mc_plp_flags & ALP_LMT_PLP_MC_COMP_MASK;
                    if (lmt_mc_plp_sid_flag) {
                        plp_mc_len += 1;
                    }
                    if (lmt_mc_plp_comp_flag) {
                        plp_mc_len += 1;
                    }
                }
                lmt_plp_length += plp_mc_len;

                /* Second pass. Add PLP to the tree */
                proto_item *lmt_plp_item = proto_tree_add_item(lmt_tree, hf_alp_lmt_plp, tvb, offset, lmt_plp_length, ENC_NA);
                proto_tree *lmt_plp_tree = proto_item_add_subtree(lmt_plp_item, ett_alp_lmt_plp);

                uint8_t lmt_plp_id = (tvb_get_uint8(tvb, offset) & ALP_LMT_PLP_ID_MASK) >> 2;
                proto_item_append_text(lmt_plp_item, " ID=%u", lmt_plp_id);

                proto_tree_add_item(lmt_plp_tree, hf_alp_lmt_plp_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(lmt_plp_tree, hf_alp_lmt_plp_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;

                proto_tree_add_item(lmt_plp_tree, hf_alp_lmt_plp_nummc, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;

                for(uint8_t j = 0; j < lmt_mc_nummc; j++) {
                    int mc_len = 13;
                    uint8_t lmt_mc_plp_flags = tvb_get_uint8(tvb, offset + 12);
                    uint8_t lmt_mc_plp_sid_flag = lmt_mc_plp_flags & ALP_LMT_PLP_MC_SID_MASK;
                    uint8_t lmt_mc_plp_comp_flag = lmt_mc_plp_flags & ALP_LMT_PLP_MC_COMP_MASK;
                    if (lmt_mc_plp_sid_flag) {
                        mc_len += 1;
                    }
                    if (lmt_mc_plp_comp_flag) {
                        mc_len += 1;
                    }

                    proto_item *lmt_plp_mc_item = proto_tree_add_item(lmt_plp_tree, hf_alp_lmt_plp_mc, tvb, offset, mc_len, ENC_NA);
                    proto_item_append_text(lmt_plp_mc_item, " (%u) Dst=%s:%u", j, tvb_ip_to_str(pinfo->pool, tvb, offset + 4), tvb_get_uint16(tvb, offset + 10, ENC_BIG_ENDIAN));
                    proto_tree *lmt_plp_mc_tree = proto_item_add_subtree(lmt_plp_mc_item, ett_alp_lmt_plp_mc);

                    proto_tree_add_item(lmt_plp_mc_tree, hf_alp_lmt_plp_mc_src_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;

                    proto_tree_add_item(lmt_plp_mc_tree, hf_alp_lmt_plp_mc_dst_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;

                    proto_tree_add_item(lmt_plp_mc_tree, hf_alp_lmt_plp_mc_src_port, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    proto_tree_add_item(lmt_plp_mc_tree, hf_alp_lmt_plp_mc_dst_port, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    proto_tree_add_item(lmt_plp_mc_tree, hf_alp_lmt_plp_mc_sid_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(lmt_plp_mc_tree, hf_alp_lmt_plp_mc_comp_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(lmt_plp_mc_tree, hf_alp_lmt_plp_mc_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;

                    if (lmt_mc_plp_sid_flag) {
                        proto_tree_add_item(lmt_plp_mc_tree, hf_alp_lmt_plp_mc_sid, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                    }
                    if (lmt_mc_plp_comp_flag) {
                        proto_tree_add_item(lmt_plp_mc_tree, hf_alp_lmt_plp_mc_context_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;
                    }
                }
            }
        }
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

    if (offset < (int)tvb_captured_length(tvb)) {
        int junk_length = tvb_captured_length(tvb) - offset;
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

        { &hf_alp_header_extension_sony_l1d_timeinfo, {
            "Sony L1D Time Info Extension Raw", "alp.he.sony_l1d_timeinfo",
            FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_header_extension_sony_l1d_timeinfo_flag, {
            "Sony L1D Time Info Flag", "alp.he.sony_l1d_timeinfo.flag",
            FT_UINT64, BASE_HEX, NULL, ALP_HE_SONY_L1D_TIME_FLAG_MASK, NULL, HFILL
        } },
        { &hf_alp_header_extension_sony_l1d_timeinfo_sec, {
            "Sony L1D Time Info Seconds", "alp.he.sony_l1d_timeinfo.sec",
            FT_UINT64, BASE_DEC, NULL, ALP_HE_SONY_L1D_TIME_SEC_MASK, NULL, HFILL
        } },
        { &hf_alp_header_extension_sony_l1d_timeinfo_ms, {
            "Sony L1D Time Info Milliseconds", "alp.he.sony_l1d_timeinfo.ms",
            FT_UINT64, BASE_DEC, NULL, ALP_HE_SONY_L1D_TIME_MS_MASK, NULL, HFILL
        } },
        { &hf_alp_header_extension_sony_l1d_timeinfo_us, {
            "Sony L1D Time Info Microseconds", "alp.he.sony_l1d_timeinfo.us",
            FT_UINT64, BASE_DEC, NULL, ALP_HE_SONY_L1D_TIME_US_MASK, NULL, HFILL
        } },
        { &hf_alp_header_extension_sony_l1d_timeinfo_ns, {
            "Sony L1D Time Info Nanoseconds", "alp.he.sony_l1d_timeinfo.ns",
            FT_UINT64, BASE_DEC, NULL, ALP_HE_SONY_L1D_TIME_NS_MASK, NULL, HFILL
        } },
        { &hf_alp_header_extension_sony_l1d_timeinfo_time, {
            "Sony L1D Time Info TAI Time", "alp.he.sony_l1d_timeinfo.time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_header_extension_sony_l1d_timeinfo_time_ns, {
            "Sony L1D Time Info TAI Time (ns)", "alp.he.sony_l1d_timeinfo.time_ns",
            FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_alp_header_extension_sony_plp_id, {
            "Sony PLP Extension PLP ID", "alp.he.sony_plp.id",
            FT_UINT8, BASE_DEC, NULL, ALP_HE_SONY_PLP_NUM_MASK, NULL, HFILL
        } },
        { &hf_alp_header_extension_sony_plp_unk, {
            "Sony PLP Extension Unknown Bits", "alp.he.sony_plp.unknown",
            FT_UINT8, BASE_HEX, NULL, ALP_HE_SONY_PLP_UNK_MASK, NULL, HFILL
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

        { &hf_alp_lmt, {
            "Link Mapping Table", "alp.lmt",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_lmt_numplp, {
            "Number of PLPs", "alp.lmt.numplp",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_lmt_reserved, {
            "Reserved", "alp.lmt.reserved",
            FT_UINT8, BASE_HEX, NULL, ALP_LMT_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_alp_lmt_plp, {
            "PLP", "alp.plp",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_lmt_plp_id, {
            "PLP ID", "alp.plp.id",
            FT_UINT8, BASE_DEC, NULL, ALP_LMT_PLP_ID_MASK, NULL, HFILL
        } },
        { &hf_alp_lmt_plp_reserved, {
            "Reserved", "alp.plp.reserved",
            FT_UINT8, BASE_HEX, NULL, ALP_LMT_PLP_RESERVED_MASK, NULL, HFILL
        } },
        { &hf_alp_lmt_plp_nummc, {
            "Number of Multicast Entries", "alp.plp.nummc",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_lmt_plp_mc, {
            "Multicast Entry", "alp.plp.mc",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_lmt_plp_mc_src_ip, {
            "Source IP", "alp.plp.mc.src_ip",
            FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_lmt_plp_mc_dst_ip, {
            "Destination IP", "alp.plp.mc.dst_ip",
            FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_lmt_plp_mc_src_port, {
            "Source Port", "alp.plp.mc.src_port",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_lmt_plp_mc_dst_port, {
            "Destination IP", "alp.plp.mc.dst_port",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_lmt_plp_mc_sid_flag, {
            "SID Flag", "alp.plp.mc.sid_flag",
            FT_UINT8, BASE_DEC, NULL, ALP_LMT_PLP_MC_SID_MASK, NULL, HFILL
        } },
        { &hf_alp_lmt_plp_mc_comp_flag, {
            "Compressed Flag", "alp.plp.mc.comp_flag",
            FT_UINT8, BASE_DEC, NULL, ALP_LMT_PLP_MC_COMP_MASK, NULL, HFILL
        } },
        { &hf_alp_lmt_plp_mc_reserved, {
            "Reserved", "alp.plp.mc.reserved",
            FT_UINT8, BASE_HEX, NULL, ALP_LMT_PLP_MC_RESERVED_MASK, NULL, HFILL
        } },
        { &hf_alp_lmt_plp_mc_sid, {
            "Reserved", "alp.plp.mc.sid",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        { &hf_alp_lmt_plp_mc_context_id, {
            "Reserved", "alp.plp.mc.context_id",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_alp_junk, {
            "Junk", "alp.junk",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
    };

    static int *ett[] = {
        &ett_alp,
        &ett_alp_si,
        &ett_alp_he,
        &ett_alp_sig_info,
        &ett_alp_lmt,
        &ett_alp_lmt_plp,
        &ett_alp_lmt_plp_mc,
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
