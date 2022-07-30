/* packet-opus.c
 * Routines for OPUS dissection
 * Copyright 2014, Owen Williams williams.owen@gmail.com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "tvbuff.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <ftypes/ftypes.h>
#include <glibconfig.h>
#include <proto.h>
#include <stdint.h>

#define MAX_FRAMES_COUNT 48

void proto_reg_handoff_opus(void);
void proto_register_opus(void);

static dissector_handle_t opus_handle;

/* Initialize the protocol and registered fields */
static int proto_opus = -1;
static int hf_opus_toc_config = -1;
static int hf_opus_toc_s = -1;
static int hf_opus_toc_c = -1;
static int hf_opus_frame = -1;
static int hf_opus_frame_size = -1;
static int hf_opus_frame_count_v = -1;
static int hf_opus_frame_count_p = -1;
static int hf_opus_frame_count_m = -1;
static int hf_opus_padding = -1;

/* Initialize the subtree pointers */
static gint ett_opus = -1;

static expert_field ei_opus_err_r1 = EI_INIT;
static expert_field ei_opus_err_r2 = EI_INIT;
static expert_field ei_opus_err_r3 = EI_INIT;
static expert_field ei_opus_err_r4 = EI_INIT;
static expert_field ei_opus_err_r5 = EI_INIT;
static expert_field ei_opus_err_r6 = EI_INIT;
static expert_field ei_opus_err_r7 = EI_INIT;

/* From RFC6716 chapter 3.1
 * The top five bits of the TOC byte, labeled "config", encode one of 32
 * possible configurations of operating mode, audio bandwidth, and frame size.
 */
static const value_string opus_codec_toc_config_request_vals[] = {
    {0, "NB, SILK-only ptime=10"},
    {1, "NB, SILK-only ptime=20"},
    {2, "NB, SILK-only ptime=30"},
    {3, "NB, SILK-only ptime=40"},
    {4, "MB, SILK-only ptime=10"},
    {5, "MB, SILK-only ptime=20"},
    {6, "MB, SILK-only ptime=30"},
    {7, "MB, SILK-only ptime=40"},
    {8, "WB, SILK-only ptime=10"},
    {9, "WB, SILK-only ptime=20"},
    {10, "WB, SILK-only ptime=30"},
    {11, "WB, SILK-only ptime=40"},
    {12, "SWB, Hybrid ptime=10"},
    {13, "SWB, Hybrid ptime=20"},
    {14, "FB, Hybrid ptime=10"},
    {15, "FB, Hybrid ptime=20"},
    {16, "NB, CELT-only ptime=2.5"},
    {17, "NB, CELT-only ptime=5"},
    {18, "NB, CELT-only ptime=10"},
    {19, "NB, CELT-only ptime=20"},
    {20, "WB, CELT-only ptime=2.5"},
    {21, "WB, CELT-only ptime=5"},
    {22, "WB, CELT-only ptime=10"},
    {23, "WB, CELT-only ptime=20"},
    {24, "SWB, CELT-only ptime=2.5"},
    {25, "SWB, CELT-only ptime=5"},
    {26, "SWB, CELT-only ptime=10"},
    {27, "SWB, CELT-only ptime=20"},
    {28, "FB, CELT-only ptime=2.5"},
    {29, "FB, CELT-only ptime=5"},
    {30, "FB, CELT-only ptime=10"},
    {31, "FB, CELT-only ptime=20"},
    {0, NULL}};
static value_string_ext opus_codec_toc_config_request_vals_ext
    = VALUE_STRING_EXT_INIT(opus_codec_toc_config_request_vals);

static const true_false_string toc_s_bit_vals = {"stereo", "mono"};
static const true_false_string fc_v_bit_vals = {"VBR", "CBR"};
static const true_false_string fc_p_bit_vals = {"Padding", "No Padding"};

static const value_string opus_codec_toc_c_request_vals[]
    = {{0, "1 frame in the packet"},
       {1, "2 frames in the packet, each with equal compressed size"},
       {2, "2 frames in the packet, with different compressed sizes"},
       {3, "an arbitrary number of frames in the packet"},
       {0, NULL}};
static value_string_ext opus_codec_toc_c_request_vals_ext
    = VALUE_STRING_EXT_INIT(opus_codec_toc_c_request_vals);

static int
parse_size_field(const unsigned char *ch, int32_t cn, int16_t *size)
{
    if (cn < 1) {
        *size = -1;
        return -1;
    }
    else if (ch[0] < 252) {
        *size = ch[0];
        return 1;
    }
    else if (cn < 2) {
        *size = -1;
        return -1;
    }
    else {
        *size = 4 * ch[1] + ch[0];
        return 2;
    }
}

static int16_t
opus_packet_get_samples_per_frame(const unsigned char *data, int16_t Fs)
{
    int audiosize;
    if (data[0] & 0x80) {
        audiosize = ((data[0] >> 3) & 0x3);
        audiosize = (Fs << audiosize) / 400;
    }
    else if ((data[0] & 0x60) == 0x60) {
        audiosize = (data[0] & 0x08) ? Fs / 50 : Fs / 100;
    }
    else {
        audiosize = ((data[0] >> 3) & 0x3);
        if (audiosize == 3)
            audiosize = Fs * 60 / 1000;
        else
            audiosize = (Fs << audiosize) / 100;
    }
    return audiosize;
}

static int
dissect_opus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int idx;

    proto_item *item;
    proto_tree *opus_tree;

    gint pkt_total = 0, offset = 0;
    guint cap_len = 0;
    guint8 ch = 0, toc = 0, octet[2] = {0, 0};
    int octet_cnt = 0;
    int bytes = 0;
    int16_t framesize = 0;
    struct FRAME_T {
        int16_t begin;
        int16_t size;
    } frames[MAX_FRAMES_COUNT] = {{0}};
    int frame_count = 0;
    static int *toc_fields[]
        = {&hf_opus_toc_config, &hf_opus_toc_s, &hf_opus_toc_c, NULL};
    static int *frame_count_fields[]
        = {&hf_opus_frame_count_v, &hf_opus_frame_count_p,
        &hf_opus_frame_count_m, NULL};

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OPUS");

    item = proto_tree_add_item(tree, proto_opus, tvb, 0, -1, ENC_NA);
    opus_tree = proto_item_add_subtree(item, ett_opus);

    /*
     *  A ToC entry takes the following format, details defined in section-3.1:
     *
     *    0 1 2 3 4 5 6 7
     *   +-+-+-+-+-+-+-+-+
     *   | config  |s| c |
     *   +-+-+-+-+-+-+-+-+
     */
    proto_tree_add_bitmask_list(opus_tree, tvb, offset, 1, toc_fields, ENC_NA);

    cap_len = tvb_captured_length(tvb);
    pkt_total = tvb_captured_length_remaining(tvb, offset);

    if (pkt_total <= 0) {
        expert_add_info(pinfo, opus_tree, &ei_opus_err_r1);
        return cap_len;
    }

    toc = tvb_get_guint8(tvb, offset++);

    switch (toc & 0x3) {
    case 0: /* One frame */
        frames[0].begin = offset;
        frames[0].size = pkt_total - offset;
        frame_count = 1;
        break;
    case 1: /* Two CBR frames */
        if ((pkt_total - offset) & 0x1) {
            expert_add_info(pinfo, opus_tree, &ei_opus_err_r3);
            return cap_len;
        }
        frames[0].begin = offset;
        frames[0].size = frames[1].size = (pkt_total - offset) / 2;
        frames[1].begin = frames[0].begin + frames[0].size;
        frame_count = 2;
        break;
    case 2: /* Two VBR frames */
        if (offset >= pkt_total) {
            expert_add_info(pinfo, opus_tree, &ei_opus_err_r4);
            return cap_len;
        }
        /* offset < pkt_total */
        octet[octet_cnt++] = tvb_get_guint8(tvb, offset);
        if (offset + 1 < pkt_total) {
            octet[octet_cnt++] = tvb_get_guint8(tvb, offset + 1);
        }
        bytes = parse_size_field(octet, octet_cnt, &framesize);
        if (framesize < 0 || framesize > pkt_total) {
            expert_add_info(pinfo, opus_tree, &ei_opus_err_r1);
            return cap_len;
        }
        proto_tree_add_item(opus_tree, hf_opus_frame_size, tvb, offset, bytes,
                            ENC_NA);
        offset += bytes;
        /* frame[0] has size header, frame[1] is remaining */
        frames[0].begin = offset;
        frames[0].size = framesize;
        frames[1].begin = frames[0].begin + framesize;
        frames[1].size = -1;
        frame_count = 2;
        break;
    /* Multiple CBR/VBR frames (from 0 to 120 ms) */
    default: /* case 3:*/
        if ((pkt_total - offset) < 2) {
            expert_add_info(pinfo, opus_tree, &ei_opus_err_r6);
            return cap_len;
        }
        proto_tree_add_bitmask_list(opus_tree, tvb, offset, 1,
                                    frame_count_fields, ENC_NA);
        /* Number of frames encoded in bits 0 to 5 */
        ch = tvb_get_guint8(tvb, offset++);
        frame_count = ch & 0x3F;
        framesize = opus_packet_get_samples_per_frame(&toc, 48000U);
        if (frame_count <= 0
            || framesize * frame_count > 120 * MAX_FRAMES_COUNT) {
            expert_add_info(pinfo, opus_tree, &ei_opus_err_r5);
            return cap_len;
        }
        /* Padding flag (bit 6) used */
        if (ch & 0x40) {
            int p;
            gint padding_size = 0;
            gint padding_begin = offset;
            do {
                int tmp;
                if (offset >= pkt_total) {
                    expert_add_info(pinfo, opus_tree, &ei_opus_err_r7);
                    return cap_len;
                }
                p = tvb_get_guint8(tvb, offset++);
                tmp = p == 255 ? 254 : p;
                padding_size += tmp;
            } while (p == 255);
            proto_tree_add_item(opus_tree, hf_opus_padding, tvb, padding_begin,
                                padding_size, ENC_NA);
            offset = padding_begin + padding_size;
        }
        if (offset >= pkt_total) {
            expert_add_info(pinfo, opus_tree, &ei_opus_err_r7);
            return cap_len;
        }
        /* VBR flag is bit 7 */
        if (ch & 0x80) { /* VBR case */
            for (idx = 0; idx < frame_count; idx++) {
                octet_cnt = 0;
                octet[octet_cnt++] = tvb_get_guint8(tvb, offset);
                if (offset + 1 < pkt_total) {
                    octet[octet_cnt++] = tvb_get_guint8(tvb, offset);
                }
                bytes = parse_size_field(octet, octet_cnt, &frames[idx].size);
                if (frames[idx].size < 0
                    || frames[idx].size > (pkt_total - offset)) {
                    expert_add_info(pinfo, opus_tree, &ei_opus_err_r1);
                    return cap_len;
                }

                proto_tree_add_item(opus_tree, hf_opus_frame_size, tvb, offset,
                                    bytes, ENC_NA);
                offset += bytes;
            }
            for (idx = 0; idx < frame_count; idx++) {
                frames[idx].begin = offset;
                offset += frames[idx].size;
            }
            if (offset > pkt_total) {
                expert_add_info(pinfo, opus_tree, &ei_opus_err_r7);
                return cap_len;
            }
        }
        else { /* CBR case */
            guint frame_size = (pkt_total - offset) / frame_count;
            if (frame_size * frame_count != (guint)(pkt_total - offset)) {
                expert_add_info(pinfo, opus_tree, &ei_opus_err_r6);
                return cap_len;
            }
            for (idx = 0; idx < frame_count; idx++) {
                frames[idx].begin = offset + idx * frame_size;
                frames[idx].size = frame_size;
            }
        }
        break;
    }

    for (idx = 0; idx < frame_count; idx++) {
        struct FRAME_T *f = &frames[idx];
        /* reject the frame which is larger than 1275. */
        if (f->size > 1275) {
            expert_add_info(pinfo, opus_tree, &ei_opus_err_r2);
            return cap_len;
        }
        proto_tree_add_item(opus_tree, hf_opus_frame, tvb, f->begin, f->size,
                            ENC_NA);
    }

    return cap_len;
}

void
proto_register_opus(void)
{
    module_t *opus_module;
    expert_module_t* expert_opus;

    static hf_register_info hf[] = {
        {&hf_opus_toc_config,
         {"TOC.config", "opus.TOC.config", FT_UINT8, BASE_DEC | BASE_EXT_STRING,
          &opus_codec_toc_config_request_vals_ext, 0xF8, "Opus TOC config",
          HFILL}},
        {&hf_opus_toc_s,
         {"TOC.S bit", "opus.TOC.s", FT_BOOLEAN, SEP_DOT, TFS(&toc_s_bit_vals),
          0x04, NULL, HFILL}},
        {&hf_opus_toc_c,
         {"TOC.C bits", "opus.TOC.c", FT_UINT8, BASE_DEC | BASE_EXT_STRING,
          &opus_codec_toc_c_request_vals_ext, 0x03, "Opus TOC code", HFILL}},
        {&hf_opus_frame_count_m,
         {"Frame Count.m", "opus.FC.m", FT_UINT8, BASE_DEC, NULL, 0x3F,
          "Frame Count", HFILL}},
        {&hf_opus_frame_count_p,
         {"Frame Count.p bit", "opus.FC.p", FT_BOOLEAN, SEP_DOT,
          TFS(&fc_p_bit_vals), 0x40, NULL, HFILL}},
        {&hf_opus_frame_count_v,
         {"Frame Count.v bit", "opus.FC.v", FT_BOOLEAN, SEP_DOT,
          TFS(&fc_v_bit_vals), 0x80, NULL, HFILL}},
        {&hf_opus_frame_size,
         {"Frame Size", "opus.frame_size", FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
          HFILL}},
        {&hf_opus_frame,
         {"Frame Data", "opus.frame_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
          HFILL}},
        {&hf_opus_padding,
         {"Padding", "opus.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
          HFILL}},
    };

    static gint *ett[] = { &ett_opus, };

    static ei_register_info ei[] = {
        {&ei_opus_err_r1,
         {"opus.violate_r1", PI_PROTOCOL, PI_ERROR,
          "Error:[R1] Packets are at least one byte.", EXPFILL}},
        {&ei_opus_err_r2,
         {"opus.violate_r2", PI_MALFORMED, PI_ERROR,
          "Error:[R2] No implicit frame length is larger than 1275 bytes.",
          EXPFILL}},
        {&ei_opus_err_r3,
         {"opus.violate_r3", PI_MALFORMED, PI_ERROR,
          "Error:[R3] Code 1 packets have an odd total length, N, so that "
          "(N-1)/2 is an integer.",
          EXPFILL}},
        {&ei_opus_err_r4,
         {"opus.violate_r4", PI_MALFORMED, PI_ERROR,
          "Error:[R4] Code 2 packets have enough bytes after the TOC for a "
          "valid frame length, and that length is no larger than the number of"
          "bytes remaining in the packet.",
          EXPFILL}},
        {&ei_opus_err_r5,
         {"opus.violate_r5", PI_PROTOCOL, PI_ERROR,
          "Error:[R5] Code 3 packets contain at least one frame, but no more "
          "than 120 ms of audio total.",
          EXPFILL}},
        {&ei_opus_err_r6,
         {"opus.violate_r6", PI_PROTOCOL, PI_ERROR,
          "Error:[R6] The length of a CBR code 3 packet, N, is at least two "
          "bytes, the number of bytes added to indicate the padding size plus "
          "the trailing padding bytes themselves, P, is no more than N-2, and "
          "the frame count, M, satisfies the constraint that (N-2-P) is a "
          "non-negative integer multiple of M.",
          EXPFILL}},
        {&ei_opus_err_r7,
         {"opus.violate_r7", PI_PROTOCOL, PI_ERROR,
          "Error:[R7] VBR code 3 packets are large enough to contain all the "
          "header bytes (TOC byte, frame count byte, any padding length bytes, "
          "and any frame length bytes), plus the length of the first M-1 "
          "frames, plus any trailing padding bytes.",
          EXPFILL}},
    };

    proto_opus
        = proto_register_protocol("Opus Interactive Audio Codec", /* name */
                                  "OPUS", /* short name */
                                  "opus"  /* abbrev     */
        );

    proto_register_field_array(proto_opus, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    opus_module = prefs_register_protocol(proto_opus, NULL);

    expert_opus = expert_register_protocol(proto_opus);
    expert_register_field_array(expert_opus, ei, array_length(ei));

    prefs_register_obsolete_preference(opus_module, "dynamic.payload.type");

    opus_handle = register_dissector("opus", dissect_opus, proto_opus);
}

void
proto_reg_handoff_opus(void)
{
    dissector_add_string("rtp_dyn_payload_type" , "OPUS", opus_handle);

    dissector_add_uint_range_with_preference("rtp.pt", "", opus_handle);
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
