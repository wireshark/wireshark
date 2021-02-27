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
#include <glibconfig.h>
#include <stdint.h>

void proto_reg_handoff_opus(void);
void proto_register_opus(void);

static range_t *g_dynamic_payload_type_range = NULL;

static dissector_handle_t opus_handle;

/* Initialize the protocol and registered fields */
static int proto_opus = -1;
static int hf_opus_toc_config = -1;
static int hf_opus_toc_s = -1;
static int hf_opus_toc_c = -1;
static int hf_opus_payload = -1;

/* Initialize the subtree pointers */
static int ett_opus = -1;
static int ett_opus_table_of_contents = -1;

static expert_field ei_opus_err_r1 = EI_INIT;
static expert_field ei_opus_err_r2 = EI_INIT;
static expert_field ei_opus_err_r3 = EI_INIT;
static expert_field ei_opus_err_r4 = EI_INIT;
static expert_field ei_opus_err_r5 = EI_INIT;
static expert_field ei_opus_err_r6 = EI_INIT;
static expert_field ei_opus_err_r7 = EI_INIT;

static gint *ett[] = {
    &ett_opus,
    &ett_opus_table_of_contents
};

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

static const value_string opus_codec_toc_c_request_vals[]
    = {{0, "1 frame in the packet"},
       {1, "2 frames in the packet, each with equal compressed size"},
       {2, "2 frames in the packet, with different compressed sizes"},
       {3, "an arbitrary number of frames in the packet"},
       {0, NULL}};
static value_string_ext opus_codec_toc_c_request_vals_ext
    = VALUE_STRING_EXT_INIT(opus_codec_toc_c_request_vals);

static int
dissect_opus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbuff_t *newtvb;

    proto_item *item;
    proto_tree *opus_tree;

    proto_item *item_toc;
    proto_tree *opus_toc_tree;

    gint offset = 0;
    guint cap_len, pkt_total;

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
    opus_toc_tree
        = proto_tree_add_subtree(opus_tree, tvb, offset, -1,
                                 ett_opus_table_of_contents, &item_toc,
                                 "Payload Table of Contents");

    proto_tree_add_item(opus_toc_tree, hf_opus_toc_config, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(opus_toc_tree, hf_opus_toc_s,      tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(opus_toc_tree, hf_opus_toc_c,      tvb, offset, 1, ENC_BIG_ENDIAN);

    cap_len = tvb_captured_length(tvb);
    pkt_total = tvb_captured_length_remaining(tvb, offset);

    if (pkt_total <= 0) {
        expert_add_info(pinfo, opus_tree, &ei_opus_err_r1);
        return cap_len;
    }
    offset++;  /* skip the TOC */
    newtvb = tvb_new_subset_length_caplen(tvb, offset, pkt_total - offset, pkt_total - offset);
    proto_tree_add_item(opus_tree, hf_opus_payload, newtvb, 0, -1, ENC_NA);

    return cap_len;
}

void
proto_register_opus(void)
{
    module_t *opus_module;
    expert_module_t* expert_opus;

    static hf_register_info hf[] = {
        {&hf_opus_toc_config,
         {"config", "opus.TOC.config", FT_UINT8, BASE_DEC | BASE_EXT_STRING,
          &opus_codec_toc_config_request_vals_ext, 0xF8, "Opus TOC config",
          HFILL}},
        {&hf_opus_toc_s,
         {"S bit", "opus.TOC.s", FT_BOOLEAN, SEP_DOT, TFS(&toc_s_bit_vals),
          0x04, NULL, HFILL}},
        {&hf_opus_toc_c,
         {"C bits", "opus.TOC.c", FT_UINT8, BASE_DEC | BASE_EXT_STRING,
          &opus_codec_toc_c_request_vals_ext, 0x03, "Opus TOC code", HFILL}},
        {&hf_opus_payload,
         {"Payload", "opus.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
          HFILL}},
    };

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

    opus_module = prefs_register_protocol(proto_opus, proto_reg_handoff_opus);

    expert_opus = expert_register_protocol(proto_opus);
    expert_register_field_array(expert_opus, ei, array_length(ei));

    prefs_register_range_preference(opus_module, "dynamic.payload.type",
                                    "OPUS dynamic payload types",
                                    "Dynamic payload types which will be "
                                    "interpreted as OPUS; Values must be in "
                                    "the range 1 - 127",
                                    &g_dynamic_payload_type_range, 127);

    opus_handle = register_dissector("opus", dissect_opus, proto_opus);
}

void
proto_reg_handoff_opus(void)
{
    static range_t  *dynamic_payload_type_range = NULL;
    static gboolean  opus_prefs_initialized      = FALSE;

    if (!opus_prefs_initialized) {
        dissector_add_string("rtp_dyn_payload_type" , "OPUS", opus_handle);
        opus_prefs_initialized = TRUE;
    } else {
        dissector_delete_uint_range("rtp.pt", dynamic_payload_type_range, opus_handle);
        wmem_free(wmem_epan_scope(), dynamic_payload_type_range);
    }

    dynamic_payload_type_range = range_copy(wmem_epan_scope(), g_dynamic_payload_type_range);
    range_remove_value(wmem_epan_scope(), &dynamic_payload_type_range, 0);
    dissector_add_uint_range("rtp.pt", dynamic_payload_type_range, opus_handle);
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
