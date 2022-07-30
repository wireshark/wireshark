/* packet-evs.c
 * Routines for EVS dissection
 * Copyright 2018, Anders Broman <anders.broman[at]ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References:
 * 3GPP TS 26.445 A.2 EVS RTP Payload Format
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>


void proto_register_evs(void);
void proto_reg_handoff_evs(void);

static dissector_handle_t evs_handle;

/* Initialize the protocol and registered fields */
static int proto_evs = -1;

static int hf_evs_packet_length = -1;
static int hf_evs_voice_data = -1;
static int hf_evs_h_bit = -1;
static int hf_evs_cmr_t = -1;
static int hf_evs_cmr_t0_d = -1;
static int hf_evs_cmr_t1_d = -1;
static int hf_evs_cmr_t2_d = -1;
static int hf_evs_cmr_t3_d = -1;
static int hf_evs_cmr_t4_d = -1;
static int hf_evs_cmr_t5_d = -1;
static int hf_evs_cmr_t6_d = -1;
static int hf_evs_cmr_t7_d = -1;
static int hf_evs_f_bit = -1;
static int hf_evs_mode_bit = -1;
static int hf_evs_toc_spare = -1;
static int hf_evs_amr_wb_q_bit = -1;
static int hf_evs_bit_rate_mode_0 = -1;
static int hf_evs_bit_rate_mode_1 = -1;
static int hf_evs_cmr_amr_io = -1;
static int hf_evs_bw = -1;
static int hf_evs_reserved_1bit = -1;
static int hf_evs_celp_switch_to_mdct_core = -1;
static int hf_evs_celp_mdct_core = -1;
static int hf_evs_tcx_or_hq_mdct_core = -1;
static int hf_evs_sid_cng = -1;
static int hf_evs_celp_sample_rate = -1;
static int hf_evs_core_sample_rate = -1;
static int hf_evs_132_bwctrf_idx = -1;
static int hf_evs_28_frame_type = -1;
static int hf_evs_28_bw_ppp_nelp = -1;
static int hf_evs_72_80_bwct_idx = -1;
static int hf_evs_320_bwct_idx = -1;
static int hf_evs_640_bwct_idx = -1;

static int ett_evs = -1;
static int ett_evs_header = -1;
static int ett_evs_speech = -1;
static int ett_evs_voice_data = -1;

static const value_string evs_protected_payload_sizes_value[] = {
    {    48, "EVS Primary SID 2.4" },
    {    56, "Special case" },
    {   136, "EVS AMR-WB IO 6.6" },
    {   144, "EVS Primary 7.2" },
    {   160, "EVS Primary 8.0" },
    {   184, "EVS AMR-WB IO 8.85" },
    {   192, "EVS Primary 9.6" },
    {   256, "EVS AMR-WB IO 12.65" },
    {   264, "EVS Primary 13.2" },
    {   288, "EVS AMR-WB IO 14.25" },
    {   320, "EVS AMR-WB IO 15.85" },
    {   328, "EVS Primary 16.4" },
    {   368, "EVS AMR-WB IO 18.25" },
    {   400, "EVS AMR-WB IO 19.85" },
    {   464, "EVS AMR-WB IO 23.05" },
    {   480, "EVS AMR-WB IO 23.85" },
    {   488, "EVS Primary 24.4" },
    {   640, "EVS Primary 32.0" },
    {   960, "EVS Primary 48.0" },
    {  1280, "EVS Primary 64.0" },
    {  1920, "EVS Primary 96.0" },
    {  2560, "EVS Primary 128.0" },
    { 0, NULL }
};

static const value_string evs_d_bits_t0_values[] = {
    { 0x0, "NB 5.9 kbps (VBR)" },
    { 0x1, "NB 7.2 kbps" },
    { 0x2, "NB 8.0 kbps" },
    { 0x3, "NB 9.6 kbps" },
    { 0x4, "NB 13.2 kbps" },
    { 0x5, "NB 16.4 kbps" },
    { 0x6, "Not used" },
    { 0x7, "Not used" },
    { 0x8, "Not used" },
    { 0x9, "Not used" },
    { 0xa, "Not used" },
    { 0xb, "Not used" },
    { 0xc, "Not used" },
    { 0xd, "Not used" },
    { 0xe, "Not used" },
    { 0xf, "Not used" },
    { 0, NULL }
};

static const value_string evs_d_bits_t1_values[] = {
    { 0x0, "AMR-WB IO 6.6 kbps (mode-set 0)" },
    { 0x1, "AMR-WB IO 8.8 kbps (mode-set 1)" },
    { 0x2, "AMR-WB IO 12.65 kbps (mode-set 2)" },
    { 0x3, "AMR-WB IO 14.25 kbps (mode-set 3)" },
    { 0x4, "AMR-WB IO 15.85 kbps (mode-set 4)" },
    { 0x5, "AMR-WB IO 18.25 kbps (mode-set 5)" },
    { 0x6, "AMR-WB IO 19.85 kbps (mode-set 6)" },
    { 0x7, "AMR-WB IO 23.05 kbps (mode-set 7)" },
    { 0x8, "AMR-WB IO 23.85 kbps (mode-set 8)" },
    { 0x9, "Not used" },
    { 0xa, "Not used" },
    { 0xb, "Not used" },
    { 0xc, "Not used" },
    { 0xd, "Not used" },
    { 0xe, "Not used" },
    { 0xf, "Not used" },
    { 0, NULL }
};


static const value_string evs_d_bits_t2_values[] = {
    { 0x0, "WB 5.9 kbps (VBR)" },
    { 0x1, "WB 7.2 kbps" },
    { 0x2, "WB 8 kbps" },
    { 0x3, "WB 9.6 kbps" },
    { 0x4,"WB 13.2 kbps" },
    { 0x5,"WB 16.4 kbps" },
    { 0x6,"WB 24.4 kbps" },
    { 0x7,"WB 32 kbps" },
    { 0x8,"WB 48 kbps" },
    { 0x9,"WB 64 kbps" },
    { 0xa,"WB 96 kbps" },
    { 0xb,"WB 128 kbps" },
    { 0xc, "Not used" },
    { 0xd, "Not used" },
    { 0xe, "Not used" },
    { 0xf, "Not used" },
    { 0, NULL }
};

static const value_string evs_d_bits_t3_values[] = {
    { 0x0, "Not used" },
    { 0x1, "Not used" },
    { 0x2, "Not used" },
    { 0x3, "SWB 9.6 kbps" },
    { 0x4, "SWB 13.2 kbps" },
    { 0x5, "SWB 16.4 kbps" },
    { 0x6, "SWB 24.4 kbps" },
    { 0x7, "SWB 32 kbps" },
    { 0x8, "SWB 48 kbps" },
    { 0x9, "SWB 64 kbps" },
    { 0xa, "SWB 96 kbps" },
    { 0xb, "SWB 128 kbps" },
    { 0xc, "Not used" },
    { 0xd, "Not used" },
    { 0xe, "Not used" },
    { 0xf, "Not used" },
    { 0, NULL }
};

static const value_string evs_d_bits_t4_values[] = {
    { 0x0, "Not used" },
    { 0x1, "Not used" },
    { 0x2, "Not used" },
    { 0x3, "Not used" },
    { 0x4, "Not used" },
    { 0x5, "FB 16.4 kbps" },
    { 0x6, "FB 24.4 kbps" },
    { 0x7, "FB 32 kbps" },
    { 0x8, "FB 48 kbps" },
    { 0x9, "FB 64 kbps" },
    { 0xa, "FB 96 kbps" },
    { 0xb, "FB 128 kbps" },
    { 0xc, "Not used" },
    { 0xd, "Not used" },
    { 0xe, "Not used" },
    { 0xf, "Not used" },
    { 0, NULL }
};

static const value_string evs_d_bits_t5_values[] = {
    { 0x0, "WB 13.2 kbps CA-L-O2" },
    { 0x1, "WB 13.2 kbps CA-L-O2" },
    { 0x2, "WB 13.2 kbps CA-L-O5" },
    { 0x3, "WB 13.2 kbps CA-L-O7" },
    { 0x4, "WB 13.2 kbps CA-H-O2" },
    { 0x5, "WB 13.2 kbps CA-H-O3" },
    { 0x6, "WB 13.2 kbps CA-H-O5" },
    { 0x7, "WB 13.2 kbps CA-H-O7" },
    { 0x8, "Not used" },
    { 0x9, "Not used" },
    { 0xa, "Not used" },
    { 0xb, "Not used" },
    { 0xc, "Not used" },
    { 0xd, "Not used" },
    { 0xe, "Not used" },
    { 0xf, "Not used" },
    { 0, NULL }
};

static const value_string evs_d_bits_t6_values[] = {
    { 0x0, "SWB 13.2 kbps CA-L-O2" },
    { 0x1, "SWB 13.2 kbps CA-L-O2" },
    { 0x2, "SWB 13.2 kbps CA-L-O5" },
    { 0x3, "SWB 13.2 kbps CA-L-O7" },
    { 0x4, "SWB 13.2 kbps CA-H-O2" },
    { 0x5, "SWB 13.2 kbps CA-H-O3" },
    { 0x6, "SWB 13.2 kbps CA-H-O5" },
    { 0x7, "SWB 13.2 kbps CA-H-O7" },
    { 0x8, "Not used" },
    { 0x9, "Not used" },
    { 0xa, "Not used" },
    { 0xb, "Not used" },
    { 0xc, "Not used" },
    { 0xd, "Not used" },
    { 0xe, "Not used" },
    { 0xf, "Not used" },
    { 0, NULL }
};

static const value_string evs_d_bits_t7_values[] = {
    { 0x0, "Reserved" },
    { 0x1, "Reserved" },
    { 0x2, "Reserved" },
    { 0x3, "Reserved" },
    { 0x4, "Reserved" },
    { 0x5, "Reserved" },
    { 0x6, "Reserved" },
    { 0x7, "Reserved" },
    { 0x8, "Reserved" },
    { 0x9, "Reserved" },
    { 0xa, "Reserved" },
    { 0xb, "Reserved" },
    { 0xc, "Reserved" },
    { 0xd, "Reserved" },
    { 0xe, "Reserved" },
    { 0xf, "NO_REQ" },
    { 0, NULL }
};

static const value_string evs_bit_rate_mode_0_values[] = {
    { 0x0, "Primary 2.8 kbps" },
    { 0x1, "Primary 7.2 kbps" },
    { 0x2, "Primary 8.0 kbps" },
    { 0x3, "Primary 9.6 kbps" },
    { 0x4, "Primary 13.2 kbps" },
    { 0x5, "Primary 16.4 kbps" },
    { 0x6, "Primary 24.4 kbps" },
    { 0x7, "Primary 32.0 kbps" },
    { 0x8, "Primary 48.0 kbps" },
    { 0x9, "Primary 64.0 kbps" },
    { 0xa, "Primary 96.0 kbps" },
    { 0xb, "Primary 128.0 kbps" },
    { 0xc, "Primary 2.4 kbps SID" },
    { 0xd, "For future use" },
    { 0xe, "SPEECH_LOST" },
    { 0xf, "NO_DATA" },
    { 0, NULL }
};

static const value_string evs_bit_rate_mode_1_values[] = {
    { 0x0, "AMR-WB IO 6.6 kbps" },
    { 0x1, "AMR-WB IO 8.85 kbps" },
    { 0x2, "AMR-WB IO 12.65 kbps" },
    { 0x3, "AMR-WB IO 14.24 kbps" },
    { 0x4, "AMR-WB IO 15.85 kbps" },
    { 0x5, "AMR-WB IO 18.25 kbps" },
    { 0x6, "AMR-WB IO 19.85 kbps" },
    { 0x7, "AMR-WB IO 23.05 kbps" },
    { 0x8, "AMR-WB IO 23.85 kbps" },
    { 0x9, "AMR-WB IO 2.0 kbps SID" },
    { 0xa, "For future use" },
    { 0xb, "For future use" },
    { 0xc, "For future use" },
    { 0xd, "For future use" },
    { 0xe, "SPEECH_LOST" },
    { 0xf, "NO_DATA" },
    { 0, NULL }
};


static const value_string evs_cmr_amr_io_values[] = {
    { 0x0, "AMR-WB IO 6.6 kbps" },
    { 0x1, "AMR-WB IO 8.85 kbps" },
    { 0x2, "AMR-WB IO 12.65 kbps" },
    { 0x3, "AMR-WB IO 15.85 kbps" },
    { 0x4, "AMR-WB IO 18.25 kbps" },
    { 0x5, "AMR-WB IO 23.05 kbps" },
    { 0x6, "AMR-WB IO 23.85 kbps" },
    { 0x7, "none" },
    { 0, NULL }
};

static const true_false_string tfs_evs_h_bit = {
    "CMR",
    "ToC"
};

static const true_false_string tfs_evs_f_bit = {
    "Speech frame follows",
    "Last frame in payload"
};

static const true_false_string toc_evs_q_bit_vals = {
    "Ok",
    "Severely damaged frame"
};

static const value_string evs_bw_values[] = {
    { 0x0, "NB" },
    { 0x1, "WB" },
    { 0x2, "SWB" },
    { 0x3, "FB" },
    { 0, NULL }
};

static const value_string evs_celp_switch_to_mdct_core_values[] = {
    { 0x00,  "False" },
    { 0x01,  "True" },
    { 0, NULL }
};

static const value_string evs_celp_or_mdct_core_values[] = {
    { 0x0, "CELP" },
    { 0x1, "MDCT" },
    { 0, NULL }
};

static const value_string evs_tcx_or_hq_mdct_core_values[] = {
    { 0x0, "HQ-MDCT core" },
    { 0x1, "TCX Core" },
    { 0, NULL }
};

static const value_string evs_sid_cng_values[] = {
    { 0x0, "LP-CNG SID" },
    { 0x1, "FD-CNG" },
    { 0, NULL }
};

static const value_string evs_sid_celp_sample_rate_values[] = {
    { 0x0, "12.8 kHz" },
    { 0x1, "16 kHz" },
    { 0, NULL }
};

static const value_string evs_132_bwctrf_idx_vals[] = {
    { 0x0, "NB generic" },
    { 0x1, "NB voiced" },
    { 0x2, "NB transition" },
    { 0x3, "NB audio" },
    { 0x4, "NB inactive" },
    { 0x5, "WB generic" },
    { 0x6, "WB voiced" },
    { 0x7, "WB transition" },
    { 0x8, "WB audio" },
    { 0x9, "WB inactive" },
    { 0xa, "SWB generic" },
    { 0xb, "SWB voiced" },
    { 0xc, "SWB transition" },
    { 0xd, "SWB audio" },
    { 0xe, "SWB inactive" },
    { 0xf, "NB generic" },
    { 0x10, "NB voiced" },
    { 0x11, "WB generic" },
    { 0x12, "WB voiced" },
    { 0x13, "SWB generic" },
    { 0x14, "SWB voiced" },
    { 0x15, "WB generic" },
    { 0x16, "WB unvoiced" },
    { 0x17, "WB voiced" },
    { 0x18, "WB inactive" },
    { 0x19, "SWB generic" },
    { 0x1a, "SWB unvoiced" },
    { 0x1b, "SWB voiced" },
    { 0x1c, "SWB inactive" },
    { 0x1d, "NB lrMDCT" },
    { 0x1e, "WB lrMDCT" },
    { 0x1f, "SWB lrMDCT" },
    { 0, NULL }
};

static const value_string evs_28_frame_type_vals[] = {
    { 0x0, "Primary PPP/NELP" },
    { 0x1, "AMR-WB IO SID" },
    { 0, NULL }
};

static const value_string evs_28_bw_ppp_nelp_vals[] = {
    { 0x00, "NB PPP" },
    { 0x01, "WB PPP" },
    { 0x02, "NB NELP" },
    { 0x03, "WB NELP" },
    { 0, NULL }
};

static const value_string evs_72_80_bwct_idx_vals[] = {
    { 0x0, "NB generic" },
    { 0x1, "NB unvoiced" },
    { 0x2, "NB voiced" },
    { 0x3, "NB transition" },
    { 0x4, "NB audio" },
    { 0x5, "NB inactive" },
    { 0x6, "WB generic" },
    { 0x7, "WB unvoiced" },
    { 0x8, "WB voiced" },
    { 0x9, "WB transition" },
    { 0xa, "WB audio" },
    { 0xb, "WB inactive" },
    { 0xc, "NB generic" },
    { 0xd, "WB generic" },
    { 0xe, "NB lrMDCT" },
    { 0, NULL }
};

static const value_string evs_320_bwct_idx_vals[] = {
    { 0x0, "WB generic" },
    { 0x1, "WB transition" },
    { 0x2, "WB inactive" },
    { 0x3, "SWB generic" },
    { 0x4, "SWB transition" },
    { 0x5, "SWB inactive" },
    { 0x6, "FB generic" },
    { 0x7, "FB transition" },
    { 0x8, "FB inactive" },
    { 0x9, "WB generic" },
    { 0xa, "WB transition" },
    { 0xb, "SWB generic" },
    { 0xc, "SWB transition" },
    { 0xd, "FB generic" },
    { 0xe, "FB transition" },
    { 0, NULL }
};

static const value_string evs_640_bwct_idx_vals[] = {
    { 0x0, "WB generic" },
    { 0x1, "WB transition" },
    { 0x2, "WB inactive" },
    { 0x3, "SWB generic" },
    { 0x4, "SWB transition" },
    { 0x5, "SWB inactive" },
    { 0x6, "FB generic" },
    { 0x7, "FB transition" },
    { 0x8, "FB inactive" },
    { 0x9, "SWB generic" },
    { 0xa, "SWB transition" },
    { 0xb, "FB generic" },
    { 0xc, "FB transition" },
    { 0, NULL }
};

static void
dissect_evs_cmr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *evs_tree, int offset, guint8 cmr_oct)
{
    proto_tree *tree;
    proto_item *item;
    const gchar *str;
    guint8 t_bits = (cmr_oct & 0x70) >> 4;
    guint8 d_bits = (cmr_oct & 0x0f);
    /* CMR */
    tree = proto_tree_add_subtree(evs_tree, tvb, offset, 1, ett_evs_header, &item, "CMR");


    switch (t_bits) {
    case 0:
    {
        static int * const flags_t0[] = {
            &hf_evs_h_bit,
            &hf_evs_cmr_t,
            &hf_evs_cmr_t0_d,
            NULL
        };

        str = val_to_str_const(d_bits, evs_d_bits_t0_values, "Unknown value");
        proto_item_append_text(item, " %s",str);
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_t0, ENC_BIG_ENDIAN);
    }
    break;
    case 1:
    {
        static int * const flags_t1[] = {
            &hf_evs_h_bit,
            &hf_evs_cmr_t,
            &hf_evs_cmr_t1_d,
            NULL
        };

        str = val_to_str_const(d_bits, evs_d_bits_t1_values, "Unknown value");
        proto_item_append_text(item, " %s",str);
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_t1, ENC_BIG_ENDIAN);
    }
    break;
    case 2:
    {
        static int * const flags_t2[] = {
            &hf_evs_h_bit,
            &hf_evs_cmr_t,
            &hf_evs_cmr_t2_d,
            NULL
        };

        str = val_to_str_const(d_bits, evs_d_bits_t2_values, "Unknown value");
        proto_item_append_text(item, " %s",str);
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_t2, ENC_BIG_ENDIAN);
    }
    break;
    case 3:
    {
        static int * const flags_t3[] = {
            &hf_evs_h_bit,
            &hf_evs_cmr_t,
            &hf_evs_cmr_t3_d,
            NULL
        };

        str = val_to_str_const(d_bits, evs_d_bits_t3_values, "Unknown value");
        proto_item_append_text(item, " %s",str);
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_t3, ENC_BIG_ENDIAN);
    }
    break;
    case 4:
    {
        static int * const flags_t4[] = {
            &hf_evs_h_bit,
            &hf_evs_cmr_t,
            &hf_evs_cmr_t4_d,
            NULL
        };

        str = val_to_str_const(d_bits, evs_d_bits_t4_values, "Unknown value");
        proto_item_append_text(item, " %s",str);
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_t4, ENC_BIG_ENDIAN);
    }
    break;
    case 5:
    {
        static int * const flags_t5[] = {
            &hf_evs_h_bit,
            &hf_evs_cmr_t,
            &hf_evs_cmr_t5_d,
            NULL
        };

        str = val_to_str_const(d_bits, evs_d_bits_t5_values, "Unknown value");
        proto_item_append_text(item, " %s",str);
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_t5, ENC_BIG_ENDIAN);
    }
    break;
    case 6:
    {
        static int * const flags_t6[] = {
            &hf_evs_h_bit,
            &hf_evs_cmr_t,
            &hf_evs_cmr_t6_d,
            NULL
        };

        str = val_to_str_const(d_bits, evs_d_bits_t6_values, "Unknown value");
        proto_item_append_text(item, " %s",str);
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_t6, ENC_BIG_ENDIAN);
    }
    break;
    case 7:
    {
        static int * const flags_t7[] = {
            &hf_evs_h_bit,
            &hf_evs_cmr_t,
            &hf_evs_cmr_t7_d,
            NULL
        };

        str = val_to_str_const(d_bits, evs_d_bits_t7_values, "Unknown value");
        proto_item_append_text(item, " %s",str);
        proto_tree_add_bitmask_list(tree, tvb, offset, 1, flags_t7, ENC_BIG_ENDIAN);
    }
    break;
    default:
        DISSECTOR_ASSERT_NOT_REACHED();
        break;

    }
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", str);
}

/* Code to actually dissect the packets */
static int
dissect_evs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *evs_tree, *sub_tree, *vd_tree;
    int offset = 0 , bit_offset = 0;
    int packet_len, idx, speech_data_len;
    guint32 num_bits;
    const gchar *str;
    guint8 oct, h_bit, toc_f_bit, evs_mode_b;
    int num_toc, num_data;
    guint64 value;
    gboolean is_compact = FALSE;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "EVS");


    /* Find out if we have one of the reserved packet sizes*/
    packet_len = tvb_reported_length(tvb);
    num_bits = packet_len * 8;
    if (num_bits == 56) {
        /* A.2.1.3 Special case for 56 bit payload size (EVS Primary or EVS AMR-WB IO SID) */
        /* The resulting ambiguity between EVS Primary 2.8 kbps and EVS AMR-WB IO SID frames is resolved through the
           most significant bit (MSB) of the first byte of the payload. By definition, the first data bit d(0) of the EVS Primary 2.8
           kbps is always set to '0'.
         */
        oct = tvb_get_bits8(tvb, bit_offset, 1);
        if (oct == 0) {
            /* EVS Primary 2.8 kbps */
            str = "EVS Primary 2.8 kbps";
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", str);
            is_compact = TRUE;
        } else {
            /* EVS AMR-WB IO SID */
            str = "EVS AMR-WB IO SID";
        }
    } else {
        str = try_val_to_str_idx(num_bits, evs_protected_payload_sizes_value, &idx);
        if (str) {
            is_compact = TRUE;
        }
    }
    ti = proto_tree_add_item(tree, proto_evs, tvb, 0, -1, ENC_NA);
    evs_tree = proto_item_add_subtree(ti, ett_evs);
    if (is_compact) {
        /* A.2.1 EVS codec Compact Format */
        proto_tree_add_subtree(evs_tree, tvb, offset, -1, ett_evs_header, &ti, "Framing Mode: Compact");
        proto_item_set_generated(ti);

        /* One of the protected payload sizes, no further dissection currently.*/
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", str);
        proto_tree_add_int_format(evs_tree, hf_evs_packet_length, tvb, offset, 1, packet_len * 8, " %s, packet_len %i bits", str, packet_len * 8);
        if (strncmp(str, "EVS A", 5) == 0) {
            /* A.2.1.2	Compact format for EVS AMR-WB IO mode */
            /* CMR */
            proto_tree_add_item(evs_tree, hf_evs_cmr_amr_io, tvb, offset, 1, ENC_BIG_ENDIAN);
        }

        vd_tree = proto_tree_add_subtree(evs_tree, tvb, offset, -1, ett_evs_voice_data, NULL, "Voice Data");
        switch (packet_len) {
        case 17: /* 136 EVS AMR-WB IO 6.6 */
        case 23: /* 184 EVS AMR-WB IO 8.85 */
        case 32: /* 256 EVS AMR-WB IO 12.65 */
        case 36: /* 288 EVS AMR-WB IO 14.25 */
        case 40: /* 320 EVS AMR-WB IO 15.85 */
        case 46: /* 368 EVS AMR-WB IO 18.25 */
        case 50: /* 400 EVS AMR-WB IO 19.85 */
        case 58: /* 464 EVS AMR-WB IO 23.05 */
        case 60: /* 480 EVS AMR-WB IO 23.85 */
            /* A.2.1.2 Compact format for EVS AMR-WB IO mode (except SID)
             * In the Compact format for EVS AMR-WB IO mode, except SID, the RTP payload consists of one 3-bit CMR field,
             * one coded frame, and zero-padding bits if necessary.
             */
            /* CMR */
            proto_tree_add_item(evs_tree, hf_evs_cmr_amr_io, tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        case 6: /* 48 EVS Primary SID 2.4 */
            /* 7.2	Bit allocation for SID frames in the DTX operation */
            /* CNG type flag 1 bit */
            proto_tree_add_bits_ret_val(vd_tree, hf_evs_sid_cng, tvb, bit_offset, 1, &value, ENC_BIG_ENDIAN);
            bit_offset++;
            if (value == 1) {
                /* FD-CNG SID frame */
                /* Bandwidth indicator 2 bits */
                proto_tree_add_bits_item(vd_tree, hf_evs_bw, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
                bit_offset += 2;
                /* CELP sample rate 1 bit*/
                proto_tree_add_bits_item(vd_tree, hf_evs_celp_sample_rate, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
                /* Global gain 7 bits */
                /* Spectral band and energy 37 bits */
            } else {
                /* LP-CNG SID frame */
                /* Bandwidth indicator 1 bit */
                oct = tvb_get_bits8(tvb, bit_offset, 1);
                proto_tree_add_uint_bits_format_value(vd_tree, hf_evs_bw, tvb, bit_offset, 1, 1, ENC_BIG_ENDIAN, "%s (%u)",
                    val_to_str_const(1 << oct, evs_bw_values, "Unknown value"), oct);
                bit_offset++;
                /* Core sampling rate indicator */
                proto_tree_add_bits_item(vd_tree, hf_evs_core_sample_rate, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            }
            break;
        case 7: /*  56 EVS Primary SID 2.8 */
            /* A.2.1.3 Special case for 56 bit payload size (EVS Primary or EVS AMR-WB IO SID) */
            /* The resulting ambiguity between EVS Primary 2.8 kbps and EVS AMR-WB IO SID frames is resolved through the
               most significant bit (MSB) of the first byte of the payload. By definition, the first data bit d(0) of the EVS Primary 2.8
               kbps is always set to '0'.
             */
            proto_tree_add_bits_ret_val(vd_tree, hf_evs_28_frame_type, tvb, bit_offset, 1, &value, ENC_BIG_ENDIAN);
            bit_offset++;
            if (value == 0) {
                /* Primary PPP/NELP frame */
                proto_tree_add_bits_item(vd_tree, hf_evs_28_bw_ppp_nelp, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            }
            break;
        case 18: /* 144 EVS Primary 7.2 */
        case 20: /* 160 EVS Primary 8.0 */
            /* 7.1.1 Bit allocation at VBR 5.9, 7.2 – 9.6 kbps
             * Note that the BW and CT parameters are combined together to form a single index at 7.2 and 8.0 kbps. This index
             * conveys the information whether CELP core or HQ-MDCT core is used.
             */
            /* BW, CT, 4*/
            proto_tree_add_bits_item(vd_tree, hf_evs_72_80_bwct_idx, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
            break;
        case 24: /* 192 EVS Primary 9.6 */
            /* 7.1.1 Bit allocation at VBR 5.9, 7.2 – 9.6 kbps */
            /* BW 2 bits */
            proto_tree_add_bits_item(vd_tree, hf_evs_bw, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            break;
        case 33: /* 264 EVS Primary 13.2 */
            /* 7.1.2 Bit allocation at 13.2 kbps
             * The EVS codec encodes NB, WB and SWB content at 13.2 kbps with CELP core, HQ-MDCT core, or TCX core.
             * For WB signals, the CELP core uses TBE or FD extension layer. For SWB signals, the CELP core uses TBE or FD extension layer,
             * and the TCX core uses IGF extension layer
             */
            /* BW, CT, RF	5*/
            proto_tree_add_bits_item(vd_tree, hf_evs_132_bwctrf_idx, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
            break;
        case 41: /* 328 EVS Primary 16.4 */
            /* 7.1.3	Bit allocation at 16.4 and 24.4 kbps */
            /* BW 2 bits*/
            proto_tree_add_bits_item(vd_tree, hf_evs_bw, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            bit_offset+=2;
            /* Reserved 1 bit */
            proto_tree_add_bits_item(vd_tree, hf_evs_reserved_1bit, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            break;
        case 61: /* 488 EVS Primary 24.4 */
            /* 7.1.3	Bit allocation at 16.4 and 24.4 kbps */
            /* BW 2 bits*/
            proto_tree_add_bits_item(vd_tree, hf_evs_bw, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            bit_offset+=2;
            /* Reserved 1 bit */
            proto_tree_add_bits_item(vd_tree, hf_evs_reserved_1bit, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            /* CELP/MDCT core flag	1 */
            proto_tree_add_bits_ret_val(vd_tree, hf_evs_celp_mdct_core, tvb, bit_offset, 1, &value, ENC_BIG_ENDIAN);
            bit_offset++;
            /* In the case of MDCT-based core, the next bit decides whether HQ-MDCT core or TCX core is used */
            if (value == 1) {
                /* MDCT-based core*/
                proto_tree_add_bits_ret_val(vd_tree, hf_evs_tcx_or_hq_mdct_core, tvb, bit_offset, 1, &value, ENC_BIG_ENDIAN);
            }
            break;
        case 80: /* 640 EVS Primary 32 */
            /* 7.1.4 Bit allocation at 32 kbps */
            /* CELP/MDCT core flag	1 */
            proto_tree_add_bits_ret_val(vd_tree, hf_evs_celp_mdct_core, tvb, bit_offset, 1, &value, ENC_BIG_ENDIAN);
            bit_offset++;
            /* In the case of MDCT-based core, the next bit decides whether HQ-MDCT core or TCX core is used */
            if (value == 1) {
                /* MDCT-based core*/
                proto_tree_add_bits_ret_val(vd_tree, hf_evs_tcx_or_hq_mdct_core, tvb, bit_offset, 1, &value, ENC_BIG_ENDIAN);
                bit_offset++;
                if (value == 1) {
                    /* TCX core */
                    /* BW 2 bits */
                    proto_tree_add_bits_item(vd_tree, hf_evs_bw, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
                }
            } else {
                /* BW, CT, 4*/
                proto_tree_add_bits_item(vd_tree, hf_evs_320_bwct_idx, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
            }
            break;
        case 160: /* 1280 EVS Primary 64 */
            /* 7.1.5 Bit allocation at 48, 64, 96 and 128 kbps */
            /* CELP/MDCT core flag	1 */
            proto_tree_add_bits_ret_val(vd_tree, hf_evs_celp_mdct_core, tvb, bit_offset, 1, &value, ENC_BIG_ENDIAN);
            bit_offset++;
            if (value == 1) {
                /* MDCT-based core*/
                proto_tree_add_bits_ret_val(vd_tree, hf_evs_celp_switch_to_mdct_core, tvb, bit_offset, 1, &value, ENC_BIG_ENDIAN);
                bit_offset++;
                if (value == 1) {
                    /* CELP sample rate 1 bit*/
                    proto_tree_add_bits_item(vd_tree, hf_evs_celp_sample_rate, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
                    bit_offset++;
                }
                /* BW 2 bits*/
                proto_tree_add_bits_item(vd_tree, hf_evs_bw, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            } else {
                /* BW, CT, 4*/
                proto_tree_add_bits_item(vd_tree, hf_evs_640_bwct_idx, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
            }
            break;
        case 120: /* 960 EVS Primary 48 */
        case 240: /* 1920 EVS Primary 96 */
        case 320: /* 2560 EVS Primary 128 */
            /* 7.1.5 Bit allocation at 48, 64, 96 and 128 kbps */
            /* BW 2 bits*/
            proto_tree_add_bits_item(vd_tree, hf_evs_bw, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            bit_offset+=2;
            /* Reserved 1 bit */
            proto_tree_add_bits_item(vd_tree, hf_evs_reserved_1bit, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            break;
        default:
            break;
        }

        return packet_len;
    }

    /* A.2.2 EVS codec Header-Full format */
    proto_tree_add_subtree(evs_tree, tvb, offset, -1, ett_evs_header, &ti, "Framing Mode: Header-full");
    proto_item_set_generated(ti);

    /*proto_tree_add_int_format(evs_tree, hf_evs_packet_length, tvb, offset, 1, packet_len * 8, "packet_len %i bits", packet_len * 8);*/
    oct = tvb_get_guint8(tvb, offset);
    h_bit = oct >> 7;

    if (h_bit == 1) {
        /* CMR */
        dissect_evs_cmr(tvb, pinfo, evs_tree, offset, oct);
        offset++;
    }
    /* ToC */
    num_toc = 0;
    do {
        oct = tvb_get_guint8(tvb, offset);
        toc_f_bit = (oct & 0x40) >> 6;
        evs_mode_b = (oct & 0x20) >> 5;
        num_toc++;

        sub_tree = proto_tree_add_subtree_format(evs_tree, tvb, offset, 1, ett_evs_header, NULL, " TOC # %u",
            num_toc);

        if (evs_mode_b == 0) {
            static int * const flags_toc_mode_0[] = {
                &hf_evs_h_bit,
                &hf_evs_f_bit,
                &hf_evs_mode_bit,
                &hf_evs_toc_spare,
                &hf_evs_bit_rate_mode_0,
                NULL
            };

            proto_tree_add_bitmask_list(sub_tree, tvb, offset, 1, flags_toc_mode_0, ENC_BIG_ENDIAN);
            str = val_to_str_const((oct & 0x0f), evs_bit_rate_mode_0_values, "Unknown value");
        } else {
            static int * const flags_toc_mode_1[] = {
            &hf_evs_h_bit,
            &hf_evs_f_bit,
            &hf_evs_mode_bit,
            &hf_evs_amr_wb_q_bit,
            &hf_evs_bit_rate_mode_1,
            NULL
            };
            proto_tree_add_bitmask_list(sub_tree, tvb, offset, 1, flags_toc_mode_1, ENC_BIG_ENDIAN);
            str = val_to_str_const((oct & 0x0f), evs_bit_rate_mode_1_values, "Unknown value");
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", str);
        offset++;
    } while (toc_f_bit == 1);

    speech_data_len = (packet_len - offset) / num_toc;

    num_data = num_toc;
    num_toc = 1;
    col_append_fstr(pinfo->cinfo, COL_INFO, "... ( %u frames in packet)", num_data);
    while (num_data > 0) {
        proto_tree *speech_tree;

        speech_tree = proto_tree_add_subtree_format(evs_tree, tvb, offset, speech_data_len, ett_evs_speech, NULL, "Speech frame for TOC # %u",
            num_toc);
        proto_tree_add_item(speech_tree, hf_evs_voice_data, tvb, offset, speech_data_len, ENC_NA);
        offset += speech_data_len;
        num_toc++;
        num_data--;
    }

    return packet_len;
}

void
proto_register_evs(void)
{
    module_t *evs_module;
    /*expert_module_t* expert_evs;*/

    static hf_register_info hf[] = {
        { &hf_evs_packet_length,
        { "Packet length", "evs.packet_length",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_evs_voice_data,
        { "Voice data", "evs.voice_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_evs_h_bit,
        { "Header Type identification bit (H)", "evs.h_bit",
        FT_BOOLEAN, 8, TFS(&tfs_evs_h_bit), 0x80,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t,
        { "Type of Request(T)", "evs.cmr_t",
        FT_UINT8, BASE_DEC, NULL, 0x70,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t0_d,
        { "D", "evs.cmr_t0_d",
        FT_UINT8, BASE_DEC, VALS(evs_d_bits_t0_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t1_d,
        { "D", "evs.cmr_t1_d",
        FT_UINT8, BASE_DEC, VALS(evs_d_bits_t1_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t2_d,
        { "D", "evs.cmr_t3_d",
        FT_UINT8, BASE_DEC, VALS(evs_d_bits_t2_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t3_d,
        { "D", "evs.cmr_t3_d",
        FT_UINT8, BASE_DEC, VALS(evs_d_bits_t3_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t4_d,
        { "D", "evs.cmr_t4_d",
        FT_UINT8, BASE_DEC, VALS(evs_d_bits_t4_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t5_d,
        { "D", "evs.cmr_t5_d",
        FT_UINT8, BASE_DEC, VALS(evs_d_bits_t5_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t6_d,
        { "D", "evs.cmr_t6_d",
        FT_UINT8, BASE_DEC, VALS(evs_d_bits_t6_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_cmr_t7_d,
        { "D", "evs.cmr_t7_d",
        FT_UINT8, BASE_DEC, VALS(evs_d_bits_t7_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_mode_bit,
        { "EVS Mode", "evs.mode_bit",
        FT_UINT8, BASE_DEC, NULL, 0x20,
        NULL, HFILL }
        },
        { &hf_evs_toc_spare,
        { "Unused", "evs.toc_spare",
        FT_UINT8, BASE_DEC, NULL, 0x10,
        NULL, HFILL }
        },
        { &hf_evs_amr_wb_q_bit,
        { "AMR WB Q bit", "evs.amr_wb_q_bit",
        FT_BOOLEAN, 8, TFS(&toc_evs_q_bit_vals), 0x10,
        NULL, HFILL }
        },

        { &hf_evs_bit_rate_mode_0,
        { "EVS mode and bit rate", "evs.bit_rate_mode_0",
        FT_UINT8, BASE_DEC, VALS(evs_bit_rate_mode_0_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_bit_rate_mode_1,
        { "EVS mode and bit rate", "evs.bit_rate_mode_1",
        FT_UINT8, BASE_DEC, VALS(evs_bit_rate_mode_1_values), 0x0f,
        NULL, HFILL }
        },
        { &hf_evs_f_bit,
        { "F", "evs.f_bit",
        FT_BOOLEAN, 8, TFS(&tfs_evs_f_bit), 0x40,
        NULL, HFILL }
        },
    { &hf_evs_cmr_amr_io,
    { "CMR", "evs.cmr_amr_io",
        FT_UINT8, BASE_DEC, VALS(evs_cmr_amr_io_values), 0xe0,
        NULL, HFILL }
    },
    { &hf_evs_bw,
    { "BW", "evs.bw",
        FT_UINT8, BASE_DEC, VALS(evs_bw_values), 0x0,
        NULL, HFILL }
    },
    { &hf_evs_reserved_1bit,
    { "Reserved", "evs.reserved_1bit",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_evs_celp_switch_to_mdct_core,
    { "CELP->HQ-MDCT core", "evs.celp_switch_to_mdct_core",
        FT_UINT8, BASE_DEC, VALS(evs_celp_switch_to_mdct_core_values), 0x0,
        NULL, HFILL }
    },
    { &hf_evs_celp_mdct_core,
    { "CELP/MDCT core", "evs.celp_mdct_core",
        FT_UINT8, BASE_DEC, VALS(evs_celp_or_mdct_core_values), 0x0,
        NULL, HFILL }
    },
    { &hf_evs_tcx_or_hq_mdct_core,
    { "TCX/HQ-MDCT core", "evs.tcx_hq_mdct_core",
        FT_UINT8, BASE_DEC, VALS(evs_tcx_or_hq_mdct_core_values), 0x0,
        NULL, HFILL }
    },
    { &hf_evs_sid_cng,
    { "CNG type", "evs.sid.cng",
        FT_UINT8, BASE_DEC, VALS(evs_sid_cng_values), 0x0,
        NULL, HFILL }
    },
    { &hf_evs_celp_sample_rate,
    { "CELP Sample Rate", "evs.sid.celp_sample_rate",
        FT_UINT8, BASE_DEC, VALS(evs_sid_celp_sample_rate_values), 0x0,
        NULL, HFILL }
    },
    { &hf_evs_core_sample_rate,
    { "Core sampling rate indicator", "evs.sid.core_sample_rate",
        FT_UINT8, BASE_DEC, VALS(evs_sid_celp_sample_rate_values), 0x0,
        NULL, HFILL }
    },
    { &hf_evs_132_bwctrf_idx,
    { "BW CT RF Index", "evs.132.bwctrf_idx",
        FT_UINT8, BASE_DEC, VALS(evs_132_bwctrf_idx_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_evs_28_frame_type,
    { "Frame type", "evs.28.frame_type",
        FT_UINT8, BASE_DEC, VALS(evs_28_frame_type_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_evs_28_bw_ppp_nelp,
    { "BW PPP/NELP", "evs.28.bw_ppp_nelp",
        FT_UINT8, BASE_DEC, VALS(evs_28_bw_ppp_nelp_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_evs_72_80_bwct_idx,
    { "BW CT Index", "evs.72.80.bwct_idx",
        FT_UINT8, BASE_DEC, VALS(evs_72_80_bwct_idx_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_evs_320_bwct_idx,
    { "BW CT Index", "evs.320.bwct_idx",
        FT_UINT8, BASE_DEC, VALS(evs_320_bwct_idx_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_evs_640_bwct_idx,
    { "BW CT Index", "evs.640.bwct_idx",
        FT_UINT8, BASE_DEC, VALS(evs_640_bwct_idx_vals), 0x0,
        NULL, HFILL }
    },
};


    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_evs,
        &ett_evs_header,
        &ett_evs_speech,
        &ett_evs_voice_data,
    };


    /* Register the protocol name and description */
    proto_evs = proto_register_protocol("Enhanced Voice Services", "EVS", "evs");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_evs, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    evs_module = prefs_register_protocol(proto_evs, NULL);

    prefs_register_obsolete_preference(evs_module, "dynamic.payload.type");

    evs_handle = register_dissector("evs", dissect_evs, proto_evs);

}

void
proto_reg_handoff_evs(void)
{
    dissector_add_string("rtp_dyn_payload_type", "EVS", evs_handle);
    dissector_add_uint_range_with_preference("rtp.pt", "", evs_handle);
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

